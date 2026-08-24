##[>] 🤖🤖
set -u
setopt err_return pipe_fail

REPO_ROOT=${0:A:h:h:h}
MOCK_NAME=id_ussh_e2e_$(openssl rand -hex 3)
WORK_DIR=$(mktemp -d)
CONFIG_FILE=$WORK_DIR/config.yml
STATE_FILE=$WORK_DIR/state.yml
SSH_DIR=$HOME/.ssh
ALLOWED_SIGNERS=$SSH_DIR/allowed_signers
MOCK_EMAIL=$MOCK_NAME@mock.invalid
MAIN_PID=$$
CLEANED_UP=0
FAILURES=0
CHECKS=0

#[why] the only thing standing between this script and a real key: every destructive helper
#   filters on this pattern, so a name that does not match must never reach them
guard_mock_name() {
  [[ $MOCK_NAME =~ '^id_ussh_e2e_[0-9a-f]{6}$' ]] || {
    print -u2 "refusing to run: '$MOCK_NAME' is not a mock key name"
    exit 1
  }
}

preflight() {
  local missing=()
  glab auth status >/dev/null 2>&1 || missing+=("glab: run 'glab auth login'")
  gh auth status >/dev/null 2>&1 || missing+=("gh: run 'gh auth login'")

  local scopes
  scopes=$(gh auth status 2>&1 | sed -n 's/.*Token scopes: //p')
  [[ $scopes == *admin:public_key* ]] ||
    missing+=("gh: run 'gh auth refresh -h github.com -s admin:public_key,admin:ssh_signing_key'")
  [[ $scopes == *admin:ssh_signing_key* ]] ||
    missing+=("gh: run 'gh auth refresh -h github.com -s admin:public_key,admin:ssh_signing_key'")

  (( ${#missing} == 0 )) || {
    print -u2 "preflight failed:"
    printf '  %s\n' $missing >&2
    exit 1
  }

  sweep_stale_runs
}

#[why] a run killed hard enough to skip its traps strands keys on the real accounts, invisible
#   to the tool: every e2e key ever minted matches this prefix, so a later run collects them
sweep_stale_runs() {
  local platform id title type body
  local swept=0
  for platform in gitlab github; do
    while IFS=$'\t' read -r id title type body; do
      [[ -n ${id:-} ]] || continue
      print "sweeping stale $platform key $title ($id)"
      delete_platform_key $platform $id $type
      (( swept += 1 ))
    done < <(platform_rows $platform | awk -F'\t' '$2 ~ /^id_ussh_e2e_/')
  done

  local stale=($SSH_DIR/id_ussh_e2e_*(N))
  (( ${#stale} )) && { print "sweeping ${#stale} stale local file(s)"; rm -f $stale }

  if { grep -q '@mock\.invalid' $ALLOWED_SIGNERS 2>/dev/null } {
    print "sweeping stale mock allowed_signers lines"
    grep -v '@mock\.invalid' $ALLOWED_SIGNERS > $WORK_DIR/swept
    cp $WORK_DIR/swept $ALLOWED_SIGNERS
  }

  (( swept )) && print "swept $swept stale platform key(s)"
  return 0
}

ussh() {
  ( cd $REPO_ROOT && bundle exec ruby -Ilib exe/user-ssh-util "$@" \
      --config-file=$CONFIG_FILE --state-file=$STATE_FILE )
}

##[>] platform queries

gitlab_rows() {
  glab ssh-key list --show-id --output json 2>/dev/null |
    ruby -rjson -e 'JSON.parse(STDIN.read).each { puts [_1["id"], _1["title"], _1["usage_type"], _1["key"].split[1]].join("\t") }'
}

github_rows() {
  gh ssh-key list 2>/dev/null |
    ruby -e 'STDIN.each_line { c = _1.chomp.split("\t"); puts [c[3], c[0], c[4], c[1].split[1]].join("\t") }'
}

platform_rows() { [[ $1 == gitlab ]] && gitlab_rows || github_rows }

mock_rows() { platform_rows $1 | awk -F'\t' -v n="$MOCK_NAME" '$2 ~ "^" n' }

key_body() { awk '{print $2}' $1 }

signers_count() { grep -c . $ALLOWED_SIGNERS 2>/dev/null || print 0 }

#[why] declaring no keys at all is what makes every recorded key an orphan
write_empty_config() {
  cat > $CONFIG_FILE <<YML
defaults:
  email: $MOCK_EMAIL
keys: {}
YML
}

##[<] platform queries

##[>] assertions

check() {
  local label=$1 ok=$2
  (( CHECKS += 1 ))
  if [[ $ok == yes ]] {
    print "  PASS  $label"
  } else {
    print "  FAIL  $label"
    (( FAILURES += 1 ))
  }
}

assert_eq() {
  local label=$1 want=$2 got=$3
  [[ $want == $got ]] && check "$label" yes ||
    { check "$label (want '$want', got '$got')" no }
}

# assert_on_platform proves exactly one mock key with that title suffix carries the expected usage type.
assert_on_platform() {
  local platform=$1 title_prefix=$2 want_type=$3
  local rows found_type count
  rows=$(mock_rows $platform | awk -F'\t' -v p="$title_prefix" '$2 ~ "^" p')
  count=$(print -r -- "$rows" | grep -c . || true)
  found_type=$(print -r -- "$rows" | head -1 | cut -f3)

  assert_eq "$platform holds exactly one $title_prefix key" 1 "$count"
  assert_eq "$platform $title_prefix usage type" "$want_type" "$found_type"
}

assert_absent() {
  local platform=$1 title_prefix=$2
  local count
  count=$(mock_rows $platform | awk -F'\t' -v p="$title_prefix" '$2 ~ "^" p' | grep -c . || true)
  assert_eq "$platform holds no $title_prefix key" 0 "$count"
}

assert_local() {
  local name=$1
  [[ -f $SSH_DIR/$name && -f $SSH_DIR/$name.pub ]] && check "$name keypair is in ~/.ssh" yes ||
    check "$name keypair is in ~/.ssh" no
}

assert_no_local() {
  local name=$1
  [[ ! -f $SSH_DIR/$name && ! -f $SSH_DIR/$name.pub ]] && check "$name is gone from ~/.ssh" yes ||
    check "$name is gone from ~/.ssh" no
}

# assert_archived proves the superseded keypair was backed up rather than destroyed.
assert_archived() {
  local name=$1 want_body=$2
  local backups=$HOME/.local/share/user-ssh-util/backups/$name
  local hit
  hit=$(grep -rl -- "$want_body" $backups 2>/dev/null | head -1 || true)
  [[ -n $hit ]] && check "$name superseded key is archived under backups/" yes ||
    check "$name superseded key is archived under backups/" no
}

assert_signer() {
  local body=$1 want=$2 label=$3
  local found=no
  grep -qF -- "$body" $ALLOWED_SIGNERS 2>/dev/null && found=yes
  assert_eq "$label" "$want" "$found"
}

state_field() {
  ruby -rpsych -e 'e = (Psych.safe_load_file(ARGV[0], permitted_classes: [Time]) || {})[ARGV[1]] || {}; print e.dig(*ARGV.drop(2)).inspect' \
    $STATE_FILE "$@"
}

##[<] assertions

##[>] cleanup

delete_platform_key() {
  local platform=$1 id=$2 type=$3
  if [[ $platform == gitlab ]] {
    glab ssh-key delete $id >/dev/null 2>&1 || true
  } elif [[ $type == signing ]] {
    gh api -X DELETE /user/ssh_signing_keys/$id >/dev/null 2>&1 || true
  } else {
    gh api -X DELETE /user/keys/$id >/dev/null 2>&1 || true
  }
}

#[why] a rotated-away body is no longer on disk, so every body the mock key ever had is
#   recorded as it appears: that ledger is the only way cleanup can find its allowed_signers lines
remember_body() {
  [[ -f $1 ]] || return 0
  key_body $1 >> $WORK_DIR/mock-bodies
}

#[why] the mock email identifies every line this run added, whatever body it carried at the time
prune_allowed_signers() {
  [[ -f $ALLOWED_SIGNERS ]] || return 0

  local patterns=$WORK_DIR/mock-patterns kept=$WORK_DIR/allowed_signers.kept
  print -r -- $MOCK_EMAIL > $patterns
  [[ -s $WORK_DIR/mock-bodies ]] && cat $WORK_DIR/mock-bodies >> $patterns

  grep -vF -f $patterns $ALLOWED_SIGNERS > $kept 2>/dev/null || true
  cp $kept $ALLOWED_SIGNERS
}

#[why] zsh runs no EXIT trap for a signal that kills the shell, so INT/TERM/HUP are trapped
#   too: without them a Ctrl-C mid-rotation leaves live keys on both real accounts

remove_mock_keys() {
  local platform id title type body
  for platform in gitlab github; do
    while IFS=$'\t' read -r id title type body; do
      [[ -n ${id:-} ]] || continue
      print "  removing $platform $title ($id)"
      delete_platform_key $platform $id $type
    done < <(mock_rows $platform)
  done
}

#[why] process substitution and $( ) spawn subshells that inherit this trap: without the pid
#   guard the first one to exit tears down the run's keys and temp dir mid-script
cleanup() {
  local exit_code=$?
  [[ $$ == $MAIN_PID ]] || return $exit_code
  #[why] a signal trap and the EXIT trap both fire, and the second pass has no temp dir left
  (( CLEANED_UP )) && return $exit_code
  CLEANED_UP=1

  guard_mock_name
  print "cleaning up $MOCK_NAME"
  remove_mock_keys

  prune_allowed_signers
  rm -f $SSH_DIR/$MOCK_NAME* 2>/dev/null || true

  rm -rf $WORK_DIR $HOME/.local/share/user-ssh-util/backups/${MOCK_NAME}* 2>/dev/null || true
  return $exit_code
}

##[<] cleanup

report() {
  print
  if (( FAILURES == 0 )) {
    print "$CHECKS checks passed"
    return 0
  }
  print -u2 "$FAILURES of $CHECKS checks FAILED"
  return 1
}

#[why] installed at file scope, never from a function: zsh fires a function-scoped EXIT trap
#   the moment that function returns, which would tear the run down before it began
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
trap 'cleanup; exit 129' HUP

##[<] 🤖🤖
