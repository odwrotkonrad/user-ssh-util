#!/usr/bin/env zsh
##[>] 🤖🤖
source ${0:A:h}/helper.zsh

guard_mock_name
preflight

NAME=${MOCK_NAME}_adopted
EMAIL=$MOCK_EMAIL

write_config() {
  cat > $CONFIG_FILE <<YML
keys:
$1
YML
}

declared_key() {
  print -r -- "  $NAME:
    type: access
    email: $EMAIL
    algorithm: ssh-ed25519
    publishTo: [gitlab, github]"
}

print "e2e adoption: $MOCK_NAME"
SIGNERS_BEFORE=$(signers_count)

##[>] step 1: a keypair made by hand, published nowhere

print "\nstep 1: ssh-keygen creates the keypair, nothing is published"
ssh-keygen -t ed25519 -C $EMAIL -N "" -f $SSH_DIR/$NAME >/dev/null
HAND_MADE=$(key_body $SSH_DIR/$NAME.pub)

assert_absent gitlab $NAME
assert_absent github $NAME

##[<] step 1

##[>] step 2: sync adopts rather than creates

print "\nstep 2: sync adopts the existing keypair"
write_config "$(declared_key)"
OUTPUT=$(ussh sync --yes)

assert_eq "sync reports adoption, not creation" yes \
  "$([[ $OUTPUT == *"adopted $NAME"* ]] && print yes || print no)"
assert_eq "the hand-made material is preserved" "$HAND_MADE" "$(key_body $SSH_DIR/$NAME.pub)"
assert_eq "state now records the key" '"access"' "$(state_field $NAME type)"

assert_on_platform gitlab $NAME auth
assert_on_platform github $NAME authentication

##[<] step 2

##[>] step 3: an already-published key is matched, never duplicated

print "\nstep 3: a fresh state file re-adopts the published key by material"
GITLAB_TITLE=$(mock_rows gitlab | head -1 | cut -f2)
GITLAB_ID=$(mock_rows gitlab | head -1 | cut -f1)

rm -f $STATE_FILE
ussh sync --yes >/dev/null

assert_eq "gitlab still holds exactly one key for $NAME" 1 "$(mock_rows gitlab | grep -c . || true)"
assert_eq "the existing gitlab title was recorded, not a new upload" \
  "\"$GITLAB_TITLE\"" "$(state_field $NAME publishedTo gitlab)"
assert_eq "the gitlab key id never changed" "$GITLAB_ID" "$(mock_rows gitlab | head -1 | cut -f1)"
assert_eq "github still holds exactly one key for $NAME" 1 "$(mock_rows github | grep -c . || true)"

##[<] step 3

##[>] step 4: rotation

print "\nstep 4: forced rotation replaces the adopted key"
ussh sync --yes --force-rotate-keys=$NAME

assert_eq "the adopted material was replaced" changed \
  "$([[ $(key_body $SSH_DIR/$NAME.pub) == $HAND_MADE ]] && print same || print changed)"
assert_eq "$NAME rotationCounter" 1 "$(state_field $NAME rotationCounter)"

assert_on_platform gitlab $NAME auth
assert_on_platform github $NAME authentication
assert_archived $NAME "$HAND_MADE"

##[<] step 4

##[>] step 5: orphan revoke

print "\nstep 5: dropping the key from config revokes and archives it"
ROTATED=$(key_body $SSH_DIR/$NAME.pub)

write_empty_config
ussh sync --yes

assert_absent gitlab $NAME
assert_absent github $NAME
assert_no_local $NAME
assert_archived $NAME "$ROTATED"
assert_eq "unrelated allowed_signers lines survive" "$SIGNERS_BEFORE" "$(signers_count)"

##[<] step 5

report
##[<] 🤖🤖
