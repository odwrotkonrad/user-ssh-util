#!/usr/bin/env zsh
##[>] 🤖🤖
source ${0:A:h}/helper.zsh

guard_mock_name
preflight

ACCESS=${MOCK_NAME}_access
SIGNING=${MOCK_NAME}_signing

write_config() {
  cat > $CONFIG_FILE <<YML
defaults:
  email: $MOCK_EMAIL
  algorithm: ssh-ed25519
keys:
$@
YML
}

both_keys() {
  print -r -- "  $ACCESS:
    type: access
    publishTo: [gitlab, github]
  $SIGNING:
    type: signing
    publishTo: [gitlab, github]"
}

print "e2e lifecycle: $MOCK_NAME"
SIGNERS_BEFORE=$(signers_count)

##[>] step 1: create and publish

print "\nstep 1: sync creates both keypairs"
write_config "$(both_keys)"
ussh sync --yes

assert_local $ACCESS
assert_local $SIGNING
remember_body $SSH_DIR/$SIGNING.pub

assert_on_platform gitlab $ACCESS auth
assert_on_platform github $ACCESS authentication
assert_on_platform gitlab $SIGNING signing
assert_on_platform github $SIGNING signing

assert_signer "$(key_body $SSH_DIR/$SIGNING.pub)" yes "$SIGNING is in allowed_signers"
assert_signer "$(key_body $SSH_DIR/$ACCESS.pub)" no "an access key stays out of allowed_signers"

assert_eq "state records both gitlab and github for $ACCESS" \
  '["gitlab", "github"]' "$(state_field $ACCESS publishedTo | ruby -e 'print eval(STDIN.read).keys.inspect')"

##[<] step 1

##[>] step 2: idempotence

print "\nstep 2: a second sync changes nothing"
GITLAB_BEFORE=$(mock_rows gitlab | wc -l | tr -d ' ')
OUTPUT=$(ussh sync --yes)

assert_eq "a reconciled sync reports nothing to do" "nothing to do" "$OUTPUT"
assert_eq "no new gitlab keys appeared" "$GITLAB_BEFORE" "$(mock_rows gitlab | wc -l | tr -d ' ')"

##[<] step 2

##[>] step 3: rotate both

print "\nstep 3: forced rotation replaces both keys"
ACCESS_OLD=$(key_body $SSH_DIR/$ACCESS.pub)
SIGNING_OLD=$(key_body $SSH_DIR/$SIGNING.pub)

ussh sync --yes --force-rotate-keys=$ACCESS,$SIGNING
remember_body $SSH_DIR/$SIGNING.pub

assert_eq "$ACCESS material changed" changed \
  "$([[ $(key_body $SSH_DIR/$ACCESS.pub) == $ACCESS_OLD ]] && print same || print changed)"
assert_eq "$SIGNING material changed" changed \
  "$([[ $(key_body $SSH_DIR/$SIGNING.pub) == $SIGNING_OLD ]] && print same || print changed)"

assert_eq "$ACCESS rotationCounter" 1 "$(state_field $ACCESS rotationCounter)"
assert_eq "$SIGNING rotationCounter" 1 "$(state_field $SIGNING rotationCounter)"

assert_on_platform gitlab $ACCESS auth
assert_on_platform github $ACCESS authentication
assert_on_platform gitlab $SIGNING signing
assert_on_platform github $SIGNING signing

assert_signer "$SIGNING_OLD" no "the superseded signer body is gone"
assert_signer "$(key_body $SSH_DIR/$SIGNING.pub)" yes "the replacement signer body is present"

assert_archived $ACCESS "$ACCESS_OLD"
assert_archived $SIGNING "$SIGNING_OLD"

##[<] step 3

##[>] step 4: orphan revoke

print "\nstep 4: dropping both keys from config revokes them"
ROTATED_ACCESS=$(key_body $SSH_DIR/$ACCESS.pub)
ROTATED_SIGNING=$(key_body $SSH_DIR/$SIGNING.pub)

write_empty_config
ussh sync --yes

assert_absent gitlab $ACCESS
assert_absent github $ACCESS
assert_absent gitlab $SIGNING
assert_absent github $SIGNING

assert_no_local $ACCESS
assert_no_local $SIGNING
assert_archived $ACCESS "$ROTATED_ACCESS"
assert_archived $SIGNING "$ROTATED_SIGNING"
assert_signer "$ROTATED_SIGNING" no "the revoked signer body is gone from allowed_signers"
assert_eq "unrelated allowed_signers lines survive" "$SIGNERS_BEFORE" "$(signers_count)"

##[<] step 4

report
##[<] 🤖🤖
