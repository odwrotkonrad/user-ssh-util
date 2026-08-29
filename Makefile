##[>] 🤖🤖
SHELL := zsh
.SHELLFLAGS := -c

COMMANDS := che-install generic-setup install repo-prepare-deps test e2e

.PHONY: $(COMMANDS)

-include shared/generic/make/generic.mk

##[>] Setup [genai-include]
#[what] install the latest released che into ~/.local/bin, only when the one on PATH is older
che-install:
	@curl -fsSL https://konradodwrot.gitlab.io/go-modules/che-install.sh | sh -s -- --skip-if-present-is-newer

#[what] render the generic consumer payload (generic.mk, lefthook.yml, shared/generic/) at the pinned CENTRALIZED_ASSETS_GENERIC_REF
generic-setup:
	@$${CHE_BIN:-che} render-templates --profiles=genericSetup

shared/generic/make/generic.mk: generic-setup

#[what] install ruby gem dependencies (needs ruby + bundler)
#[why] --path vendor/bundle, not a bare `bundle install`: .bundle/config carries that setting but is
#   gitignored, so a fresh clone would install into the system gem dir and fail without root
install:
	@bundle config set --local path vendor/bundle
	@bundle install

#[why] the repo declares ruby in its devEnv profile, so no host or image has to carry it in advance
#[what] install this repo's toolchain, then its dependencies
#[why] debian's ruby ships bundler only as the versioned `bundle3.1`, so a plain `bundle` is missing
#   on a fresh image even though the gem is present: install it as a user gem to get the unversioned
#   binary, and put the gem bindir on PATH for the install that follows
repo-prepare-deps:
	@che run --profiles=devEnv
	@command -v bundle >/dev/null || gem install --user-install --no-document bundler
	@PATH="$$(gem environment gemdir 2>/dev/null)/bin:$$(ruby -e 'print Gem.user_dir' 2>/dev/null)/bin:$$PATH" $(MAKE) install
##[<] Setup

##[>] Test [genai-include]
#[what] run the unit test suite
test:
	@bundle exec ruby -Ilib -Itest -e 'Dir.glob("test/**/*_test.rb").each { |f| require File.expand_path(f) }'

#[why] refuses to run under CI: these scripts create and delete real keys on the user's own
#   gitlab and github accounts, which no pipeline is authenticated for or entitled to touch
#[what] run the local end-to-end checks against the real gitlab/github accounts (never in CI)
e2e:
	@[[ -z $${CI:-} ]] || { print -u2 "e2e touches real accounts, refusing to run in CI"; exit 1; }
	@test/e2e/lifecycle.zsh
	@test/e2e/adoption.zsh
##[<] Test
##[<] 🤖🤖
