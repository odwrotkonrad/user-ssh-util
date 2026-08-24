##[>] 🤖🤖
#[what] Project's Makefile
SHELL := zsh
.SHELLFLAGS := -c

WRAPPERS := repo-prepare-dev-env
COMMANDS := semver-next tag-mint install repo-prepare-deps test e2e repo-ci-prepare-hooks repo-ci-precommit-all

#[why] render-templates, repo-ci-render-templates and repo-render-env are declared .PHONY by the shared .mk, never here: a .PHONY name make cannot build reports "nothing to be done" and exits 0, turning a failed bootstrap into a silent success
.PHONY: $(WRAPPERS) $(COMMANDS)

##[>] Dev Environment [genai-include]
#[why] render precedes hooks: the docsgen pre-commit hook runs render-templates and fails on drift,
#   so a fresh clone whose generated files were never rendered would fail its first commit
#[what] make a fresh clone a working checkout: generated docs, dependencies, git hooks
repo-prepare-dev-env: repo-render-env render-templates repo-prepare-deps repo-ci-prepare-hooks
##[<] Dev Environment

##[>] Docs [genai-include]
#[what] shared render targets, authored in cross-repo/misc and rendered here by the bootstrap rule below
-include shared/ci/make/render.mk

#[why] gitignored shared/ tree: a fresh clone has no render.mk, so make renders it, then re-execs itself with the shared targets defined
#[why] CI carries every ref as a job variable and has no glab auth: seed .env only when the environment names no MISC_REF
shared/ci/make/render.mk:
	@[[ -n $${MISC_REF:-} ]] || CHE_ENV_UNSET=empty $${CHE_BIN:-che} render-templates --profiles=envSeed
	@$${CHE_BIN:-che} render-templates --profiles=bootstrapCrossRepoCI
##[<] Docs

##[>] Setup [genai-include]
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

##[>] Release [genai-include]
#[what] print the next semver tag inferred from the last tag..HEAD diff (override: `semver: major|minor|patch` commit token)
semver-next: render-templates
	@shared/ci/semver-bump.zsh

#[what] mint and push the next semver tag (CI: authed via TAG_TOKEN)
tag-mint: render-templates
	@shared/ci/tag-mint.zsh
##[<] Release

##[>] CI [genai-include]
#[what] install lefthook git hooks
repo-ci-prepare-hooks:
	@lefthook install --force

#[what] run pre-commit hooks over all files (not just staged)
repo-ci-precommit-all: repo-ci-prepare-hooks
	@lefthook run pre-commit --all-files --force
##[<] CI
##[<] 🤖🤖
