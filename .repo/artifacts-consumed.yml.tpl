##[>] 🤖
consumes:
  - uri: gitlab.com/konradodwrot/configs
    type: gitRepository
    version: {{ env.Getenv "CONFIGS_REF" }}
  - uri: gitlab.com/konradodwrot/cross-repo/misc
    type: gitRepository
    version: {{ env.Getenv "MISC_REF" }}
  - uri: gitlab.com/konradodwrot/cross-repo/prose/assets
    type: gitRepository
    version: {{ env.Getenv "PROSE_ASSETS_REF" }}
  - uri: gitlab.com/konradodwrot/cross-repo/prose/spec
    type: gitRepository
    version: {{ env.Getenv "PROSE_SPEC_REF" }}
  - uri: gitlab.com/konradodwrot/go-modules/che-schema
    type: file
    version: {{ env.Getenv "CHE_SCHEMA_REF" }}
  - uri: us-central1-docker.pkg.dev/staging-499418/ci/ci-linux
    type: ociImage
    version: {{ env.Getenv "OCI_IMAGES_CI_LINUX_REF" }}
##[<] 🤖
