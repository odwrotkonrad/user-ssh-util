##[>] 🤖🤖
##[>] dependencies
{{ localFile ".repo/upstream.env" | dependency }}
##[<] dependencies
ARTIFACT_REGISTRY={{ shell "glab variable get -g konradodwrot GRP_KO_VAR_ARTIFACT_REGISTRY" }}
ARTIFACT_REGISTRY_PROXY_DOCKERHUB={{ shell "glab variable get -g konradodwrot GRP_KO_VAR_ARTIFACT_REGISTRY_PROXY_DOCKERHUB" }}
TAG_TOKEN={{ shell "glab variable get -R konradodwrot/user-ssh-util REPO_PROTECTED_VAR_BOT_TAG_TOKEN" }}
##[<] 🤖🤖
