# Manage the controller's system message (a safe first step for JCasC adoption).
resource "jenkins_configuration_as_code" "system_message" {
  section = "jenkins"
  yaml = yamlencode({
    systemMessage = "Managed by Terraform — do not edit in the UI."
  })
}

# A second instance can own a different top-level section. Secrets use JCasC
# ${VAR} interpolation, so the resolved value never enters Terraform state.
resource "jenkins_configuration_as_code" "unclassified" {
  section = "unclassified"
  yaml    = <<-YAML
    globalLibraries:
      libraries:
        - name: shared-pipeline
          defaultVersion: main
          retriever:
            modernSCM:
              scm:
                git:
                  remote: "https://git.example.com/jenkins/shared-pipeline.git"
                  credentialsId: "shared-pipeline-token"
  YAML
}

# A secret held by Terraform rather than by a secret source on the controller:
# the provider replaces ${client_secret} with the write-only value just before
# sending the section, and state keeps the placeholder. Change
# secrets_wo_version to re-send a rotated value.
#
# The role plugin exports permissions in an order of its own, so the
# permission lists are compared without regard to order.
resource "jenkins_configuration_as_code" "security" {
  section = "jenkins"
  yaml = yamlencode({
    securityRealm = {
      oic = {
        clientId     = "jenkins"
        clientSecret = "$${client_secret}"
        serverConfiguration = {
          wellKnown = {
            wellKnownOpenIDConfigurationUrl = "https://sso.example.com/.well-known/openid-configuration"
          }
        }
      }
    }
    authorizationStrategy = {
      roleBased = {
        roles = {
          global = [{
            name        = "readers"
            permissions = ["Overall/Read", "Job/Read"]
            entries     = [{ group = "authenticated" }]
          }]
        }
      }
    }
  })

  secrets_wo         = { client_secret = var.oidc_client_secret }
  secrets_wo_version = "1"
  unordered_paths    = ["authorizationStrategy.roleBased.roles.*.*.permissions"]
}
