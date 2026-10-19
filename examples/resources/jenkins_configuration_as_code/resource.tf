# Manage the jenkins section. The system message alone is a safe first step for
# JCasC adoption; later jenkins settings go into this same resource, since one
# instance owns a whole top-level section.
#
# clientSecret is held by Terraform rather than by a secret source on the
# controller: the provider replaces ${client_secret} with the write-only value
# just before sending the section, and state keeps the placeholder. Change
# secrets_wo_version to re-send a rotated value.
resource "jenkins_configuration_as_code" "jenkins" {
  section = "jenkins"
  yaml = yamlencode({
    systemMessage = "Managed by Terraform: do not edit in the UI."
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
  })

  secrets_wo         = { client_secret = var.oidc_client_secret }
  secrets_wo_version = "1"
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
