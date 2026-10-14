# Manage the controller's system message (a safe first step for JCasC adoption).
resource "jenkins_configuration_as_code" "system_message" {
  section = "jenkins"
  yaml = yamlencode({
    systemMessage = "Managed by Terraform — do not edit in the UI."
  })
}

# A second instance can own a different top-level section. secrets_wo fills
# the ${NAME} references at apply and never enters state or plan, so yaml holds
# no secret and its diff stays readable. Change secrets_wo_version to re-apply
# after a secret changes. A ${NAME} with no secrets_wo key is resolved by the
# controller's own JCasC secret sources (environment variables, files, ...).
resource "jenkins_configuration_as_code" "unclassified" {
  section = "unclassified"
  yaml    = <<-YAML
    mailer:
      smtpHost: "smtp.example.com"
      authentication:
        username: "jenkins"
        password: "$${SMTP_PASSWORD}"
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

  secrets_wo         = { SMTP_PASSWORD = var.smtp_password }
  secrets_wo_version = "1"
}
