resource "jenkins_node" "agent" {
  name      = "linux-agent-01"
  remote_fs = "/home/jenkins/agent"
}

# Referencing the node's id defers the lookup until the node exists.
data "jenkins_node_secret" "agent" {
  name = jenkins_node.agent.id
}

# Pass data.jenkins_node_secret.agent.secret to the agent, e.g.
# java -jar agent.jar -url <jenkins-url> -name linux-agent-01 -secret <secret>
