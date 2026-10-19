package jenkins

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccJenkinsConfigurationAsCode_basic(t *testing.T) {
	msg := "tf-acc " + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	updated := "tf-acc " + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resourceName := "jenkins_configuration_as_code.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource jenkins_configuration_as_code test {
  section = "jenkins"
  yaml    = yamlencode({ systemMessage = "%s" })
}`, msg),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", "jenkins"),
					resource.TestCheckResourceAttr(resourceName, "section", "jenkins"),
					resource.TestCheckResourceAttrSet(resourceName, "yaml"),
					testAccCheckCASCSectionContains("jenkins", msg),
				),
			},
			{
				// Changing the YAML re-applies (in-place update).
				Config: fmt.Sprintf(`
resource jenkins_configuration_as_code test {
  section = "jenkins"
  yaml    = yamlencode({ systemMessage = "%s" })
}`, updated),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCASCSectionContains("jenkins", updated),
				),
			},
		},
	})
}

// TestAccJenkinsConfigurationAsCode_secretNotInState asserts the Q3 invariant
// of docs/design/casc.md after out-of-band drift and after import (#249).
// JCasC resolves ${decodeBase64:...} on apply, so the resolved value stands in
// for a secret: the controller holds it, the configuration does not.
func TestAccJenkinsConfigurationAsCode_secretNotInState(t *testing.T) {
	resolved := "tf-acc-secret-" + acctest.RandStringFromCharSet(12, acctest.CharSetAlphaNum)
	resourceName := "jenkins_configuration_as_code.test"
	config := fmt.Sprintf(`
resource jenkins_configuration_as_code test {
  section = "jenkins"
  yaml    = yamlencode({
    systemMessage = "$${decodeBase64:%s}"
    quietPeriod   = 5
  })
}`, base64.StdEncoding.EncodeToString([]byte(resolved)))

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCASCSectionContains("jenkins", resolved),
					testAccCheckStateOmits(resolved),
				),
			},
			{
				// Drift on a sibling key: the refreshed yaml shows it, keeps the
				// placeholder, and still differs from the configuration.
				PreConfig: func() {
					if err := testAccClient.ApplyCASC(context.Background(), "jenkins:\n  quietPeriod: 7\n"); err != nil {
						t.Fatalf("inducing drift: %v", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckStateOmits(resolved),
					resource.TestMatchResourceAttr(resourceName, "yaml", regexp.MustCompile(`quietPeriod: 7`)),
					resource.TestMatchResourceAttr(resourceName, "yaml", regexp.MustCompile(`\$\{decodeBase64:`)),
				),
			},
			{
				// Re-applying reconciles the drift.
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckStateOmits(resolved),
					testAccCheckCASCSectionContains("jenkins", "quietPeriod: 5"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"yaml"},
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					for _, s := range states {
						for k, v := range s.Attributes {
							if strings.Contains(v, resolved) {
								return fmt.Errorf("imported attribute %s holds the resolved secret", k)
							}
						}
					}
					return nil
				},
			},
		},
	})
}

// testAccCheckStateOmits fails if any attribute of any resource in state
// contains value.
func testAccCheckStateOmits(value string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		for name, rs := range s.RootModule().Resources {
			for k, v := range rs.Primary.Attributes {
				if strings.Contains(v, value) {
					return fmt.Errorf("%s.%s holds %q", name, k, value)
				}
			}
		}
		return nil
	}
}

// testAccCheckCASCSectionContains exports the live JCasC configuration and
// asserts the given section's YAML contains want, proving the apply reached the
// controller.
func testAccCheckCASCSectionContains(section, want string) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		exported, err := testAccClient.ExportCASC(context.Background())
		if err != nil {
			return fmt.Errorf("exporting JCasC config: %w", err)
		}
		sub, found, err := extractSectionYAML(exported, section)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("section %q not present in exported configuration", section)
		}
		if !strings.Contains(sub, want) {
			return fmt.Errorf("section %q does not contain %q; got:\n%s", section, want, sub)
		}
		return nil
	}
}

// TestAccJenkinsConfigurationAsCode_secretsWo applies a section whose secret
// comes from secrets_wo, then rotates it with secrets_wo_version. The value
// holds a "${" that JCasC must keep literal rather than resolve to an empty
// string, and it must never reach state.
func TestAccJenkinsConfigurationAsCode_secretsWo(t *testing.T) {
	first := "tf-acc-wo-" + acctest.RandStringFromCharSet(12, acctest.CharSetAlphaNum)
	second := "tf-acc-wo-" + acctest.RandStringFromCharSet(12, acctest.CharSetAlphaNum)
	config := func(value, version string) string {
		return fmt.Sprintf(`
resource jenkins_configuration_as_code test {
  section            = "jenkins"
  yaml               = yamlencode({ systemMessage = "$${message}" })
  secrets_wo         = { message = "%s-$${literal}" }
  secrets_wo_version = "%s"
}`, value, version)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: config(first, "1"),
				Check: resource.ComposeTestCheckFunc(
					// The export escapes a literal "${" as "^${".
					testAccCheckCASCSectionContains("jenkins", first+"-^${literal}"),
					testAccCheckStateOmits(first),
					resource.TestCheckResourceAttr("jenkins_configuration_as_code.test", "yaml", "\"systemMessage\": \"${message}\"\n"),
				),
			},
			{
				Config: config(second, "2"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCASCSectionContains("jenkins", second+"-^${literal}"),
					testAccCheckStateOmits(second),
				),
			},
		},
	})
}

// testAccCASCMonitorsConfig declares disabledAdministrativeMonitors, a set the
// controller exports in an order of its own, not in the declared one.
func testAccCASCMonitorsConfig(unordered bool) string {
	paths := ""
	if unordered {
		paths = `unordered_paths = ["disabledAdministrativeMonitors"]`
	}
	return fmt.Sprintf(`
resource jenkins_configuration_as_code test {
  section = "jenkins"
  yaml    = yamlencode({
    disabledAdministrativeMonitors = [
      "jenkins.security.QueueItemAuthenticatorMonitor",
      "hudson.diagnosis.ReverseProxySetupMonitor",
      "jenkins.diagnostics.RootUrlNotSetMonitor",
      "hudson.model.UpdateCenter$CoreUpdateMonitor",
    ]
  })
  %s
}`, paths)
}

// TestAccJenkinsConfigurationAsCode_unorderedPaths applies a list the
// controller reorders: in order it never converges, with unordered_paths the
// plan after the apply is empty.
func TestAccJenkinsConfigurationAsCode_unorderedPaths(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config:             testAccCASCMonitorsConfig(false),
				ExpectNonEmptyPlan: true,
			},
			{
				Config: testAccCASCMonitorsConfig(true),
			},
		},
	})
}
