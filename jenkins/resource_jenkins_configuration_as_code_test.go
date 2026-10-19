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
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
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
			{
				// The same configuration again: a refresh must agree with it.
				Config: config(second, "2"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectEmptyPlan(),
				}},
			},
		},
	})
}

// TestAccJenkinsConfigurationAsCode_secretsWoCASCSyntax checks secrets_wo
// against JCasC's own ${...} syntax on a real controller: a reference nested
// in a JCasC expression is substituted, then compared as a placeholder; an
// escaped ^${name} stays literal; and a value JCasC syntax cannot carry fails
// before anything is sent.
func TestAccJenkinsConfigurationAsCode_secretsWoCASCSyntax(t *testing.T) {
	decoded := "tf-acc-nested-" + acctest.RandStringFromCharSet(12, acctest.CharSetAlphaNum)
	encoded := base64.StdEncoding.EncodeToString([]byte(decoded))
	config := func(message, value string) string {
		return fmt.Sprintf(`
resource jenkins_configuration_as_code test {
  section            = "jenkins"
  yaml               = yamlencode({ systemMessage = "%s" })
  secrets_wo         = { value = %q }
  secrets_wo_version = "1"
}`, message, value)
	}
	nested := "$${decodeBase64:$${value}}"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: config(nested, encoded),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCASCSectionContains("jenkins", "systemMessage: "+decoded+"\n"),
					testAccCheckStateOmits(decoded),
					testAccCheckStateOmits(encoded),
				),
			},
			{
				// The nested expression is one placeholder: no drift.
				Config: config(nested, encoded),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectEmptyPlan(),
				}},
			},
			{
				// The escaped expression reaches the controller as a literal,
				// which the export escapes again. Embedded in a longer string,
				// the reference never compares equal, hence the plan.
				Config:             config("^$${value}-$${value}", decoded),
				ExpectNonEmptyPlan: true,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCASCSectionContains("jenkins", "systemMessage: ^${value}-"+decoded+"\n"),
					testAccCheckStateOmits(decoded),
				),
			},
			{
				Config:      config(nested, `{"k":"v"}`),
				ExpectError: regexp.MustCompile(`Invalid Secret Value`),
			},
		},
	})
}
