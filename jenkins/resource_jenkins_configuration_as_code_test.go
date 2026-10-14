package jenkins

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
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

func TestAccJenkinsConfigurationAsCode_secretsWriteOnly(t *testing.T) {
	token := acctest.RandStringFromCharSet(12, acctest.CharSetAlphaNum)
	rotated := acctest.RandStringFromCharSet(12, acctest.CharSetAlphaNum)
	// The literal ${HOME} proves the value is applied verbatim: interpolated by
	// JCasC, it would read /var/jenkins_home. JCasC exports a stored ${ as ^${.
	config := func(secret, version string) string {
		return fmt.Sprintf(`
resource jenkins_configuration_as_code jenkins {
  section            = "jenkins"
  yaml               = yamlencode({ systemMessage = "$${MESSAGE}" })
  secrets_wo         = { MESSAGE = "tf-acc %[1]s $${HOME}" }
  secrets_wo_version = "%[2]s"
}

resource jenkins_configuration_as_code unclassified {
  section = "unclassified"
  yaml = yamlencode({
    mailer = {
      authentication = {
        username = "tf-acc"
        password = "$${SMTP_PASSWORD}"
      }
    }
  })
  secrets_wo         = { SMTP_PASSWORD = "%[1]s" }
  secrets_wo_version = "%[2]s"

  # JCasC answers 409 to an apply while another one runs.
  depends_on = [jenkins_configuration_as_code.jenkins]
}`, secret, version)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_11_0)},
		ProtoV6ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				// The test framework plans again after apply and fails on a
				// diff: the exported message and the encrypted password must
				// both match their ${...} placeholders.
				Config: config(token, "1"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCASCSectionContains("jenkins", "tf-acc "+token+" ^${HOME}"),
					resource.TestMatchResourceAttr("jenkins_configuration_as_code.jenkins", "yaml", regexp.MustCompile(`systemMessage"?: "?\$\{MESSAGE\}`)),
					resource.TestCheckResourceAttr("jenkins_configuration_as_code.jenkins", "secrets_wo_version", "1"),
					resource.TestCheckNoResourceAttr("jenkins_configuration_as_code.jenkins", "secrets_wo"),
					resource.TestCheckNoResourceAttr("jenkins_configuration_as_code.unclassified", "secrets_wo"),
					testAccCheckNotInState(token),
				),
			},
			{
				// Terraform cannot see a write-only value change: without a
				// version bump there is nothing to apply.
				Config:   config(rotated, "1"),
				PlanOnly: true,
			},
			{
				Config: config(rotated, "2"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCASCSectionContains("jenkins", "tf-acc "+rotated+" ^${HOME}"),
					testAccCheckNotInState(rotated),
				),
			},
		},
	})
}

func TestAccJenkinsConfigurationAsCode_secretsValidation(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_11_0)},
		ProtoV6ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: `
resource jenkins_configuration_as_code test {
  section            = "jenkins"
  yaml               = yamlencode({ systemMessage = "$${MESSAGE}" })
  secrets_wo         = { MESAGE = "typo" }
  secrets_wo_version = "1"
}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Unreferenced Secret`),
			},
			{
				Config: `
resource jenkins_configuration_as_code test {
  section    = "jenkins"
  yaml       = yamlencode({ systemMessage = "$${MESSAGE}" })
  secrets_wo = { MESSAGE = "no version" }
}`,
				PlanOnly:    true,
				ExpectError: errInvalidAttributeCombination,
			},
			{
				Config: `
resource jenkins_configuration_as_code test {
  section            = "jenkins"
  yaml               = yamlencode({ systemMessage = "$${readFile:/etc/passwd}" })
  secrets_wo         = { "readFile:/etc/passwd" = "x" }
  secrets_wo_version = "1"
}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Invalid Attribute Value Match`),
			},
		},
	})
}

func TestAccJenkinsConfigurationAsCode_unorderedScalarList(t *testing.T) {
	// Jenkins keeps disabledAdministrativeMonitors in a HashSet, which
	// iterates these three as zulu, alpha, mike.
	declared := []interface{}{"tf-acc.alpha", "tf-acc.mike", "tf-acc.zulu"}
	config := `
resource jenkins_configuration_as_code test {
  section = "jenkins"
  yaml = yamlencode({
    disabledAdministrativeMonitors = ["tf-acc.alpha", "tf-acc.mike", "tf-acc.zulu"]
  })
}`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check:  testAccCheckCASCExportedReordered("jenkins", "disabledAdministrativeMonitors", declared),
			},
			{
				Config: config,
			},
		},
	})
}

// testAccCheckCASCExportedReordered asserts that the list at key of the
// exported section holds the declared elements in another order. Exported in
// the declared order, the list would not exercise unordered comparison.
func testAccCheckCASCExportedReordered(section, key string, declared []interface{}) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		exported, err := testAccClient.ExportCASC(context.Background())
		if err != nil {
			return fmt.Errorf("exporting JCasC config: %w", err)
		}
		sub, _, err := extractSectionYAML(exported, section)
		if err != nil {
			return err
		}
		parsed, err := parseYAML(sub)
		if err != nil {
			return err
		}
		m, _ := parsed.(map[string]interface{})
		got, _ := m[key].([]interface{})
		if len(got) != len(declared) || !unorderedMatch(declared, got) {
			return fmt.Errorf("exported %s.%s = %#v, want the elements of %#v", section, key, got, declared)
		}
		if reflect.DeepEqual(got, declared) {
			return fmt.Errorf("exported %s.%s keeps the declared order %#v", section, key, got)
		}
		return nil
	}
}

// testAccCheckNotInState asserts that no attribute of any resource in state
// contains secret.
func testAccCheckNotInState(secret string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		for name, rs := range s.RootModule().Resources {
			for k, v := range rs.Primary.Attributes {
				if strings.Contains(v, secret) {
					return fmt.Errorf("%s.%s holds the secret", name, k)
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
