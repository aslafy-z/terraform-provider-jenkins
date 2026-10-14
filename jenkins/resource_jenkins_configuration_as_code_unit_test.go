package jenkins

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func cascTestSchema(t *testing.T) schema.Schema {
	t.Helper()
	resp := &fwresource.SchemaResponse{}
	newConfigurationAsCodeResource().Schema(context.Background(), fwresource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema: %v", resp.Diagnostics)
	}
	return resp.Schema
}

// cascTestConfig builds a config holding yaml and, when secrets is not nil,
// secrets_wo with a version.
func cascTestConfig(t *testing.T, s schema.Schema, yaml types.String, secrets map[string]string) tfsdk.Config {
	t.Helper()
	ctx := context.Background()
	model := configurationAsCodeResourceModel{
		ID:               types.StringNull(),
		Section:          types.StringValue("jenkins"),
		YAML:             yaml,
		SecretsWo:        types.MapNull(types.StringType),
		SecretsWoVersion: types.StringNull(),
	}
	if secrets != nil {
		m, diags := types.MapValueFrom(ctx, types.StringType, secrets)
		if diags.HasError() {
			t.Fatalf("secrets map: %v", diags)
		}
		model.SecretsWo = m
		model.SecretsWoVersion = types.StringValue("1")
	}
	st := tfsdk.State{Schema: s}
	if diags := st.Set(ctx, &model); diags.HasError() {
		t.Fatalf("config: %v", diags)
	}
	return tfsdk.Config{Schema: s, Raw: st.Raw}
}

func TestConfigurationAsCodeSecretsSchema(t *testing.T) {
	attrs := cascTestSchema(t).Attributes

	wo, ok := attrs["secrets_wo"]
	if !ok {
		t.Fatal("missing secrets_wo attribute")
	}
	if !wo.IsWriteOnly() || !wo.IsSensitive() || !wo.IsOptional() {
		t.Errorf("secrets_wo must be optional, sensitive and write-only")
	}
	ver, ok := attrs["secrets_wo_version"]
	if !ok {
		t.Fatal("missing secrets_wo_version attribute")
	}
	if ver.IsWriteOnly() || !ver.IsOptional() {
		t.Errorf("secrets_wo_version must be optional and stored in state")
	}
}

func TestConfigurationAsCodeValidateConfig(t *testing.T) {
	s := cascTestSchema(t)
	cases := []struct {
		name    string
		yaml    types.String
		secrets map[string]string
		errAt   string // secrets_wo key the error is expected on, "" for none
	}{
		{"every secret referenced", types.StringValue("a: ${ONE}\nb: x-${TWO}"), map[string]string{"ONE": "1", "TWO": "2"}, ""},
		{"unreferenced secret", types.StringValue("a: ${ONE}"), map[string]string{"ONE": "1", "TYPO": "2"}, "TYPO"},
		{"escaped reference does not count", types.StringValue("a: ^${ONE}"), map[string]string{"ONE": "1"}, "ONE"},
		{"no secrets", types.StringValue("a: ${ENV_VAR}"), nil, ""},
		{"unknown yaml is checked at apply", types.StringUnknown(), map[string]string{"ONE": "1"}, ""},
		{"invalid yaml is reported at apply", types.StringValue("a: [bad"), map[string]string{"ONE": "1"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newConfigurationAsCodeResource().(*configurationAsCodeResource)
			resp := &fwresource.ValidateConfigResponse{}
			r.ValidateConfig(context.Background(), fwresource.ValidateConfigRequest{Config: cascTestConfig(t, s, tc.yaml, tc.secrets)}, resp)

			if tc.errAt == "" {
				if resp.Diagnostics.HasError() {
					t.Errorf("unexpected error: %v", resp.Diagnostics)
				}
				return
			}
			if resp.Diagnostics.ErrorsCount() != 1 {
				t.Fatalf("want one error, got %v", resp.Diagnostics)
			}
			d, ok := resp.Diagnostics.Errors()[0].(interface{ Path() path.Path })
			if !ok || !d.Path().Equal(path.Root("secrets_wo").AtMapKey(tc.errAt)) {
				t.Errorf("error is not on secrets_wo[%q]: %v", tc.errAt, resp.Diagnostics)
			}
		})
	}
}

func TestConfigurationAsCodeCreateSubstitutesSecrets(t *testing.T) {
	ctx := context.Background()
	s := cascTestSchema(t)
	const declared = "securityRealm:\n  oic:\n    clientSecret: ${CLIENT_SECRET}\n"
	cfg := cascTestConfig(t, s, types.StringValue(declared), map[string]string{"CLIENT_SECRET": "s3cr3t"})

	var posted string
	r := &configurationAsCodeResource{resourceHelper: &resourceHelper{client: &mockJenkinsClient{
		mockApplyCASC: func(_ context.Context, doc string) error {
			posted = doc
			return nil
		},
	}}}
	// Terraform sends write-only values in the config only, never in the plan.
	plan := tfsdk.Plan{Schema: s, Raw: cfg.Raw}
	if diags := plan.SetAttribute(ctx, path.Root("secrets_wo"), types.MapNull(types.StringType)); diags.HasError() {
		t.Fatal(diags)
	}
	resp := &fwresource.CreateResponse{State: tfsdk.State{Schema: s}}
	r.Create(ctx, fwresource.CreateRequest{Plan: plan, Config: cfg}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create: %v", resp.Diagnostics)
	}

	if !strings.Contains(posted, "clientSecret: s3cr3t") {
		t.Errorf("posted document does not carry the secret:\n%s", posted)
	}
	var got configurationAsCodeResourceModel
	resp.Diagnostics.Append(resp.State.Get(ctx, &got)...)
	if got.YAML.ValueString() != declared {
		t.Errorf("state yaml = %q, want the declared document %q", got.YAML.ValueString(), declared)
	}
	if !got.SecretsWo.IsNull() {
		t.Errorf("secrets_wo must not be stored in state, got %v", got.SecretsWo)
	}
}

func TestConfigurationAsCodeApplyErrorRedactsSecrets(t *testing.T) {
	ctx := context.Background()
	s := cascTestSchema(t)
	// SHORT prefixes LONG: masking it first would leave "-tail" in clear.
	cfg := cascTestConfig(t, s, types.StringValue("a: ${PASS}\nb: ${ESC}\nc: ${SHORT}\nd: ${LONG}"),
		map[string]string{"PASS": "s3cr3t", "ESC": "x${y}", "SHORT": "pre", "LONG": "pre-tail"})

	r := &configurationAsCodeResource{resourceHelper: &resourceHelper{client: &mockJenkinsClient{
		mockApplyCASC: func(_ context.Context, doc string) error {
			return errors.New("JCasC apply failed (status 400): invalid value 's3cr3t' or 'x^${y}' or 'pre-tail' in " + doc)
		},
	}}}
	plan := tfsdk.Plan{Schema: s, Raw: cfg.Raw}
	resp := &fwresource.CreateResponse{State: tfsdk.State{Schema: s}}
	r.Create(ctx, fwresource.CreateRequest{Plan: plan, Config: cfg}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected the apply error")
	}
	for _, d := range resp.Diagnostics {
		for _, leaked := range []string{"s3cr3t", "x^${y}", "-tail"} {
			if strings.Contains(d.Detail(), leaked) {
				t.Errorf("diagnostic leaks %q: %s", leaked, d.Detail())
			}
		}
	}
}
