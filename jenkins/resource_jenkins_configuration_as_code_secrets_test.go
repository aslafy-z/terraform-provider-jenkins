package jenkins

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// cascConfig builds a config holding m. tfsdk.Config has no setter, so the
// value is built through a State of the same schema.
func cascConfig(t *testing.T, s rschema.Schema, m configurationAsCodeResourceModel) tfsdk.Config {
	t.Helper()
	st := tfsdk.State{Schema: s}
	if diags := st.Set(context.Background(), m); diags.HasError() {
		t.Fatalf("config: %v", diags)
	}
	return tfsdk.Config{Schema: s, Raw: st.Raw}
}

func TestConfigurationAsCodeCreateSubstitutesSecretsWo(t *testing.T) {
	ctx := context.Background()
	const secret = "wo-secret-value-0001"
	declared := "securityRealm:\n  oic:\n    clientSecret: \"${client_secret}\"\n"

	var posted string
	r := &configurationAsCodeResource{resourceHelper: &resourceHelper{client: &mockJenkinsClient{
		mockApplyCASC: func(_ context.Context, doc string) error { posted = doc; return nil },
	}}}
	var sr resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sr)

	// Terraform plans a write-only attribute as null and hands its value
	// over in config only.
	m := cascNullModel("jenkins", declared)
	m.ID = types.StringUnknown()
	m.SecretsWoVersion = types.StringValue("1")
	plan := tfsdk.Plan{Schema: sr.Schema}
	if diags := plan.Set(ctx, m); diags.HasError() {
		t.Fatalf("plan: %v", diags)
	}
	m.SecretsWo = types.MapValueMust(types.StringType, map[string]attr.Value{"client_secret": types.StringValue(secret)})
	config := cascConfig(t, sr.Schema, m)

	resp := resource.CreateResponse{State: tfsdk.State{Schema: sr.Schema}}
	r.Create(ctx, resource.CreateRequest{Plan: plan, Config: config}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}

	if !strings.Contains(posted, secret) || strings.Contains(posted, "${client_secret}") {
		t.Errorf("posted document did not substitute the secret:\n%s", posted)
	}
	if got := cascStateYAML(t, resp.State); got != declared {
		t.Errorf("state yaml = %q, want the declared document %q", got, declared)
	}
	assertCASCStateOmits(t, resp.State, secret)
}

func TestConfigurationAsCodeValidateConfigUnreferencedSecret(t *testing.T) {
	ctx := context.Background()
	r, s := cascTestResource("")

	for name, tc := range map[string]struct {
		keys    []string
		wantErr bool
	}{
		"all referenced": {keys: []string{"used"}},
		"typo":           {keys: []string{"used", "usde"}, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			m := cascNullModel("jenkins", "a: ${used}\n")
			elems := map[string]attr.Value{}
			for _, k := range tc.keys {
				elems[k] = types.StringValue("v")
			}
			m.SecretsWo = types.MapValueMust(types.StringType, elems)
			m.SecretsWoVersion = types.StringValue("1")
			config := cascConfig(t, s, m)
			var resp resource.ValidateConfigResponse
			r.ValidateConfig(ctx, resource.ValidateConfigRequest{Config: config}, &resp)
			if resp.Diagnostics.HasError() != tc.wantErr {
				t.Errorf("HasError = %v, want %v: %v", resp.Diagnostics.HasError(), tc.wantErr, resp.Diagnostics)
			}
			if tc.wantErr && !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "usde") {
				t.Errorf("diagnostic does not name the unreferenced key: %v", resp.Diagnostics)
			}
		})
	}
}

func TestConfigurationAsCodeReadUnorderedPaths(t *testing.T) {
	ctx := context.Background()
	declared := "authorizationStrategy:\n  roleBased:\n    roles:\n      global:\n        - name: admin\n          permissions: [Overall/Read, Overall/Administer]\n"
	export := "jenkins:\n  authorizationStrategy:\n    roleBased:\n      roles:\n        global:\n          - name: admin\n            permissions: [Overall/Administer, Overall/Read]\n"

	for name, tc := range map[string]struct {
		paths  []string
		inSync bool
	}{
		"ordered by default":    {inSync: false},
		"unordered permissions": {paths: []string{"authorizationStrategy.roleBased.roles.*.*.permissions"}, inSync: true},
	} {
		t.Run(name, func(t *testing.T) {
			r, s := cascTestResource(export)
			m := cascNullModel("jenkins", declared)
			m.ID = types.StringValue("jenkins")
			if tc.paths != nil {
				m.UnorderedPaths = types.SetValueMust(types.StringType, []attr.Value{types.StringValue(tc.paths[0])})
			}
			st := tfsdk.State{Schema: s}
			if diags := st.Set(ctx, m); diags.HasError() {
				t.Fatalf("state: %v", diags)
			}
			resp := resource.ReadResponse{State: st}
			r.Read(ctx, resource.ReadRequest{State: st}, &resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diags: %v", resp.Diagnostics)
			}
			if got := cascStateYAML(t, resp.State) == declared; got != tc.inSync {
				t.Errorf("yaml kept as declared = %v, want %v", got, tc.inSync)
			}
		})
	}
}
