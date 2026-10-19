package jenkins

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// The values JCasC resolves ${LAB_SECRET} to in the export: plaintext for a
// String-typed field, ciphertext for a Secret-typed one. Neither may reach
// state (docs/design/casc.md Q3, #249).
const (
	cascTestResolvedSecret = "dummy-lab-secret-0001"
	cascTestCiphertext     = "{AQAAABAAAAAgZHVtbXktbGFiLWNpcGhlcnRleHQ=}"
)

const cascTestDeclared = `location:
  adminAddress: "${LAB_SECRET}"
  url: "http://jenkins:8080/"
mailer:
  smtpHost: "smtp.example.invalid"
  authentication:
    username: "mailer"
    password: "${LAB_SECRET}"
`

// cascTestExport is a full export whose unclassified section resolved both
// placeholders and carries keys the resource does not manage.
func cascTestExport(url string) string {
	return `jenkins:
  systemMessage: hi
unclassified:
  location:
    adminAddress: "` + cascTestResolvedSecret + `"
    url: "` + url + `"
  mailer:
    smtpHost: smtp.example.invalid
    charset: UTF-8
    useSsl: false
    authentication:
      username: mailer
      password: "` + cascTestCiphertext + `"
  unmanagedPlugin:
    apiToken: unmanaged-token-value
`
}

// cascNullModel returns a model with section and yaml set and every optional
// attribute null, as a configuration that sets neither would plan it.
func cascNullModel(section, yaml string) configurationAsCodeResourceModel {
	return configurationAsCodeResourceModel{
		Section:          types.StringValue(section),
		YAML:             types.StringValue(yaml),
		SecretsWo:        types.MapNull(types.StringType),
		SecretsWoVersion: types.StringNull(),
	}
}

func cascTestResource(export string) (*configurationAsCodeResource, rschema.Schema) {
	r := &configurationAsCodeResource{resourceHelper: &resourceHelper{client: &mockJenkinsClient{
		mockExportCASC: func(context.Context) (string, error) { return export, nil },
	}}}
	var sr resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &sr)
	return r, sr.Schema
}

func TestConfigurationAsCodeReadDriftView(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name     string
		declared string
		export   string
		// want is the expected state yaml, compared semantically. Ignored
		// when inSync or removed is set.
		want           string
		inSync         bool
		removed        bool
		mustNotContain []string
	}{
		{
			name:     "in sync export keeps the declared document",
			declared: cascTestDeclared,
			export:   cascTestExport("http://jenkins:8080/"),
			inSync:   true,
		},
		{
			name:     "drift on an unrelated key keeps placeholders and drops unmanaged keys",
			declared: cascTestDeclared,
			export:   cascTestExport("http://changed.example:8080/"),
			want: `location:
  adminAddress: "${LAB_SECRET}"
  url: "http://changed.example:8080/"
mailer:
  smtpHost: "smtp.example.invalid"
  authentication:
    username: "mailer"
    password: "${LAB_SECRET}"
`,
			mustNotContain: []string{cascTestResolvedSecret, cascTestCiphertext, "charset", "useSsl", "unmanagedPlugin", "unmanaged-token-value"},
		},
		{
			name: "sequence element change copies only the declared keys",
			declared: `globalLibraries:
  libraries:
    - name: shared-pipeline
      defaultVersion: main
`,
			export: `unclassified:
  globalLibraries:
    libraries:
      - name: shared-pipeline
        defaultVersion: release
        implicit: false
        retriever:
          modernSCM:
            scm:
              git:
                credentialsId: shared-pipeline-token
  location:
    adminAddress: "` + cascTestResolvedSecret + `"
`,
			want: `globalLibraries:
  libraries:
    - name: shared-pipeline
      defaultVersion: release
`,
			mustNotContain: []string{cascTestResolvedSecret, "implicit", "retriever", "shared-pipeline-token"},
		},
		{
			// Positional copying would put the resolved token under b's
			// declared plain value once the controller reorders the list.
			name: "reordered sequence holding a placeholder is not copied",
			declared: `items:
  - name: a
    token: "${A_TOKEN}"
  - name: b
    token: not-secret
`,
			export: `unclassified:
  items:
    - name: b
      token: not-secret
    - name: a
      token: resolved-a-token
`,
			mustNotContain: []string{"resolved-a-token"},
		},
		{
			name:     "missing section removes the resource",
			declared: cascTestDeclared,
			export:   "jenkins:\n  systemMessage: hi\n",
			removed:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, s := cascTestResource(tc.export)
			st := tfsdk.State{Schema: s}
			m := cascNullModel("unclassified", tc.declared)
			m.ID = types.StringValue("unclassified")
			if diags := st.Set(ctx, m); diags.HasError() {
				t.Fatalf("setting state: %v", diags)
			}
			resp := resource.ReadResponse{State: st}
			r.Read(ctx, resource.ReadRequest{State: st}, &resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diags: %v", resp.Diagnostics)
			}

			if tc.removed {
				if !resp.State.Raw.IsNull() {
					t.Fatalf("expected the resource to be removed, state = %s", resp.State.Raw)
				}
				return
			}

			assertCASCStateOmits(t, resp.State, tc.mustNotContain...)
			got := cascStateYAML(t, resp.State)
			if tc.inSync {
				if got != tc.declared {
					t.Errorf("in-sync Read rewrote yaml:\n got: %q\nwant: %q", got, tc.declared)
				}
				return
			}

			gotDoc, declaredDoc := mustParseYAML(t, got), mustParseYAML(t, tc.declared)
			if reflect.DeepEqual(gotDoc, declaredDoc) {
				t.Errorf("drift must leave yaml different from the declared document so a plan diff appears; got:\n%s", got)
			}
			if tc.want != "" {
				if wantDoc := mustParseYAML(t, tc.want); !reflect.DeepEqual(gotDoc, wantDoc) {
					t.Errorf("drift view mismatch:\n got: %#v\nwant: %#v", gotDoc, wantDoc)
				}
			}
		})
	}
}

func TestConfigurationAsCodeImportStateOmitsExport(t *testing.T) {
	ctx := context.Background()
	r, s := cascTestResource(cascTestExport("http://jenkins:8080/"))

	imp := resource.ImportStateResponse{State: tfsdk.State{Schema: s, Raw: covMNull(ctx, s)}}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "unclassified"}, &imp)
	if imp.Diagnostics.HasError() {
		t.Fatalf("unexpected import diags: %v", imp.Diagnostics)
	}
	assertCASCStateOmits(t, imp.State, cascTestResolvedSecret, cascTestCiphertext, "unmanagedPlugin")

	var section, id, yaml types.String
	imp.State.GetAttribute(ctx, path.Root("section"), &section)
	imp.State.GetAttribute(ctx, path.Root("id"), &id)
	imp.State.GetAttribute(ctx, path.Root("yaml"), &yaml)
	if section.ValueString() != "unclassified" || id.ValueString() != "unclassified" {
		t.Errorf("section/id = %q/%q, want unclassified", section.ValueString(), id.ValueString())
	}
	if !yaml.IsNull() {
		t.Errorf("import must not store the exported section; yaml = %q", yaml.ValueString())
	}

	// The Read that follows an import must not fill yaml from the export
	// either; the first plan then shows the configured yaml being applied.
	read := resource.ReadResponse{State: imp.State}
	r.Read(ctx, resource.ReadRequest{State: imp.State}, &read)
	if read.Diagnostics.HasError() {
		t.Fatalf("unexpected read diags: %v", read.Diagnostics)
	}
	assertCASCStateOmits(t, read.State, cascTestResolvedSecret, cascTestCiphertext, "unmanagedPlugin")
	read.State.GetAttribute(ctx, path.Root("yaml"), &yaml)
	if !yaml.IsNull() {
		t.Errorf("Read after import must keep yaml null; yaml = %q", yaml.ValueString())
	}
}

func cascStateYAML(t *testing.T, st tfsdk.State) string {
	t.Helper()
	var v types.String
	if diags := st.GetAttribute(context.Background(), path.Root("yaml"), &v); diags.HasError() {
		t.Fatalf("reading yaml from state: %v", diags)
	}
	return v.ValueString()
}

// assertCASCStateOmits fails if any of the given strings appears anywhere in
// the state object, not just in yaml.
func assertCASCStateOmits(t *testing.T, st tfsdk.State, values ...string) {
	t.Helper()
	raw := st.Raw.String()
	var leaked []string
	for _, v := range values {
		if strings.Contains(raw, v) {
			leaked = append(leaked, v)
		}
	}
	if len(leaked) > 0 {
		t.Errorf("state contains %q:\n%s", leaked, raw)
	}
}

func mustParseYAML(t *testing.T, s string) interface{} {
	t.Helper()
	v, err := parseYAML(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return v
}
