package jenkins

import (
	"context"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type configurationAsCodeResourceModel struct {
	ID               types.String `tfsdk:"id"`
	Section          types.String `tfsdk:"section"`
	YAML             types.String `tfsdk:"yaml"`
	SecretsWo        types.Map    `tfsdk:"secrets_wo"`
	SecretsWoVersion types.String `tfsdk:"secrets_wo_version"`
}

type configurationAsCodeResource struct {
	*resourceHelper
}

var _ resource.ResourceWithConfigure = &configurationAsCodeResource{}
var _ resource.ResourceWithImportState = &configurationAsCodeResource{}
var _ resource.ResourceWithConfigValidators = &configurationAsCodeResource{}
var _ resource.ResourceWithValidateConfig = &configurationAsCodeResource{}

func newConfigurationAsCodeResource() resource.Resource {
	return &configurationAsCodeResource{
		resourceHelper: newResourceHelper(),
	}
}

func (r *configurationAsCodeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_configuration_as_code"
}

func (r *configurationAsCodeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `Manages one top-level section of the controller configuration through the ` + "`configuration-as-code`" + ` (JCasC) plugin.

Each instance owns a single top-level JCasC section (` + "`jenkins`, `security`, `unclassified`, `tool`, ..." + `) named by ` + "`section`" + `, and applies the ` + "`yaml`" + ` subtree for it. See the [design notes](https://github.com/namecheap/terraform-provider-jenkins/blob/main/docs/design/casc.md) for the full model.

Key behaviours:

- **Merge, not replace.** Applying a section merges the declared keys into the running configuration; keys present on the controller but not in ` + "`yaml`" + ` are left untouched. Drift is detected as a *subset*: only keys you declare are compared.
- **Lists of scalars are unordered.** A list whose elements are all scalars (a role's permissions, for example) matches the controller's list in any order, because plugins export set-backed lists in their own order. Every other list is compared element by element, in order.
- **Secrets.** Reference a secret as ` + "`${NAME}`" + ` in ` + "`yaml`" + `. When ` + "`NAME`" + ` is a key of ` + "`secrets_wo`" + `, the provider substitutes the value at apply; otherwise the controller resolves it from its own JCasC secret sources (environment variables, files, ...). Either way the value is never stored in state, and a key whose whole value is a reference is never compared. A string with a reference inside it is compared on its other characters only.
- **Delete is best-effort.** JCasC cannot "unset" configuration, so destroying this resource only stops managing the section — the applied values remain on the controller.

Requires the ` + "`configuration-as-code`" + ` plugin and an account with ` + "`Overall/Administer`" + `.`,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The managed section name (same as `section`).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"section": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The top-level JCasC configuration section this resource manages, e.g. `jenkins`, `security`, `unclassified`, or `tool`. Changing it forces replacement.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					stringvalidator.RegexMatches(reCASCSection, "must be a bare top-level key (letters, digits, '_' or '-')"),
				},
			},
			"yaml": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The YAML subtree for `section` (the content *under* the section key, not including the key itself). May reference secrets as `${NAME}`, filled from `secrets_wo` or by the controller's JCasC interpolation.",
			},
			"secrets_wo": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Sensitive:   true,
				WriteOnly:   true,
				MarkdownDescription: "Secret values substituted for the `${NAME}` references of `yaml` at apply, keyed by `NAME`. Write-only: the values are **never stored in Terraform state or plan**, so `yaml` itself holds no secret and its diff stays readable. " +
					"A value is applied verbatim: the provider escapes any `${` in it, so JCasC does not interpolate it. Every key must be referenced in `yaml`, since JCasC silently resolves a misspelled reference to an empty string. " +
					"A reference written `^${NAME}` is JCasC's escaped literal and is not substituted. Requires Terraform >= 1.11 and must be paired with `secrets_wo_version`.",
				Validators: []validator.Map{
					mapvalidator.KeysAre(stringvalidator.RegexMatches(reCASCSecretName, "must be a name of letters, digits and '_', not starting with a digit")),
				},
			},
			"secrets_wo_version": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Version identifier for `secrets_wo`. Because a write-only value is not stored in state, Terraform cannot detect when it changes; " +
					"change this value (e.g. after rotating a secret) to have Terraform re-apply the section with the current `secrets_wo`. Required when `secrets_wo` is set.",
			},
		},
	}
}

// ConfigValidators pairs secrets_wo with its version trigger.
func (r *configurationAsCodeResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.RequiredTogether(path.MatchRoot("secrets_wo"), path.MatchRoot("secrets_wo_version")),
	}
}

// ValidateConfig rejects a secrets_wo key that yaml does not reference. JCasC
// resolves an unknown ${NAME} to an empty string without error, so a typo on
// either side would otherwise apply an empty secret.
func (r *configurationAsCodeResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var yamlDoc types.String
	var secrets types.Map
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("yaml"), &yamlDoc)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("secrets_wo"), &secrets)...)
	if resp.Diagnostics.HasError() || yamlDoc.IsNull() || yamlDoc.IsUnknown() || secrets.IsNull() || secrets.IsUnknown() {
		return
	}
	// Invalid YAML is reported by apply, which parses it anyway.
	declared, err := parseYAML(yamlDoc.ValueString())
	if err != nil {
		return
	}
	referenced := secretReferences(declared)
	names := make([]string, 0, len(secrets.Elements()))
	for name := range secrets.Elements() {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !referenced[name] {
			resp.Diagnostics.AddAttributeError(
				path.Root("secrets_wo").AtMapKey(name),
				"Unreferenced Secret",
				"yaml has no ${"+name+"} reference for this secrets_wo key. JCasC resolves an unknown reference to an empty string, so a misspelled name would apply an empty secret. "+
					"Reference it in yaml, or remove the key.",
			)
		}
	}
}

func (r *configurationAsCodeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Debug(ctx, "configurationAsCodeResource.Create")
	var data configurationAsCodeResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.apply(ctx, req.Config, &data, &resp.Diagnostics) {
		return
	}

	data.ID = data.Section
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *configurationAsCodeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	tflog.Debug(ctx, "configurationAsCodeResource.Read")
	var data configurationAsCodeResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exported, err := r.client.ExportCASC(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to Refresh Resource", "Could not export JCasC configuration.\n\nError: "+err.Error())
		return
	}

	section := data.Section.ValueString()
	inSync, err := cascInSync(data.YAML.ValueString(), exported, section)
	if err != nil {
		resp.Diagnostics.AddError("Unable to Compare Configuration", err.Error())
		return
	}

	if !inSync {
		// The controller no longer matches the declared subtree. Reflect the
		// actual state so a diff (and a reconciling apply) is produced. If the
		// section is gone entirely, drop the resource so it is recreated.
		actual, found, err := extractSectionYAML(exported, section)
		if err != nil {
			resp.Diagnostics.AddError("Unable to Read Section", err.Error())
			return
		}
		if !found {
			resp.State.RemoveResource(ctx)
			return
		}
		data.YAML = types.StringValue(actual)
	}

	data.ID = data.Section
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *configurationAsCodeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Debug(ctx, "configurationAsCodeResource.Update")
	var data configurationAsCodeResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.apply(ctx, req.Config, &data, &resp.Diagnostics) {
		return
	}

	data.ID = data.Section
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete only stops managing the section: JCasC has no operation to remove
// previously-applied configuration, so the values remain on the controller.
func (r *configurationAsCodeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Debug(ctx, "configurationAsCodeResource.Delete (no-op)")
	var data configurationAsCodeResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.AddWarning(
		"Configuration Not Removed",
		"JCasC cannot un-apply configuration, so the '"+data.Section.ValueString()+"' section previously applied by this "+
			"resource remains on the controller. Remove or override it manually if it is no longer wanted.",
	)
}

// ImportState imports by section name, populating yaml from the controller's
// current export of that section so the imported state is self-consistent.
func (r *configurationAsCodeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	section := req.ID
	exported, err := r.client.ExportCASC(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to Import Resource", "Could not export JCasC configuration.\n\nError: "+err.Error())
		return
	}
	actual, found, err := extractSectionYAML(exported, section)
	if err != nil {
		resp.Diagnostics.AddError("Unable to Import Resource", err.Error())
		return
	}
	if !found {
		resp.Diagnostics.AddError("Section Not Found", "The controller has no JCasC section named "+section+".")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("section"), section)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), section)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("yaml"), actual)...)
}

// apply wraps the declared subtree in its section key, with the secrets_wo
// values of config substituted, and POSTs it to JCasC. Write-only values are
// absent from the plan, hence config. Returns false (with a diagnostic) on
// failure.
func (r *configurationAsCodeResource) apply(ctx context.Context, config tfsdk.Config, data *configurationAsCodeResourceModel, diags *diag.Diagnostics) bool {
	var secretsWo types.Map
	diags.Append(config.GetAttribute(ctx, path.Root("secrets_wo"), &secretsWo)...)
	secrets := map[string]string{}
	if !secretsWo.IsNull() {
		diags.Append(secretsWo.ElementsAs(ctx, &secrets, false)...)
	}
	if diags.HasError() {
		return false
	}

	doc, err := wrapSection(data.Section.ValueString(), data.YAML.ValueString(), secrets)
	if err != nil {
		diags.AddAttributeError(path.Root("yaml"), "Invalid YAML", err.Error())
		return false
	}
	if err := r.client.ApplyCASC(ctx, doc); err != nil {
		diags.AddError("Unable to Apply Configuration", "JCasC rejected the configuration for section "+data.Section.ValueString()+".\n\nError: "+redactSecrets(err.Error(), secrets))
		return false
	}
	return true
}

// redactSecrets masks the secrets_wo values in s, in the escaped form
// substituteSecrets applies too, since a JCasC error may quote the posted
// document. Longest first: the replacer tries its pairs in order, and a secret
// that prefixes another must not leave the rest of the other one in clear.
func redactSecrets(s string, secrets map[string]string) string {
	var values []string
	for _, v := range secrets {
		if v != "" {
			values = append(values, v, strings.ReplaceAll(v, "${", "^${"))
		}
	}
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	pairs := make([]string, 0, 2*len(values))
	for _, v := range values {
		pairs = append(pairs, v, "(sensitive value)")
	}
	return strings.NewReplacer(pairs...).Replace(s)
}
