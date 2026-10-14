package jenkins

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// This file holds the YAML core of the jenkins_configuration_as_code resource
// (see docs/design/casc.md): drift detection and secret substitution. It is
// pure logic, no network and no provider surface.
//
// The resource manages one top-level JCasC section per instance. Drift is
// detected by comparing the declared section subtree against the full
// configuration returned by GET /configuration-as-code/export as a semantic
// deep subset: only keys the practitioner declares are compared, so the many
// default and unmanaged keys in the export are ignored.

// reSecretPlaceholder matches a JCasC secret interpolation expression such as
// ${SECRET} or ${SECRET:-default}. A managed key whose declared value is such
// an expression is compared structurally only: JCasC resolves it at apply time,
// and the resolved secret must never influence drift or leak into state.
var reSecretPlaceholder = regexp.MustCompile(`^\s*\$\{[^}]+\}\s*$`)

// reEmbeddedPlaceholder matches a ${...} expression anywhere in a string.
var reEmbeddedPlaceholder = regexp.MustCompile(`\$\{[^}]+\}`)

// reCASCSection matches a valid top-level JCasC section key: a bare identifier
// of letters, digits, underscores, or hyphens (e.g. "jenkins", "unclassified").
var reCASCSection = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// reCASCSecretName matches a secrets_wo key, the NAME of a ${NAME} reference.
// No ':' so a key never reads as a JCasC lookup such as ${readFile:...}.
var reCASCSecretName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// reSecretReference matches a ${NAME} reference that substituteSecrets may
// fill. Submatch 1 is NAME.
var reSecretReference = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// cascSetPaths are the lists of scalars that Jenkins keeps in a HashSet and so
// exports in hash order, not in the applied one. They are compared in any
// order; every other list keeps its order, which may be significant. A path
// starts at the section key; "*" matches any mapping key or list element.
var cascSetPaths = [][]string{
	// Role-strategy permissions of global, item and agent roles.
	{"jenkins", "authorizationStrategy", "roleBased", "roles", "*", "*", "permissions"},
	{"jenkins", "disabledAdministrativeMonitors"},
}

// isSetPath reports whether path matches one of cascSetPaths.
func isSetPath(path []string) bool {
	for _, pattern := range cascSetPaths {
		if len(pattern) != len(path) {
			continue
		}
		match := true
		for i := range pattern {
			if pattern[i] != "*" && pattern[i] != path[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// isSecretPlaceholder reports whether v is a scalar JCasC ${...} secret
// expression.
func isSecretPlaceholder(v interface{}) bool {
	s, ok := v.(string)
	return ok && reSecretPlaceholder.MatchString(s)
}

// placeholderMatch compares a declared string holding ${...} expressions with
// the actual value: each expression matches any text, the rest must be equal.
// The controller resolves the expressions, so only the literal parts are known.
func placeholderMatch(declared string, actual interface{}) bool {
	a, ok := actual.(string)
	if !ok {
		return false
	}
	literals := reEmbeddedPlaceholder.Split(declared, -1)
	for i, l := range literals {
		literals[i] = regexp.QuoteMeta(l)
	}
	re, err := regexp.Compile(`(?s)^` + strings.Join(literals, ".*") + `$`)
	return err == nil && re.MatchString(a)
}

// parseYAML decodes a YAML document into a generic structure
// (map[string]interface{}, []interface{}, scalars) for semantic comparison.
func parseYAML(s string) (interface{}, error) {
	var out interface{}
	if err := yaml.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// yamlSubset reports whether declared is a deep subset of actual:
//
//   - Mappings: every key declared must exist in actual with a subset-equal
//     value; keys present only in actual (defaults, unmanaged settings) are
//     ignored.
//   - Sequences: must have the same length, because JCasC list configurators
//     are replace-semantics, and match element-for-element. A list of scalars
//     at one of cascSetPaths matches in any order instead: Jenkins exports it
//     in hash order, which is not drift.
//   - Scalars: must be equal.
//
// A declared scalar that is a ${...} secret placeholder matches any actual
// value, so a resolved secret never registers as drift. A string with ${...}
// expressions inside it matches on its literal parts only.
//
// path locates declared from the section key, for cascSetPaths.
func yamlSubset(declared, actual interface{}, path []string) bool {
	if isSecretPlaceholder(declared) {
		return true
	}

	switch d := declared.(type) {
	case map[string]interface{}:
		a, ok := actual.(map[string]interface{})
		if !ok {
			return false
		}
		for k, dv := range d {
			av, ok := a[k]
			if !ok {
				return false
			}
			if !yamlSubset(dv, av, append(path[:len(path):len(path)], k)) {
				return false
			}
		}
		return true
	case []interface{}:
		a, ok := actual.([]interface{})
		if !ok || len(a) != len(d) {
			return false
		}
		if isScalarList(d) && isSetPath(path) {
			return unorderedMatch(d, a)
		}
		for i := range d {
			if !yamlSubset(d[i], a[i], append(path[:len(path):len(path)], strconv.Itoa(i))) {
				return false
			}
		}
		return true
	case string:
		if reEmbeddedPlaceholder.MatchString(d) {
			return placeholderMatch(d, actual)
		}
		return d == actual
	default:
		return reflect.DeepEqual(declared, actual)
	}
}

// isScalarList reports whether no element of l is a mapping or a sequence.
func isScalarList(l []interface{}) bool {
	for _, v := range l {
		switch v.(type) {
		case map[string]interface{}, map[interface{}]interface{}, []interface{}:
			return false
		}
	}
	return true
}

// unorderedMatch reports whether every declared element can be paired with a
// distinct actual element it matches, the lists being of equal length. It is a
// bipartite matching (augmenting paths) rather than a greedy pass, because a
// placeholder matches several elements and must not take the one a literal
// needs.
func unorderedMatch(declared, actual []interface{}) bool {
	owner := make([]int, len(actual)) // declared index paired with actual[j], or -1
	for j := range owner {
		owner[j] = -1
	}
	var assign func(i int, seen []bool) bool
	assign = func(i int, seen []bool) bool {
		for j := range actual {
			if seen[j] || !yamlSubset(declared[i], actual[j], nil) {
				continue
			}
			seen[j] = true
			if owner[j] < 0 || assign(owner[j], seen) {
				owner[j] = i
				return true
			}
		}
		return false
	}
	for i := range declared {
		if !assign(i, make([]bool, len(actual))) {
			return false
		}
	}
	return true
}

// cascInSync reports whether the declared single-section YAML is a semantic
// subset of the full exported JCasC configuration. section is the top-level key
// the declared document manages (e.g. "jenkins"); declaredSectionYAML is the
// bare subtree for that section, and exportedFullYAML is the whole document
// returned by /configuration-as-code/export.
//
// It returns true when the controller already satisfies everything declared
// (no drift), false when a managed key differs or is missing, and an error only
// when either document cannot be parsed.
func cascInSync(declaredSectionYAML, exportedFullYAML, section string) (bool, error) {
	declared, err := parseYAML(declaredSectionYAML)
	if err != nil {
		return false, fmt.Errorf("parsing declared YAML: %w", err)
	}
	exported, err := parseYAML(exportedFullYAML)
	if err != nil {
		return false, fmt.Errorf("parsing exported YAML: %w", err)
	}

	exportedMap, ok := exported.(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("exported configuration is not a YAML mapping")
	}

	actual, ok := exportedMap[section]
	if !ok {
		// The section is absent from the controller: in sync only if nothing is
		// declared for it.
		return declared == nil, nil
	}

	return yamlSubset(declared, actual, []string{section}), nil
}

// mapStrings returns a copy of v with f applied to every string scalar.
// Mapping keys are left as they are.
func mapStrings(v interface{}, f func(string) string) interface{} {
	switch t := v.(type) {
	case string:
		return f(t)
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, e := range t {
			out[k] = mapStrings(e, f)
		}
		return out
	case map[interface{}]interface{}:
		out := make(map[interface{}]interface{}, len(t))
		for k, e := range t {
			out[k] = mapStrings(e, f)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, e := range t {
			out[i] = mapStrings(e, f)
		}
		return out
	default:
		return v
	}
}

// replaceSecretReferences calls f for each ${NAME} reference in s that JCasC
// would interpolate, and replaces the reference with what f returns when ok.
// A reference right after ^ is JCasC's escaped literal and is skipped.
func replaceSecretReferences(s string, f func(name string) (string, bool)) string {
	var b strings.Builder
	last := 0
	for _, m := range reSecretReference.FindAllStringSubmatchIndex(s, -1) {
		if m[0] > 0 && s[m[0]-1] == '^' {
			continue
		}
		if value, ok := f(s[m[2]:m[3]]); ok {
			b.WriteString(s[last:m[0]])
			b.WriteString(value)
			last = m[1]
		}
	}
	b.WriteString(s[last:])
	return b.String()
}

// substituteSecrets returns a copy of the parsed tree v with each ${NAME}
// reference whose NAME is a key of secrets replaced by its value. Other
// references are left for JCasC to resolve from its own secret sources.
//
// JCasC interpolates the whole applied document, substituted values included,
// so a value is escaped with JCasC's ^${ escape. Otherwise JCasC would resolve
// a ${...} inside a secret, to "" when the name is unknown to it.
func substituteSecrets(v interface{}, secrets map[string]string) interface{} {
	if len(secrets) == 0 {
		return v
	}
	return mapStrings(v, func(s string) string {
		return replaceSecretReferences(s, func(name string) (string, bool) {
			value, ok := secrets[name]
			return strings.ReplaceAll(value, "${", "^${"), ok
		})
	})
}

// secretReferences returns the NAMEs of the ${NAME} references in the string
// scalars of the parsed tree v that substituteSecrets would fill.
func secretReferences(v interface{}) map[string]bool {
	names := map[string]bool{}
	mapStrings(v, func(s string) string {
		return replaceSecretReferences(s, func(name string) (string, bool) {
			names[name] = true
			return "", false
		})
	})
	return names
}

// wrapSection wraps a declared section subtree under its top-level section key,
// with secrets substituted (see substituteSecrets), producing the
// single-section YAML document POSTed to JCasC configure.
func wrapSection(section, declaredSectionYAML string, secrets map[string]string) (string, error) {
	subtree, err := parseYAML(declaredSectionYAML)
	if err != nil {
		return "", fmt.Errorf("parsing declared YAML: %w", err)
	}
	out, err := yaml.Marshal(map[string]interface{}{section: substituteSecrets(subtree, secrets)})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// extractSectionYAML returns the given top-level section's subtree from a full
// exported JCasC document, marshaled back to YAML. found is false when the
// section is absent from the export.
func extractSectionYAML(exportedFullYAML, section string) (yamlDoc string, found bool, err error) {
	exported, err := parseYAML(exportedFullYAML)
	if err != nil {
		return "", false, fmt.Errorf("parsing exported YAML: %w", err)
	}
	m, ok := exported.(map[string]interface{})
	if !ok {
		return "", false, fmt.Errorf("exported configuration is not a YAML mapping")
	}
	sub, ok := m[section]
	if !ok {
		return "", false, nil
	}
	out, err := yaml.Marshal(sub)
	if err != nil {
		return "", false, err
	}
	return string(out), true, nil
}
