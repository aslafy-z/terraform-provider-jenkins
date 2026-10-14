package jenkins

import (
	"reflect"
	"testing"
)

func TestIsSecretPlaceholder(t *testing.T) {
	cases := map[string]struct {
		in   interface{}
		want bool
	}{
		"bare placeholder":         {"${SECRET}", true},
		"placeholder with default": {"${SECRET:-fallback}", true},
		"padded placeholder":       {"  ${SECRET}  ", true},
		"plain string":             {"hello", false},
		"embedded not whole":       {"prefix-${SECRET}", false},
		"non-string int":           {42, false},
		"nil":                      {nil, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := isSecretPlaceholder(tc.in); got != tc.want {
				t.Errorf("isSecretPlaceholder(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseYAML(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		v, err := parseYAML("a: 1\nb: two\n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m, ok := v.(map[string]interface{})
		if !ok {
			t.Fatalf("expected a mapping, got %T", v)
		}
		if m["a"] != 1 || m["b"] != "two" {
			t.Errorf("unexpected parse result: %#v", m)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		if _, err := parseYAML("a: [unterminated\n"); err == nil {
			t.Fatal("expected a parse error for malformed YAML")
		}
	})
}

func TestYAMLSubset(t *testing.T) {
	mustParse := func(s string) interface{} {
		v, err := parseYAML(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		return v
	}

	cases := []struct {
		name             string
		declared, actual string
		want             bool
	}{
		{"equal scalars", "x", "x", true},
		{"unequal scalars", "x", "y", false},
		{"map subset ignores extra keys", "a: 1", "a: 1\nb: 2", true},
		{"map missing declared key", "a: 1\nc: 3", "a: 1\nb: 2", false},
		{"map changed value is drift", "a: 1", "a: 2", false},
		{"nested map subset", "outer:\n  a: 1", "outer:\n  a: 1\n  b: 2", true},
		{"nested map drift", "outer:\n  a: 1", "outer:\n  a: 9", false},
		{"equal lists", "[1, 2, 3]", "[1, 2, 3]", true},
		{"list length differs", "[1, 2]", "[1, 2, 3]", false},
		{"list element differs", "[1, 2, 3]", "[1, 2, 4]", false},
		{"secret placeholder ignores actual", "token: ${SECRET}", "token: resolved-value", true},
		{"secret placeholder with default", "token: ${SECRET:-x}", "token: anything", true},
		{"type mismatch map vs scalar", "a: 1", "a", false},
		{"bool values", "flag: true", "flag: true\nother: false", true},
		// Plugins export set-backed lists in their own order (role permissions in
		// hash order, disabledAdministrativeMonitors sorted), so the order of a
		// list of scalars is not drift.
		{"scalar list order ignored", "[Job/Read, Job/Build, Job/Cancel]", "[Job/Cancel, Job/Read, Job/Build]", true},
		{"scalar list duplicates counted", "[a, a, b]", "[a, b, b]", false},
		{"scalar list element missing", "[a, b]", "[a, c]", false},
		{"scalar list placeholder leaves the literal its match", "['${X}', a]", "[a, b]", true},
		{"list of mappings stays ordered", "[{a: 1}, {b: 2}]", "[{b: 2}, {a: 1}]", false},
		{"mixed list stays ordered", "[a, {b: 2}]", "[{b: 2}, a]", false},
		{"embedded placeholder matches the literal parts", "url: https://${HOST}/x", "url: https://h.example/x", true},
		{"embedded placeholder literal part drift", "url: https://${HOST}/x", "url: https://h.example/y", false},
		{"embedded placeholder against a non-string", "n: ${A}0", "n: 10", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := yamlSubset(mustParse(tc.declared), mustParse(tc.actual))
			if got != tc.want {
				t.Errorf("yamlSubset(%q, %q) = %v, want %v", tc.declared, tc.actual, got, tc.want)
			}
		})
	}
}

func TestWrapSection(t *testing.T) {
	t.Run("wraps a subtree under its section key", func(t *testing.T) {
		doc, err := wrapSection("jenkins", "systemMessage: hi", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		v, err := parseYAML(doc)
		if err != nil {
			t.Fatalf("wrapped doc is not valid YAML: %v", err)
		}
		m, ok := v.(map[string]interface{})
		if !ok {
			t.Fatalf("expected a mapping, got %T", v)
		}
		inner, ok := m["jenkins"].(map[string]interface{})
		if !ok || inner["systemMessage"] != "hi" {
			t.Errorf("unexpected wrapped structure: %#v", m)
		}
	})

	t.Run("invalid YAML errors", func(t *testing.T) {
		if _, err := wrapSection("jenkins", "a: [bad\n", nil); err == nil {
			t.Error("expected an error for malformed YAML")
		}
	})

	t.Run("substitutes secrets", func(t *testing.T) {
		doc, err := wrapSection("unclassified", "mailer:\n  password: ${PASS}\n", map[string]string{"PASS": "s3cr3t"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := "unclassified:\n    mailer:\n        password: s3cr3t\n"; doc != want {
			t.Errorf("wrapSection = %q, want %q", doc, want)
		}
	})
}

func TestSubstituteSecrets(t *testing.T) {
	secrets := map[string]string{
		"A":      "s3cr3t",
		"QUOTES": "it's \"quoted\": yes\nsecond line",
		"DOLLAR": "x${HOME}y",
		"CARET":  "^${HOME}",
	}
	cases := []struct {
		name     string
		declared string
		want     interface{}
	}{
		{"whole scalar", "${A}", "s3cr3t"},
		{"embedded", "https://user:${A}@host/${A}", "https://user:s3cr3t@host/s3cr3t"},
		{"escaped reference is left for JCasC", "^${A}", "^${A}"},
		{"unknown name is left for JCasC", "${OTHER}", "${OTHER}"},
		{"default form is left for JCasC", "${A:-fallback}", "${A:-fallback}"},
		// JCasC interpolates the applied document, a substituted value included;
		// ^ before ${ is its escape, so the controller stores x${HOME}y.
		{"interpolation in a value is escaped", "${DOLLAR}", "x^${HOME}y"},
		{"escape in a value is escaped", "${CARET}", "^^${HOME}"},
		{"value with YAML syntax", "${QUOTES}", "it's \"quoted\": yes\nsecond line"},
		{"non-string scalar untouched", "42", 42},
		{"nested in maps and lists", "outer:\n  list: [plain, '${A}']\n  '${A}': key", map[string]interface{}{
			"outer": map[string]interface{}{
				"list": []interface{}{"plain", "s3cr3t"},
				"${A}": "key",
			},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			declared, err := parseYAML(tc.declared)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.declared, err)
			}
			got := substituteSecrets(declared, secrets)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("substituteSecrets(%q) = %#v, want %#v", tc.declared, got, tc.want)
			}
		})
	}

	t.Run("declared tree is not modified", func(t *testing.T) {
		declared, _ := parseYAML("a: ${A}\nl: ['${A}']")
		substituteSecrets(declared, secrets)
		m := declared.(map[string]interface{})
		if m["a"] != "${A}" || m["l"].([]interface{})[0] != "${A}" {
			t.Errorf("declared tree was modified: %#v", m)
		}
	})
}

func TestSecretReferences(t *testing.T) {
	declared, err := parseYAML("a: ${ONE}\nb: ['x-${TWO}-y', '^${THREE}', '${FOUR:-d}']\n'${FIVE}': k\n")
	if err != nil {
		t.Fatal(err)
	}
	got := secretReferences(declared)
	want := map[string]bool{"ONE": true, "TWO": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("secretReferences = %v, want %v", got, want)
	}
}

func TestExtractSectionYAML(t *testing.T) {
	exported := "jenkins:\n  systemMessage: hi\nsecurity:\n  x: 1\n"

	t.Run("extracts and round-trips a section", func(t *testing.T) {
		sub, found, err := extractSectionYAML(exported, "jenkins")
		if err != nil || !found {
			t.Fatalf("found=%v err=%v", found, err)
		}
		v, _ := parseYAML(sub)
		m, ok := v.(map[string]interface{})
		if !ok || m["systemMessage"] != "hi" {
			t.Errorf("unexpected extracted subtree: %#v", v)
		}
	})

	t.Run("absent section", func(t *testing.T) {
		_, found, err := extractSectionYAML(exported, "tool")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found {
			t.Error("expected found=false for an absent section")
		}
	})

	t.Run("invalid YAML errors", func(t *testing.T) {
		if _, _, err := extractSectionYAML("a: [bad\n", "jenkins"); err == nil {
			t.Error("expected an error for malformed YAML")
		}
	})
}

func TestCASCInSync(t *testing.T) {
	exported := `
jenkins:
  systemMessage: "Managed by Terraform"
  numExecutors: 2
  mode: NORMAL
security:
  apiToken:
    creationOfLegacyTokenEnabled: false
`

	t.Run("declared subtree in sync", func(t *testing.T) {
		declared := `systemMessage: "Managed by Terraform"`
		ok, err := cascInSync(declared, exported, "jenkins")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Error("expected in-sync (no drift)")
		}
	})

	t.Run("unmanaged keys in export are ignored", func(t *testing.T) {
		// Declares only systemMessage; numExecutors/mode in the export must not
		// register as drift.
		declared := `systemMessage: "Managed by Terraform"`
		ok, err := cascInSync(declared, exported, "jenkins")
		if err != nil || !ok {
			t.Errorf("expected in-sync ignoring unmanaged keys, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("changed managed value is drift", func(t *testing.T) {
		declared := `systemMessage: "Different message"`
		ok, err := cascInSync(declared, exported, "jenkins")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok {
			t.Error("expected drift for a changed managed value")
		}
	})

	t.Run("secret placeholder never drifts", func(t *testing.T) {
		exportedWithToken := "unclassified:\n  myPlugin:\n    token: \"resolved-secret-value\"\n"
		declared := "myPlugin:\n  token: ${MY_TOKEN}\n"
		ok, err := cascInSync(declared, exportedWithToken, "unclassified")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Error("expected no drift: a ${...} secret must be compared structurally")
		}
	})

	t.Run("section absent with nothing declared is in sync", func(t *testing.T) {
		ok, err := cascInSync("", exported, "tool")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Error("expected in-sync when the section is absent and nothing declared")
		}
	})

	t.Run("section absent with something declared is drift", func(t *testing.T) {
		declared := `installations: []`
		ok, err := cascInSync(declared, exported, "tool")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok {
			t.Error("expected drift when a declared section is missing from the controller")
		}
	})

	t.Run("invalid declared YAML errors", func(t *testing.T) {
		if _, err := cascInSync("a: [bad\n", exported, "jenkins"); err == nil {
			t.Error("expected an error for malformed declared YAML")
		}
	})

	t.Run("invalid exported YAML errors", func(t *testing.T) {
		if _, err := cascInSync("a: 1", "b: [bad\n", "jenkins"); err == nil {
			t.Error("expected an error for malformed exported YAML")
		}
	})
}
