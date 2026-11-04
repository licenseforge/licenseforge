// Package compliance checks the compliance documents (ADR-0024): the OSCAL
// component definition against the vendored OSCAL 1.2.3 schema, and that the
// evidence it and the Markdown documents cite still exists in the repository.
// It is its own Go module, so the schema validator never becomes a dependency
// of the server.
package compliance

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	definition = "oscal/component-definition.json"
	schemaFile = "oscal/schema/oscal_component_schema.json"
	schemaID   = "http://csrc.nist.gov/ns/oscal/1.2.3/oscal-component-definition-schema.json"
	repoURL    = "https://github.com/licenseforge/licenseforge/blob/main/"
	statusNS   = "https://licenseforge.io/ns/oscal"
	root       = ".." // the repository, from this module
)

func compile(t *testing.T) *jsonschema.Schema {
	t.Helper()
	f, err := os.Open(schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat() // uri, date-time, email: the schema's formats are part of OSCAL
	if err := c.AddResource(schemaID, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(schemaID)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func load(t *testing.T, raw []byte) any {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestComponentDefinitionMatchesSchema(t *testing.T) {
	raw, err := os.ReadFile(definition)
	if err != nil {
		t.Fatal(err)
	}
	s := compile(t)
	if err := s.Validate(load(t, raw)); err != nil {
		t.Fatalf("%s: %v", definition, err)
	}
	// The validator really validates: documents the schema forbids fail.
	for name, bad := range map[string]func(map[string]any){
		"no metadata":   func(cd map[string]any) { delete(cd, "metadata") },
		"bad uuid":      func(cd map[string]any) { cd["uuid"] = "not-a-uuid" },
		"unknown field": func(cd map[string]any) { cd["statement"] = "x" },
		"bad date":      func(cd map[string]any) { cd["metadata"].(map[string]any)["last-modified"] = "2026-11-04" },
	} {
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		bad(doc["component-definition"].(map[string]any))
		b, _ := json.Marshal(doc)
		if s.Validate(load(t, b)) == nil {
			t.Errorf("%s: validated", name)
		}
	}
}

type requirement struct {
	UUID      string `json:"uuid"`
	ControlID string `json:"control-id"`
	Props     []struct{ Name, NS, Value string }
	Links     []struct{ Href, Text string }
}

func requirements(t *testing.T) []requirement {
	t.Helper()
	raw, err := os.ReadFile(definition)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		CD struct {
			Components []struct {
				CI []struct {
					Reqs []requirement `json:"implemented-requirements"`
				} `json:"control-implementations"`
			} `json:"components"`
		} `json:"component-definition"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var out []requirement
	for _, c := range doc.CD.Components {
		for _, ci := range c.CI {
			out = append(out, ci.Reqs...)
		}
	}
	if len(out) == 0 {
		t.Fatal("no implemented requirements")
	}
	return out
}

func status(r requirement) string {
	for _, p := range r.Props {
		if p.Name == "implementation-status" && p.NS == statusNS {
			return p.Value
		}
	}
	return ""
}

// Every repository file the definition cites exists, and every test it names
// is defined in that file, so evidence can't silently go stale.
func TestEvidenceExists(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range requirements(t) {
		if seen[r.ControlID] {
			t.Errorf("%s listed twice", r.ControlID)
		}
		seen[r.ControlID] = true
		switch status(r) {
		case "implemented", "partial", "planned", "inherited":
		default:
			t.Errorf("%s: implementation-status %q", r.ControlID, status(r))
		}
		if s := status(r); (s == "implemented" || s == "partial") && len(r.Links) == 0 {
			t.Errorf("%s is %s without evidence", r.ControlID, s)
		}
		for _, l := range r.Links {
			path, ok := strings.CutPrefix(l.Href, repoURL)
			if !ok {
				continue // external evidence (repository settings)
			}
			body, err := os.ReadFile(filepath.Join(root, path))
			if err != nil {
				t.Errorf("%s: %v", r.ControlID, err)
				continue
			}
			if strings.HasPrefix(l.Text, "Test") && !bytes.Contains(body, []byte("func "+l.Text+"(")) {
				t.Errorf("%s: %s has no %s", r.ControlID, path, l.Text)
			}
		}
	}
}

// The matrix's statuses match the OSCAL ones, control by control.
func TestMatrixMatchesDefinition(t *testing.T) {
	raw, err := os.ReadFile("nist-800-53-matrix.md")
	if err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile(`(?m)^\| \*\*([A-Z]{2}-\d+)(?:\((\d+)\))?\*\*[^|]*\| (\w+) \|`)
	matrix := map[string]string{}
	for _, m := range row.FindAllStringSubmatch(string(raw), -1) {
		id := strings.ToLower(m[1])
		if m[2] != "" {
			id += "." + m[2]
		}
		matrix[id] = m[3]
	}
	reqs := requirements(t)
	if len(matrix) != len(reqs) {
		t.Errorf("matrix has %d controls, definition %d", len(matrix), len(reqs))
	}
	for _, r := range reqs {
		if got := matrix[r.ControlID]; got != status(r) {
			t.Errorf("%s: matrix says %q, definition %q", r.ControlID, got, status(r))
		}
	}
}

// Relative links in the compliance documents point at files that exist.
func TestMarkdownLinksExist(t *testing.T) {
	docs, err := filepath.Glob("*.md")
	if err != nil {
		t.Fatal(err)
	}
	docs = append(docs, filepath.Join(root, "SECURITY.md"))
	link := regexp.MustCompile(`\]\(([^)#\s]+)(?:#[^)]*)?\)`)
	n := 0
	for _, d := range docs {
		body, err := os.ReadFile(d)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range link.FindAllStringSubmatch(string(body), -1) {
			if strings.Contains(m[1], "://") || strings.HasPrefix(m[1], "mailto:") {
				continue
			}
			n++
			if _, err := os.Stat(filepath.Join(filepath.Dir(d), m[1])); err != nil {
				t.Errorf("%s: broken link %s", d, m[1])
			}
		}
	}
	if n == 0 {
		t.Error("no relative links checked")
	}
}
