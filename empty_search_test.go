package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The three arms that exposed the defect, run over the same advisory.
//
// Arms 1 and 3 were previously indistinguishable in the output — both reported
// `reachable: false`, "NOT imported — likely false positive" — but only arm 3
// had actually searched anything. Arm 1 had no source to search at all, which
// is the ordinary shape of a dependency scan: a CI job that checks out a
// manifest, a repo whose source lives elsewhere, a container's dependency list.
func TestNoRefutationWithoutASearch(t *testing.T) {
	vuln := VulnInfo{Package: "browserslist", Ecosystem: "npm", VulnID: "GHSA-73wf-gq98-2v4g"}

	tests := []struct {
		name       string
		files      map[string]string
		wantStatus ReachStatus
	}{
		{
			name:       "no source at all: nothing was searched, so nothing is refuted",
			files:      map[string]string{"package-lock.json": `{"name":"x"}`},
			wantStatus: ReachUndetermined,
		},
		{
			name: "source imports the package: reachable",
			files: map[string]string{
				"package-lock.json": `{"name":"x"}`,
				"index.js":          `const b = require('browserslist');`,
			},
			wantStatus: ReachReachable,
		},
		{
			name: "source searched, package absent: a real refutation",
			files: map[string]string{
				"package-lock.json": `{"name":"x"}`,
				"index.js":          `const q = require('some-other-package');`,
			},
			wantStatus: ReachUnreachable,
		},
		{
			name: "source with no imports at all still counts as searched",
			files: map[string]string{
				"package-lock.json": `{"name":"x"}`,
				"index.js":          `module.exports = 1;`,
			},
			wantStatus: ReachUnreachable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			imports, err := ExtractImports(dir)
			if err != nil {
				t.Fatalf("ExtractImports: %v", err)
			}
			got := importResult(&vuln, imports)

			if got.Status != tc.wantStatus {
				t.Errorf("Status = %v, want %v (reason: %s)", got.Status, tc.wantStatus, got.Reason)
			}
		})
	}
}

// The claim a reader acts on is the message, so it is asserted directly: a
// completed search that found nothing must not be sold as a false positive,
// because an import scan cannot see a package reached through a dependency.
func TestUnreachableMessageDoesNotOverstate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(`const q = require('elsewhere');`), 0o600); err != nil {
		t.Fatal(err)
	}
	imports, err := ExtractImports(dir)
	if err != nil {
		t.Fatal(err)
	}

	r := importResult(&VulnInfo{Package: "browserslist", Ecosystem: "npm", VulnID: "GHSA-x"}, imports)
	if r.Status != ReachUnreachable {
		t.Fatalf("Status = %v, want ReachUnreachable — the fixture no longer exercises the message", r.Status)
	}

	msg := messageFor(&r)
	if strings.Contains(msg, "false positive") {
		t.Errorf("message calls a completed import scan a false positive: %q", msg)
	}
	if !strings.Contains(msg, "through a dependency") {
		t.Errorf("message does not say what the scan could not see: %q", msg)
	}
}
