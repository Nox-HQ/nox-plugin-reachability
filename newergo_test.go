package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// goStderr17 is the diagnostic, verbatim from a real run, when a plugin built with Go
// 1.26 loads a module written for Go 1.27.
const goStderr17 = `There are errors with the provided package patterns:

/tmp/m/main.go:3:1: package requires newer Go version go1.27 (application built with go1.26)
-: This application uses version go1.26 of the source-processing packages but runs version go1.27 of 'go list'.`

func TestNewerGoReason(t *testing.T) {
	tests := []struct {
		name   string
		stderr string
		want   []string // substrings; nil means not recognised
	}{
		{"plugin older than module", goStderr17, []string{"needs go1.27", "built with go1.26", "update the plugin"}},
		{"unrelated build error", "main.go:3:1: undefined: foo", nil},
		{"empty", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := newerGoReason(".", tt.stderr)
			if ok != (tt.want != nil) {
				t.Fatalf("recognised = %v, want %v (reason %q)", ok, tt.want != nil, got)
			}
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("reason %q does not contain %q", got, w)
				}
			}
		})
	}
}

// TestGoReachabilityGoOnPath runs the real analysis on a module whose go
// directive names the Go on PATH. Either the plugin can load it (built with
// that Go or newer) and the verdict is the fixture's reachable one, or it
// cannot and the reason must say so — never a generic undetermined verdict.
// Released plugin binaries always lag the newest Go, so the second case is
// the normal one on an up-to-date machine.
func TestGoReachabilityGoOnPath(t *testing.T) {
	out, err := exec.Command("go", "env", "GOVERSION").Output()
	if err != nil {
		t.Skipf("no go on PATH: %v", err)
	}
	pathGo := strings.TrimPrefix(strings.TrimSpace(string(out)), "go")

	dir := t.TempDir()
	src := testdataPath(t, "gomod-called")
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if e.Name() == "go.mod" {
			b = []byte(strings.Replace(string(b), "go 1.21", "go "+pathGo, 1))
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	a := goAnalyzer{root: dir, db: "file://" + testdataPath(t, "vulndb"), env: offlineEnv(t)}
	got := a.analyze(context.Background()).Verdict(&VulnInfo{Package: "stdlib", Ecosystem: "go", VulnID: fixtureVulnID})
	if got.Status == ReachReachable {
		return
	}
	t.Logf("plugin cannot load a go %s module: %s", pathGo, got.Reason)
	if !strings.Contains(got.Reason, "update the plugin") {
		t.Fatalf("go %s module: Status = %v with a generic reason; want reachable or the update-the-plugin reason: %s", pathGo, got.Status, got.Reason)
	}
}
