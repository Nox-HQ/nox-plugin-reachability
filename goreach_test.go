package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The Go tests run the real x/vuln analysis against fixture modules in
// testdata, pointed at a fixture vulnerability database on disk. Nothing here
// touches the network: GOPROXY is off, GOTOOLCHAIN is local, the fixture
// modules have no requirements, and the advisory is scoped to the standard
// library so no dependency needs downloading.
//
// The fixture advisory GO-9999-0001 names net/url.PathEscape. That symbol is
// called by testdata/gomod-called and deliberately not called by
// testdata/gomod-notcalled, which imports net/url and calls QueryEscape
// instead — the case that carries the value of reachability analysis.

const fixtureVulnID = "GO-9999-0001"

func testdataPath(t *testing.T, rel string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("testdata", rel))
	if err != nil {
		t.Fatalf("resolving testdata/%s: %v", rel, err)
	}
	return abs
}

// offlineEnv is the environment fixture scans run under. Proving the analysis
// is offline matters: a test that silently reaches vuln.go.dev would pass on a
// developer's machine and fail in a sandboxed CI runner.
func offlineEnv(t *testing.T) []string {
	t.Helper()
	return append(os.Environ(),
		"GOPROXY=off",
		"GOFLAGS=-mod=mod",
		"GOTOOLCHAIN=local",
		"GONOSUMCHECK=1",
		"GOWORK=off",
	)
}

// fixtureScans memoises the analysis per module directory. Loading packages
// and building a call graph costs seconds; the tests assert on different
// aspects of the same scan.
var (
	fixtureScanOnce sync.Map // dir -> *sync.Once
	fixtureScans    sync.Map // dir -> goReachability
)

func fixtureScan(t *testing.T, dir string) goReachability {
	t.Helper()

	onceAny, _ := fixtureScanOnce.LoadOrStore(dir, &sync.Once{})
	onceAny.(*sync.Once).Do(func() {
		a := goAnalyzer{
			root: dir,
			db:   "file://" + testdataPath(t, "vulndb"),
			env:  offlineEnv(t),
		}
		fixtureScans.Store(dir, a.analyze(context.Background()))
	})

	scan, _ := fixtureScans.Load(dir)
	return scan.(goReachability)
}

// TestGoReachabilitySymbolCalled: the vulnerable symbol is called, so the
// advisory is genuinely reachable and must carry the call path as proof.
func TestGoReachabilitySymbolCalled(t *testing.T) {
	scan := fixtureScan(t, testdataPath(t, "gomod-called"))

	v := VulnInfo{Package: "stdlib", Ecosystem: "go", VulnID: fixtureVulnID}
	got := scan.Verdict(&v)

	if got.Status != ReachReachable {
		t.Fatalf("Status = %v, want ReachReachable (reason: %s)", got.Status, got.Reason)
	}
	if !strings.Contains(got.Evidence, "net/url.PathEscape") {
		t.Errorf("Evidence = %q, want the call path to name net/url.PathEscape", got.Evidence)
	}
	if !strings.Contains(got.Evidence, "main") {
		t.Errorf("Evidence = %q, want the call path to reach the module's own entry point", got.Evidence)
	}
}

// TestGoReachabilityImportedNotCalled is the case reachability analysis exists
// for: the vulnerable package is imported, so any module- or import-level
// check would call it reachable, but no vulnerable symbol is ever called.
func TestGoReachabilityImportedNotCalled(t *testing.T) {
	scan := fixtureScan(t, testdataPath(t, "gomod-notcalled"))

	v := VulnInfo{Package: "stdlib", Ecosystem: "go", VulnID: fixtureVulnID}
	got := scan.Verdict(&v)

	if got.Status != ReachUnreachable {
		t.Fatalf("Status = %v, want ReachUnreachable (reason: %s)", got.Status, got.Reason)
	}
	if got.Evidence != "" {
		t.Errorf("Evidence = %q, want empty: there is no call path to prove", got.Evidence)
	}
	if !strings.Contains(got.Reason, "none of its vulnerable symbols are called") {
		t.Errorf("Reason = %q, want it to state that no vulnerable symbol is called", got.Reason)
	}
	if !strings.Contains(got.Reason, "imported") {
		t.Errorf("Reason = %q, want it to state the package is imported", got.Reason)
	}
}

// TestGoReachabilityAliasMapping: findings arrive identified by GHSA or CVE
// while the Go database issues GO ids. An advisory the scan knows under an
// alias must still resolve.
func TestGoReachabilityAliasMapping(t *testing.T) {
	scan := fixtureScan(t, testdataPath(t, "gomod-called"))

	for _, alias := range []string{"GHSA-9999-pesc-ape0", "CVE-9999-0001"} {
		t.Run(alias, func(t *testing.T) {
			// The primary id is a GHSA the Go database does not issue; the GO
			// id is only reachable through the alias list on the finding.
			v := VulnInfo{Package: "stdlib", Ecosystem: "go", VulnID: alias}
			if got := scan.Verdict(&v); got.Status != ReachReachable {
				t.Errorf("Status = %v, want ReachReachable (reason: %s)", got.Status, got.Reason)
			}

			v = VulnInfo{Package: "stdlib", Ecosystem: "go", VulnID: "CVE-2020-99999", Aliases: []string{alias}}
			if got := scan.Verdict(&v); got.Status != ReachReachable {
				t.Errorf("via Aliases: Status = %v, want ReachReachable (reason: %s)", got.Status, got.Reason)
			}
		})
	}
}

// TestGoReachabilityUnmappableID: an advisory the Go database does not carry
// says nothing about whether the code runs, so it must be undetermined rather
// than guessed either way.
func TestGoReachabilityUnmappableID(t *testing.T) {
	scan := fixtureScan(t, testdataPath(t, "gomod-called"))

	v := VulnInfo{Package: "example.com/unknown", Ecosystem: "go", VulnID: "GHSA-zzzz-zzzz-zzzz"}
	got := scan.Verdict(&v)

	if got.Status != ReachUndetermined {
		t.Fatalf("Status = %v, want ReachUndetermined (reason: %s)", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "GHSA-zzzz-zzzz-zzzz") {
		t.Errorf("Reason = %q, want it to name the id that could not be mapped", got.Reason)
	}
	if strings.Contains(got.Reason, "unsupported ecosystem") {
		t.Errorf("Reason = %q, must not blame an unsupported ecosystem", got.Reason)
	}
}

// TestGoReachabilityNotAGoModule: a target with no go.mod cannot be analysed,
// and the reason must say that rather than claiming the ecosystem is
// unsupported.
func TestGoReachabilityNotAGoModule(t *testing.T) {
	scan := fixtureScan(t, testdataPath(t, "not-a-gomod"))

	v := VulnInfo{Package: "golang.org/x/crypto", Ecosystem: "go", VulnID: "GO-2026-5932"}
	got := scan.Verdict(&v)

	if got.Status != ReachUndetermined {
		t.Fatalf("Status = %v, want ReachUndetermined", got.Status)
	}
	if !strings.Contains(got.Reason, "go.mod") {
		t.Errorf("Reason = %q, want it to explain that there is no go.mod", got.Reason)
	}
	if strings.Contains(got.Reason, "unsupported ecosystem") {
		t.Errorf("Reason = %q, must not blame an unsupported ecosystem", got.Reason)
	}
}

// TestGoReachabilityEndToEnd drives the same fixtures through Analyze, so the
// rule ids and messages an operator sees are covered, not just the verdicts.
func TestGoReachabilityEndToEnd(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantRule   string
		wantInMsg  string
		wantMethod string
	}{
		{"called", "gomod-called", "REACH-002", "IS called", MethodSymbol},
		{"not called", "gomod-notcalled", "REACH-001", "is never called", MethodSymbol},
		{"not a module", "not-a-gomod", "REACH-003", "go.mod", MethodSymbol},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scan := fixtureScan(t, testdataPath(t, tt.dir))
			vulns := []VulnInfo{{
				Fingerprint: "fp",
				Package:     "stdlib",
				Ecosystem:   "go",
				VulnID:      fixtureVulnID,
			}}

			results := Analyze(vulns, NewImportSet(), scan)
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			r := &results[0]

			if r.RuleID != tt.wantRule {
				t.Errorf("RuleID = %q, want %q (reason: %s)", r.RuleID, tt.wantRule, r.Reason)
			}
			if r.Method != tt.wantMethod {
				t.Errorf("Method = %q, want %q", r.Method, tt.wantMethod)
			}
			if msg := messageFor(r); !strings.Contains(msg, tt.wantInMsg) {
				t.Errorf("message = %q, want it to contain %q", msg, tt.wantInMsg)
			}
			if msg := messageFor(r); strings.Contains(msg, "unsupported ecosystem") {
				t.Errorf("message = %q, must not blame an unsupported ecosystem", msg)
			}
		})
	}
}

// --- unit tests over the stream parsing and module discovery ---------------

func TestParseGoScanStreamLevels(t *testing.T) {
	stream := `
{"config":{"protocol_version":"v1.0.0","scan_level":"symbol","scan_mode":"source"}}
{"osv":{"id":"GO-1000-0001","aliases":["CVE-1000-1","GHSA-abcd-efgh-ijkl"]}}
{"finding":{"osv":"GO-1000-0001","trace":[{"module":"example.com/dep"}]}}
{"finding":{"osv":"GO-1000-0001","trace":[{"module":"example.com/dep","package":"example.com/dep/vulnpkg"}]}}
{"finding":{"osv":"GO-1000-0001","trace":[{"module":"example.com/dep","package":"example.com/dep/vulnpkg","function":"Boom","receiver":"T"},{"module":"example.com/app","package":"example.com/app","function":"main"}]}}
`
	got := newGoScanResult()
	if err := parseGoScanStream(strings.NewReader(stream), got); err != nil {
		t.Fatalf("parseGoScanStream: %v", err)
	}

	// The strongest evidence must win regardless of the order findings arrive.
	if got.evidence["GO-1000-0001"] != goEvidenceSymbol {
		t.Errorf("evidence = %v, want goEvidenceSymbol", got.evidence["GO-1000-0001"])
	}
	wantPath := "example.com/app.main → example.com/dep/vulnpkg.T.Boom"
	if got.callPath["GO-1000-0001"] != wantPath {
		t.Errorf("callPath = %q, want %q", got.callPath["GO-1000-0001"], wantPath)
	}
	if got.aliases["GHSA-ABCD-EFGH-IJKL"] != "GO-1000-0001" {
		t.Errorf("alias index = %v, want GHSA to map to the GO id", got.aliases)
	}
}

// TestParseGoScanStreamRejectsWeakScan: findings from a module- or
// package-level scan cannot distinguish imported from called. Accepting them
// would turn "we did not look" into REACH-001.
func TestParseGoScanStreamRejectsWeakScan(t *testing.T) {
	stream := `{"config":{"protocol_version":"v1.0.0","scan_level":"module"}}`

	err := parseGoScanStream(strings.NewReader(stream), newGoScanResult())
	if err == nil {
		t.Fatal("expected an error for a module-level scan")
	}
	if !strings.Contains(err.Error(), "module") {
		t.Errorf("error = %v, want it to name the scan level", err)
	}
}

// TestParseGoScanStreamRejectsTruncated: a truncated stream under-reports
// findings, which would silently downgrade a reachable advisory.
func TestParseGoScanStreamRejectsTruncated(t *testing.T) {
	err := parseGoScanStream(strings.NewReader(""), newGoScanResult())
	if err == nil {
		t.Fatal("expected an error for a stream with no config message")
	}
}

func TestGoScanResultVerdictNoFinding(t *testing.T) {
	// The database knows the advisory and matched it to a module in the build,
	// but the analysis produced no finding at all.
	s := newGoScanResult()
	s.known["GO-1000-0002"] = true
	s.modules = []string{"."}

	v := VulnInfo{VulnID: "GO-1000-0002"}
	got := s.Verdict(&v)
	if got.Status != ReachUnreachable {
		t.Errorf("Status = %v, want ReachUnreachable (reason: %s)", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "GO-1000-0002") {
		t.Errorf("Reason = %q, want it to name the advisory", got.Reason)
	}
}

func TestGoModuleDirs(t *testing.T) {
	t.Run("root is a module", func(t *testing.T) {
		dir := testdataPath(t, "gomod-called")
		got, err := goModuleDirs(dir)
		if err != nil {
			t.Fatalf("goModuleDirs: %v", err)
		}
		if len(got) != 1 || got[0] != dir {
			t.Errorf("got %v, want [%s]", got, dir)
		}
	})

	t.Run("nested modules", func(t *testing.T) {
		root := t.TempDir()
		for _, sub := range []string{"a", "b/c"} {
			d := filepath.Join(root, sub)
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(d, "go.mod"), []byte("module example.com/"+sub+"\n\ngo 1.21\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}

		got, err := goModuleDirs(root)
		if err != nil {
			t.Fatalf("goModuleDirs: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %v, want both nested module roots", got)
		}
	})

	t.Run("no module", func(t *testing.T) {
		_, err := goModuleDirs(testdataPath(t, "not-a-gomod"))
		if err == nil {
			t.Fatal("expected an error when there is no go.mod")
		}
		if !strings.Contains(err.Error(), "go.mod") {
			t.Errorf("error = %v, want it to mention go.mod", err)
		}
	})

	t.Run("too many modules", func(t *testing.T) {
		root := t.TempDir()
		for i := 0; i <= goMaxModules; i++ {
			d := filepath.Join(root, string(rune('a'+i)))
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(d, "go.mod"), []byte("module example.com/m\n\ngo 1.21\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}

		// Analysing only some of them could miss the module that calls the
		// vulnerable symbol, so the whole answer must be withheld.
		if _, err := goModuleDirs(root); err == nil {
			t.Fatal("expected an error when the workspace exceeds the module cap")
		}
	})
}

func TestGoAnalyzerNoRoot(t *testing.T) {
	got := goAnalyzer{}.analyze(context.Background())

	vuln := VulnInfo{VulnID: "GO-2026-5932"}
	v := got.Verdict(&vuln)
	if v.Status != ReachUndetermined {
		t.Errorf("Status = %v, want ReachUndetermined", v.Status)
	}
	if !strings.Contains(v.Reason, "workspace") {
		t.Errorf("Reason = %q, want it to explain the missing workspace root", v.Reason)
	}
}

// TestGoAnalyzerTimeout: an analysis that cannot finish in its budget must
// degrade to undetermined, not stall the scan or invent a verdict.
func TestGoAnalyzerTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // an already-cancelled context is the cheapest overrun to simulate

	a := goAnalyzer{
		root: testdataPath(t, "gomod-called"),
		db:   "file://" + testdataPath(t, "vulndb"),
		env:  offlineEnv(t),
	}
	got := a.analyze(ctx)

	vuln := VulnInfo{VulnID: fixtureVulnID}
	v := got.Verdict(&vuln)
	if v.Status != ReachUndetermined {
		t.Errorf("Status = %v, want ReachUndetermined (reason: %s)", v.Status, v.Reason)
	}
}
