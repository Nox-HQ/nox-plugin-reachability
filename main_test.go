package main

import (
	"context"
	"net"
	"strings"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunConformance(t, srv)
}

func TestTrackConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunForTrack(t, srv, registry.TrackCoreAnalysis)
}

// TestAnalyzeReachabilityGoNoWorkspace exercises the plugin protocol end to
// end for a Go advisory with no workspace to analyse. The verdict must be
// undetermined — there is nothing to build a call graph from — and the message
// must say so rather than blaming the ecosystem.
func TestAnalyzeReachabilityGoNoWorkspace(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "analyze_reachability",
		Input:    input,
		ScanContext: &pluginv1.ScanContext{
			Findings: []*pluginv1.Finding{
				{
					RuleId:      "VULN-001",
					Severity:    sdk.SeverityCritical,
					Confidence:  sdk.ConfidenceHigh,
					Message:     "CVE-2021-44228 in log4j",
					Fingerprint: "fp-vuln-001",
					Metadata: map[string]string{
						"vuln_id":   "GO-2026-5932",
						"package":   "golang.org/x/crypto",
						"version":   "1.0.0",
						"ecosystem": "go",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	if len(resp.GetFindings()) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(resp.GetFindings()))
	}

	f := resp.GetFindings()[0]
	if f.GetRuleId() != "REACH-003" {
		t.Errorf("rule_id = %q, want REACH-003", f.GetRuleId())
	}
	if f.GetMetadata()["reachable"] != "undetermined" {
		t.Errorf("reachable = %q, want undetermined", f.GetMetadata()["reachable"])
	}
	if f.GetMetadata()["method"] != MethodSymbol {
		t.Errorf("method = %q, want %q", f.GetMetadata()["method"], MethodSymbol)
	}
	if strings.Contains(f.GetMessage(), "unsupported ecosystem") {
		t.Errorf("message = %q, must not blame an unsupported ecosystem", f.GetMessage())
	}
	if !strings.Contains(f.GetMetadata()["reason"], "workspace") {
		t.Errorf("reason = %q, want it to explain that there was no workspace", f.GetMetadata()["reason"])
	}

	// Should also produce an enrichment for the original finding.
	if len(resp.GetEnrichments()) != 1 {
		t.Fatalf("expected 1 enrichment, got %d", len(resp.GetEnrichments()))
	}

	e := resp.GetEnrichments()[0]
	if e.GetFindingFingerprint() != "fp-vuln-001" {
		t.Errorf("fingerprint = %q, want fp-vuln-001", e.GetFindingFingerprint())
	}
	if e.GetKind() != "reachability" {
		t.Errorf("kind = %q, want reachability", e.GetKind())
	}
	if e.GetSource() != "nox/reachability" {
		t.Errorf("source = %q, want nox/reachability", e.GetSource())
	}
}

func TestAnalyzeReachabilityUnsupportedEcosystem(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "analyze_reachability",
		Input:    input,
		ScanContext: &pluginv1.ScanContext{
			Findings: []*pluginv1.Finding{
				{
					RuleId:      "VULN-001",
					Severity:    sdk.SeverityHigh,
					Confidence:  sdk.ConfidenceHigh,
					Message:     "CVE-2024-0001 in some-pkg",
					Fingerprint: "fp-vuln-packagist",
					Metadata: map[string]string{
						"vuln_id":   "CVE-2024-0001",
						"package":   "vendor/some-pkg",
						"version":   "0.5.0",
						"ecosystem": "Packagist",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	if len(resp.GetFindings()) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(resp.GetFindings()))
	}

	f := resp.GetFindings()[0]
	if f.GetRuleId() != "REACH-003" {
		t.Errorf("rule_id = %q, want REACH-003", f.GetRuleId())
	}
	if f.GetMetadata()["reachable"] != "undetermined" {
		t.Errorf("reachable = %q, want undetermined", f.GetMetadata()["reachable"])
	}
}

func TestAnalyzeReachabilityNoVulnFindings(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "analyze_reachability",
		Input:    input,
		ScanContext: &pluginv1.ScanContext{
			Findings: []*pluginv1.Finding{
				{
					RuleId:     "SEC-001",
					Severity:   sdk.SeverityHigh,
					Confidence: sdk.ConfidenceHigh,
					Message:    "Hardcoded secret",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected 0 findings for non-VULN input, got %d", len(resp.GetFindings()))
	}
	if len(resp.GetEnrichments()) != 0 {
		t.Errorf("expected 0 enrichments, got %d", len(resp.GetEnrichments()))
	}
}

func TestAnalyzeReachabilityMultipleFindings(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "analyze_reachability",
		Input:    input,
		ScanContext: &pluginv1.ScanContext{
			Findings: []*pluginv1.Finding{
				{
					RuleId:      "VULN-001",
					Severity:    sdk.SeverityCritical,
					Confidence:  sdk.ConfidenceHigh,
					Message:     "CVE-1 in pkg-a",
					Fingerprint: "fp-1",
					Metadata: map[string]string{
						"vuln_id": "CVE-1", "package": "pkg-a",
						"version": "1.0", "ecosystem": "cargo",
					},
				},
				{
					RuleId:      "VULN-002",
					Severity:    sdk.SeverityMedium,
					Confidence:  sdk.ConfidenceMedium,
					Message:     "typosquat in pkg-b",
					Fingerprint: "fp-2",
					Metadata: map[string]string{
						"vuln_id": "TYPO-1", "package": "pkg-b",
						"version": "1.0", "ecosystem": "npm",
					},
				},
				{
					RuleId:      "VULN-003",
					Severity:    sdk.SeverityHigh,
					Confidence:  sdk.ConfidenceHigh,
					Message:     "malicious pkg-c",
					Fingerprint: "fp-3",
					Metadata: map[string]string{
						"vuln_id": "MAL-1", "package": "pkg-c",
						"version": "1.0", "ecosystem": "rubygems",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	// Should produce 3 findings: REACH-001 (cargo, not imported), REACH-001 (npm, not imported), REACH-001 (rubygems, not imported).
	if len(resp.GetFindings()) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(resp.GetFindings()))
	}

	// Verify all have enrichments.
	if len(resp.GetEnrichments()) != 3 {
		t.Fatalf("expected 3 enrichments, got %d", len(resp.GetEnrichments()))
	}
}

func TestAnalyzeReachabilityEmptyContext(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "analyze_reachability",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected 0 findings with no context, got %d", len(resp.GetFindings()))
	}
}

// --- Domain logic unit tests ---

func TestAnalyzeFunction(t *testing.T) {
	imports := NewImportSet()
	imports.Add(EcosystemPyPI, "flask")
	imports.Add(EcosystemNPM, "express")

	vulns := []VulnInfo{
		{Fingerprint: "fp1", Package: "github.com/vuln/pkg", Ecosystem: "go", VulnID: "GO-1000-1"},
		{Fingerprint: "fp2", Package: "requests", Ecosystem: "pypi", VulnID: "CVE-2"},
		{Fingerprint: "fp3", Package: "express", Ecosystem: "npm", VulnID: "CVE-3"},
		{Fingerprint: "fp4", Package: "some-pkg", Ecosystem: "Packagist", VulnID: "CVE-4"},
	}

	// Go is answered by the call-graph resolver, never by the import set.
	goReach := stubGoReachability{status: ReachReachable, reason: "stub", evidence: "a → b"}

	results := Analyze(vulns, imports, goReach)

	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}

	// Go verdicts come from the symbol resolver.
	if results[0].RuleID != "REACH-002" {
		t.Errorf("results[0].RuleID = %q, want REACH-002", results[0].RuleID)
	}
	if results[0].Method != MethodSymbol {
		t.Errorf("results[0].Method = %q, want %q", results[0].Method, MethodSymbol)
	}
	if results[0].Evidence != "a → b" {
		t.Errorf("results[0].Evidence = %q, want the resolver's call path", results[0].Evidence)
	}

	// PyPI package "requests" not imported → REACH-001.
	if results[1].RuleID != "REACH-001" {
		t.Errorf("results[1].RuleID = %q, want REACH-001", results[1].RuleID)
	}

	// npm "express" is imported → REACH-002.
	if results[2].RuleID != "REACH-002" {
		t.Errorf("results[2].RuleID = %q, want REACH-002", results[2].RuleID)
	}

	// Packagist (PHP) unsupported → REACH-003.
	if results[3].RuleID != "REACH-003" {
		t.Errorf("results[3].RuleID = %q, want REACH-003", results[3].RuleID)
	}
	if !strings.Contains(results[3].Reason, "unsupported ecosystem") {
		t.Errorf("results[3].Reason = %q, want it to name the unsupported ecosystem", results[3].Reason)
	}
}

// TestAnalyzeGoWithoutResolver pins the safety property: with no Go analysis
// available, a Go advisory must never be graded on import text. Before this
// was true, the ecosystem label mismatch made every Go finding REACH-003 with
// a message blaming an "unsupported ecosystem"; the verdict is still
// undetermined here, but the reason must be the real one.
func TestAnalyzeGoWithoutResolver(t *testing.T) {
	vulns := []VulnInfo{
		{Fingerprint: "fp", Package: "golang.org/x/crypto", Ecosystem: "go", VulnID: "GO-2026-5932"},
	}

	results := Analyze(vulns, NewImportSet(), nil)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].RuleID != "REACH-003" {
		t.Errorf("RuleID = %q, want REACH-003", results[0].RuleID)
	}
	if strings.Contains(results[0].Reason, "unsupported ecosystem") {
		t.Errorf("Reason = %q, must not blame an unsupported ecosystem", results[0].Reason)
	}
}

// TestCanonicalEcosystem covers the label mismatch that made Go support
// unreachable: nox tags findings with its internal lowercase names, this
// plugin indexes on OSV's names, and only npm happened to spell them alike.
func TestCanonicalEcosystem(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"go", EcosystemGo},
		{"Go", EcosystemGo},
		{"golang", EcosystemGo},
		{"pypi", EcosystemPyPI},
		{"PyPI", EcosystemPyPI},
		{"npm", EcosystemNPM},
		{"cargo", EcosystemCargo},
		{"crates.io", EcosystemCargo},
		{"maven", EcosystemMaven},
		{"gradle", EcosystemMaven},
		{"rubygems", EcosystemRubyGems},
		{"nuget", EcosystemNuGet},
		{"Packagist", "Packagist"}, // unknown labels pass through verbatim
	}

	for _, tt := range tests {
		if got := CanonicalEcosystem(tt.in); got != tt.want {
			t.Errorf("CanonicalEcosystem(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// stubGoReachability stands in for the call-graph analysis in tests that are
// about the dispatch, not about the analysis itself.
type stubGoReachability struct {
	status   ReachStatus
	reason   string
	evidence string
}

func (s stubGoReachability) Verdict(*VulnInfo) goVerdict {
	return goVerdict{Status: s.status, Reason: s.reason, Evidence: s.evidence}
}

func TestNormalizePackageName(t *testing.T) {
	tests := []struct {
		pkg  string
		eco  string
		want string
	}{
		{"github.com/foo/bar", "Go", "github.com/foo/bar"},
		{"Pillow", "PyPI", "PIL"},
		{"scikit-learn", "PyPI", "sklearn"},
		{"flask", "PyPI", "flask"},
		{"my-pkg", "PyPI", "my_pkg"},
		{"express", "npm", "express"},
		{"@scope/pkg", "npm", "@scope/pkg"},
	}

	for _, tt := range tests {
		got := normalizePackageName(tt.pkg, tt.eco)
		if got != tt.want {
			t.Errorf("normalizePackageName(%q, %q) = %q, want %q", tt.pkg, tt.eco, got, tt.want)
		}
	}
}

func TestExtractVulnFindings(t *testing.T) {
	findings := []*pluginv1.Finding{
		{
			RuleId:      "VULN-001",
			Fingerprint: "fp1",
			Metadata: map[string]string{
				"package": "pkg-a", "ecosystem": "go", "vuln_id": "CVE-1",
				"aliases": "GHSA-aaaa-bbbb-cccc, GO-2026-0001",
			},
		},
		{
			RuleId: "SEC-001",
			Metadata: map[string]string{
				"type": "secret",
			},
		},
		{
			RuleId:      "VULN-002",
			Fingerprint: "fp2",
			Metadata: map[string]string{
				"package": "pkg-b", "ecosystem": "npm", "vuln_id": "CVE-2",
			},
		},
		{
			RuleId: "VULN-003",
			// Missing metadata.
		},
	}

	vulns := extractVulnFindings(findings)
	if len(vulns) != 2 {
		t.Fatalf("expected 2 vulns, got %d", len(vulns))
	}
	if vulns[0].Package != "pkg-a" {
		t.Errorf("vulns[0].Package = %q, want pkg-a", vulns[0].Package)
	}
	if vulns[1].Package != "pkg-b" {
		t.Errorf("vulns[1].Package = %q, want pkg-b", vulns[1].Package)
	}
}

// --- helpers ---

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	const bufSize = 1024 * 1024

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}
