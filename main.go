package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/reachability", version).
		Capability("reachability", "Reachability analysis for vulnerability findings: symbol-level for Go, import-based elsewhere").
		ToolWithContext("analyze_reachability", "Classify VULN findings as reachable, unreachable, or undetermined", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("analyze_reachability", handleAnalyzeReachability)
}

func handleAnalyzeReachability(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	resp := sdk.NewResponse()

	workspaceRoot := req.InputString("workspace_root")
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	// Extract VULN findings from scan context.
	vulns := extractVulnFindings(req.Findings())
	if len(vulns) == 0 {
		return resp.Build(), nil
	}

	// Extract imports from workspace (if workspace is available).
	imports := NewImportSet()
	if workspaceRoot != "" {
		var err error
		imports, err = ExtractImports(workspaceRoot)
		if err != nil {
			return nil, fmt.Errorf("extracting imports: %w", err)
		}
	}

	// Go findings are answered by call-graph analysis, which loads and builds
	// the module — far more expensive than an import walk. Only pay for it
	// when a Go advisory is actually present.
	var goReach goReachability
	if hasGoVuln(vulns) {
		goReach = newGoReachability(ctx, workspaceRoot)
	}

	// Cross-reference vulns against imports.
	results := Analyze(vulns, imports, goReach)

	// Emit findings and enrichments.
	for i := range results {
		r := &results[i]
		severity, confidence := gradeFor(r)

		f := resp.Finding(r.RuleID, severity, confidence, messageFor(r)).
			WithMetadata("package", r.Vuln.Package).
			WithMetadata("ecosystem", r.Vuln.Ecosystem).
			WithMetadata("vuln_id", r.Vuln.VulnID).
			WithMetadata("reachable", reachableLabel(r.Status)).
			WithMetadata("method", r.Method).
			WithMetadata("reason", r.Reason).
			WithFingerprint(fmt.Sprintf("%s:%s:%s", r.RuleID, r.Vuln.Package, r.Vuln.VulnID))
		// Report the verdict where the dependency is declared. Without a
		// location the SARIF result has no artifactLocation and GitHub
		// rejects the entire upload, so every finding in the run is lost
		// to one that had nowhere to point.
		if r.Vuln.File != "" {
			f = f.At(r.Vuln.File, r.Vuln.Line, r.Vuln.Line)
		}
		if r.Evidence != "" {
			f = f.WithMetadata("call_path", r.Evidence)
		}
		f.Done()

		// Enrich the original VULN finding.
		if r.Vuln.Fingerprint != "" {
			reachable := reachableLabel(r.Status)

			e := resp.Enrichment(r.Vuln.Fingerprint, "reachability", fmt.Sprintf("Reachability: %s for %s", reachable, r.Vuln.Package)).
				Body(enrichmentBody(r)).
				WithMetadata("reachable", reachable).
				WithMetadata("package", r.Vuln.Package).
				WithMetadata("ecosystem", r.Vuln.Ecosystem).
				WithMetadata("method", r.Method).
				WithMetadata("reason", r.Reason).
				Source("nox/reachability")
			if r.Evidence != "" {
				e = e.WithMetadata("call_path", r.Evidence)
			}
			e.Done()
		}
	}

	return resp.Build(), nil
}

// messageFor renders the operator-facing message. The verdict alone is not
// actionable — REACH-003 in particular was previously always blamed on an
// "unsupported ecosystem", which hid the real reason — so every message
// carries the reason the analysis actually produced.
func messageFor(r *Result) string {
	switch r.Status {
	case ReachReachable:
		if r.Method == MethodSymbol {
			msg := fmt.Sprintf("Vulnerable symbol in %s (%s) IS called — confirmed reachable: %s", r.Vuln.Package, r.Vuln.VulnID, r.Reason)
			if r.Evidence != "" {
				msg += " via " + r.Evidence
			}
			return msg
		}
		return fmt.Sprintf("Vulnerable package %s (%s) IS imported — confirmed risk", r.Vuln.Package, r.Vuln.VulnID)
	case ReachUnreachable:
		if r.Method == MethodSymbol {
			return fmt.Sprintf("Vulnerable symbol in %s (%s) is never called — %s", r.Vuln.Package, r.Vuln.VulnID, r.Reason)
		}
		return fmt.Sprintf("Vulnerable package %s (%s) is NOT imported — likely false positive", r.Vuln.Package, r.Vuln.VulnID)
	default:
		return fmt.Sprintf("Cannot determine reachability for %s (%s) — %s", r.Vuln.Package, r.Vuln.VulnID, r.Reason)
	}
}

// gradeFor grades a result. Call-graph analysis carries a proof — a path from
// this module's code to the vulnerable symbol — so it is graded higher than
// the import-text heuristics, which can only observe that a name appears.
func gradeFor(r *Result) (severity pluginv1.Severity, confidence pluginv1.Confidence) {
	switch r.Status {
	case ReachReachable:
		if r.Method == MethodSymbol {
			return sdk.SeverityHigh, sdk.ConfidenceHigh
		}
		return sdk.SeverityHigh, sdk.ConfidenceMedium
	case ReachUnreachable:
		if r.Method == MethodSymbol {
			return sdk.SeverityInfo, sdk.ConfidenceHigh
		}
		return sdk.SeverityInfo, sdk.ConfidenceMedium
	default:
		return sdk.SeverityLow, sdk.ConfidenceLow
	}
}

func reachableLabel(s ReachStatus) string {
	switch s {
	case ReachReachable:
		return "true"
	case ReachUnreachable:
		return "false"
	default:
		return "undetermined"
	}
}

func enrichmentBody(r *Result) string {
	body := fmt.Sprintf("Package `%s` reachability: **%s** — %s", r.Vuln.Package, reachableLabel(r.Status), r.Reason)
	if r.Evidence != "" {
		body += fmt.Sprintf("\n\nCall path: `%s`", r.Evidence)
	}
	return body
}

// hasGoVuln reports whether any finding belongs to the Go ecosystem.
func hasGoVuln(vulns []VulnInfo) bool {
	for i := range vulns {
		if CanonicalEcosystem(vulns[i].Ecosystem) == EcosystemGo {
			return true
		}
	}
	return false
}

// extractVulnFindings filters findings to VULN-* rules and extracts metadata.
func extractVulnFindings(findings []*pluginv1.Finding) []VulnInfo {
	var vulns []VulnInfo
	for _, f := range findings {
		ruleID := f.GetRuleId()
		if len(ruleID) < 5 || ruleID[:5] != "VULN-" {
			continue
		}
		meta := f.GetMetadata()
		if meta == nil {
			continue
		}
		pkg := meta["package"]
		ecosystem := meta["ecosystem"]
		vulnID := meta["vuln_id"]
		if pkg == "" || ecosystem == "" {
			continue
		}

		loc := f.GetLocation()
		file := ""
		line := 0
		if loc != nil {
			file = loc.GetFilePath()
			line = int(loc.GetStartLine())
		}

		fingerprint := f.GetFingerprint()
		if fingerprint == "" {
			fingerprint = fmt.Sprintf("%s:%s:%d", ruleID, file, line)
		}

		vulns = append(vulns, VulnInfo{
			Fingerprint: fingerprint,
			Package:     pkg,
			Ecosystem:   ecosystem,
			VulnID:      vulnID,
			Aliases:     splitAliases(meta["aliases"]),
			File:        file,
			Line:        line,
		})
	}
	return vulns
}

// splitAliases parses the comma-separated alias list nox attaches to VULN
// findings. Aliases are what lets a GHSA- or CVE-identified finding be matched
// against a database that issues its own ids.
func splitAliases(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-reachability: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	return buildServer().Serve(ctx)
}
