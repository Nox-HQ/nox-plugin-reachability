package main

import "strings"

// VulnInfo holds the relevant fields from a VULN finding.
type VulnInfo struct {
	Fingerprint string
	Package     string
	Ecosystem   string
	VulnID      string
	// Aliases holds the other identifiers the advisory is known by (GHSA,
	// CVE, …). Ecosystem-native analysers speak their own id namespace — the
	// Go vulnerability database speaks GO ids — so the aliases are what makes
	// a GHSA-identified finding resolvable at all.
	Aliases []string
	// File and Line locate the advisory in the source tree — the manifest
	// that declares the dependency, which is where nox puts the VULN
	// finding this one annotates. A reachability verdict has no line of
	// its own, but a finding without any location is not merely
	// unhelpful: nox renders it into SARIF with no artifactLocation, and
	// GitHub rejects the whole submission, taking every other finding in
	// the file with it. So the verdict is reported where the dependency
	// is declared.
	File string
	Line int
}

// ReachStatus classifies the reachability of a vulnerable package.
type ReachStatus int

const (
	ReachUnreachable  ReachStatus = iota // Not reachable from this workspace
	ReachReachable                       // Reachable from this workspace
	ReachUndetermined                    // No verdict could be established
)

// Analysis methods, recorded on each Result so a consumer can tell a
// call-graph verdict from an import-text one.
const (
	// MethodSymbol is call-graph analysis: the verdict is about whether the
	// vulnerable *symbol* is called.
	MethodSymbol = "symbol"
	// MethodImport is import-statement scanning: the verdict is about whether
	// the vulnerable *package* is named in the workspace's source.
	MethodImport = "import"
)

// Result holds the reachability analysis outcome for a single VULN finding.
type Result struct {
	Vuln   VulnInfo
	Status ReachStatus
	RuleID string
	// Method records how the verdict was reached.
	Method string
	// Reason explains the verdict in operator-facing prose. For REACH-003 it
	// says why no verdict could be established — "unsupported ecosystem" is
	// only ever one of the possible answers.
	Reason string
	// Evidence carries proof for a reachable verdict, such as the call path
	// from this module's code to the vulnerable symbol. Empty otherwise.
	Evidence string
}

// Canonical ecosystem names. These are OSV's spellings, which is what the
// import extractors index on.
const (
	EcosystemGo       = "Go"
	EcosystemPyPI     = "PyPI"
	EcosystemNPM      = "npm"
	EcosystemCargo    = "crates.io"
	EcosystemMaven    = "Maven"
	EcosystemRubyGems = "RubyGems"
	EcosystemNuGet    = "NuGet"
)

// ecosystemAliases maps the ecosystem labels that actually arrive on VULN
// findings onto the canonical names above.
//
// This mapping is not cosmetic. nox's dependency analyser tags findings with
// its own internal lowercase names ("go", "pypi", "cargo", …) and only
// converts to OSV's spellings when it queries OSV.dev — the finding metadata
// keeps the internal name. This plugin was written against OSV's spellings,
// so every ecosystem except npm (identical in both) failed the support check
// and fell through to REACH-003 "unsupported ecosystem go". The support was
// present the whole time; it was never selected.
var ecosystemAliases = map[string]string{
	"go":        EcosystemGo,
	"golang":    EcosystemGo,
	"pypi":      EcosystemPyPI,
	"pip":       EcosystemPyPI,
	"python":    EcosystemPyPI,
	"npm":       EcosystemNPM,
	"node":      EcosystemNPM,
	"cargo":     EcosystemCargo,
	"crates":    EcosystemCargo,
	"crates.io": EcosystemCargo,
	"rust":      EcosystemCargo,
	"maven":     EcosystemMaven,
	"gradle":    EcosystemMaven,
	"java":      EcosystemMaven,
	"rubygems":  EcosystemRubyGems,
	"gem":       EcosystemRubyGems,
	"ruby":      EcosystemRubyGems,
	"nuget":     EcosystemNuGet,
	"dotnet":    EcosystemNuGet,
}

// CanonicalEcosystem maps an ecosystem label from a finding to the canonical
// name this plugin indexes on, returning the input unchanged when unknown so
// the caller can report it verbatim.
func CanonicalEcosystem(eco string) string {
	if canonical, ok := ecosystemAliases[strings.ToLower(strings.TrimSpace(eco))]; ok {
		return canonical
	}
	return eco
}

// supportedEcosystems lists ecosystems we can perform import analysis on.
// Precision class per language is documented per extractor:
//   - PyPI: top-level module regex + PEP 503 distribution-name normalisation; class B
//   - npm: import/require regex + scoped-package handling; class B
//   - crates.io: `use foo::...` regex with std exclusion; class B
//   - Maven: import-statement regex collapsed to top-three segments; class C (over-reports)
//   - RubyGems: require/require_relative regex; class B
//   - NuGet: using-statement regex collapsed to top-two segments; class C (over-reports)
//
// "Over-reports" means false-positives on reachability are possible,
// which is the safer direction (we never silently miss an exploited
// vulnerability path).
//
// Go is deliberately absent: it is not answered by import scanning at all but
// by call-graph analysis in goreach.go, which decides whether the vulnerable
// *symbol* is called rather than whether the package is named in source.
var supportedEcosystems = map[string]bool{
	EcosystemPyPI:     true,
	EcosystemNPM:      true,
	EcosystemCargo:    true,
	EcosystemMaven:    true,
	EcosystemRubyGems: true,
	EcosystemNuGet:    true,
}

// Analyze cross-references VULN findings against workspace imports and
// produces a Result for each.
//
// goReach answers the Go findings. It may be nil, which is treated as "the Go
// analysis was not available" and yields REACH-003 rather than a verdict
// derived from import text — module presence is not reachability.
func Analyze(vulns []VulnInfo, imports *ImportSet, goReach goReachability) []Result {
	results := make([]Result, 0, len(vulns))

	for i := range vulns {
		v := &vulns[i]
		if CanonicalEcosystem(v.Ecosystem) == EcosystemGo {
			results = append(results, goResult(v, goReach))
			continue
		}
		results = append(results, importResult(v, imports))
	}

	return results
}

// goResult classifies a Go advisory using call-graph analysis.
func goResult(v *VulnInfo, goReach goReachability) Result {
	if goReach == nil {
		goReach = goUnavailable{reason: "Go reachability analysis was not run for this workspace"}
	}

	verdict := goReach.Verdict(v)
	return Result{
		Vuln:     *v,
		Status:   verdict.Status,
		RuleID:   ruleIDFor(verdict.Status),
		Method:   MethodSymbol,
		Reason:   verdict.Reason,
		Evidence: verdict.Evidence,
	}
}

// importResult classifies a non-Go advisory by scanning import statements.
//
// The order of the cases carries the whole argument. A negative from the import
// index means "not imported" only when there was source to look in; when there
// was none, the same empty index means "nothing was searched", and reporting
// that as unreachable turns an absence of evidence into evidence of absence.
//
// That distinction is not academic. On a target holding only a lockfile — a CI
// job that checks out a manifest, a repo whose source lives elsewhere — every
// advisory was previously labelled "NOT imported — likely false positive",
// which reads as permission to stop looking. A missed detection costs a
// finding; a manufactured refutation costs the finding and the analyst's
// attention.
func importResult(v *VulnInfo, imports *ImportSet) Result {
	imported, supported := isImported(v.Package, v.Ecosystem, imports)

	r := Result{Vuln: *v, Method: MethodImport}
	switch {
	case !supported:
		r.Status = ReachUndetermined
		r.Reason = "unsupported ecosystem " + v.Ecosystem
	case imported:
		r.Status = ReachReachable
		r.Reason = "the vulnerable package is imported by this workspace"
	case !imports.Searched(CanonicalEcosystem(v.Ecosystem)):
		r.Status = ReachUndetermined
		r.Reason = "no " + v.Ecosystem + " source was found in this workspace, so " +
			"whether the package is used could not be determined"
	default:
		r.Status = ReachUnreachable
		r.Reason = "the vulnerable package is not imported by this workspace"
	}
	r.RuleID = ruleIDFor(r.Status)
	return r
}

func ruleIDFor(s ReachStatus) string {
	switch s {
	case ReachReachable:
		return "REACH-002"
	case ReachUnreachable:
		return "REACH-001"
	default:
		return "REACH-003"
	}
}

// isImported checks whether pkg is imported in the workspace for the given
// ecosystem. Returns (imported, supported).
func isImported(pkg, ecosystem string, imports *ImportSet) (imported, supported bool) {
	canonical := CanonicalEcosystem(ecosystem)
	if !supportedEcosystems[canonical] {
		return false, false
	}

	name := normalizePackageName(pkg, canonical)
	return imports.Contains(canonical, name), true
}

// normalizePackageName maps a dependency name to the form used in source
// imports. ecosystem must already be canonical.
func normalizePackageName(pkg, ecosystem string) string {
	switch ecosystem {
	case EcosystemGo:
		// Go imports use the full module path as-is.
		return pkg
	case EcosystemPyPI:
		return PyPIToImportName(pkg)
	case EcosystemNPM:
		// npm package names match import specifiers directly.
		return pkg
	case EcosystemCargo:
		// Cargo crate names use hyphens but `use` paths use underscores
		// after the crate root. We index extractors on the crate root
		// segment which preserves underscores.
		return strings.ReplaceAll(strings.ToLower(pkg), "-", "_")
	case EcosystemMaven:
		// Maven coordinates are `group:artifact`; reachability indexes
		// on `group.artifact-leading-segments`. Take the group portion
		// when present, else the bare name.
		if idx := strings.IndexByte(pkg, ':'); idx > 0 {
			return pkg[:idx]
		}
		return pkg
	case EcosystemRubyGems:
		return strings.ToLower(pkg)
	case EcosystemNuGet:
		return pkg
	default:
		return strings.ToLower(pkg)
	}
}
