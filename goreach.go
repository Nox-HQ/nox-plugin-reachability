// Symbol-level reachability for Go advisories.
//
// Every other ecosystem in this plugin answers "is the vulnerable package
// named anywhere in this repository's import statements". For Go that answer
// is both too weak and too strong: too weak because a vulnerable package is
// usually reached *through* a dependency rather than imported directly, and
// too strong because a module can be in the build graph while none of the
// symbols the advisory names are ever called — which is precisely the case
// operators need distinguished from a real exposure.
//
// So Go is answered by golang.org/x/vuln instead, the same analysis
// govulncheck performs: load the module's packages, build a call graph, and
// report whether a path exists from this module's code to a symbol the
// advisory names. x/vuln is used as a library rather than by shelling out to
// a govulncheck binary, because a binary the operator has not installed would
// make every Go finding undetermined on most machines.
//
// A wrong REACH-001 is the worst outcome this file can produce: it tells an
// operator to ignore something that can actually be exploited. Every path
// that cannot establish a verdict on positive evidence therefore degrades to
// REACH-003 carrying the reason, never to a guess.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/vuln/scan"
)

const (
	// goScanTimeout bounds the whole Go analysis. Call-graph construction is
	// superlinear in the size of the module graph, and reachability is an
	// enrichment rather than a gate: overrunning the budget must degrade to
	// REACH-003, never stall a scan.
	goScanTimeout = 3 * time.Minute

	// goMaxModules caps how many module roots a single workspace may contain
	// before the analysis gives up. The cap exists to keep a verdict honest,
	// not merely to bound runtime: analysing a subset of a workspace's modules
	// could miss the module that calls the vulnerable symbol and turn a real
	// exposure into REACH-001.
	goMaxModules = 8

	// goModuleWalkDepth bounds the search for nested go.mod files below a
	// workspace root that is not itself a module.
	goModuleWalkDepth = 4
)

// goEvidence ranks what the call-graph analysis established about an advisory,
// from weakest to strongest. Ordering matters: when several findings are
// emitted for one advisory (govulncheck emits module, package and symbol level
// findings as it works) the strongest one decides the verdict.
type goEvidence int

const (
	// goEvidenceNone means the advisory is known to the Go vulnerability
	// database and matched a module in this build, but produced no finding.
	goEvidenceNone goEvidence = iota
	// goEvidenceModule means the vulnerable module is in the build graph.
	goEvidenceModule
	// goEvidencePackage means a vulnerable package is imported, but no
	// vulnerable symbol in it is called.
	goEvidencePackage
	// goEvidenceSymbol means a symbol the advisory names is called.
	goEvidenceSymbol
)

// goVerdict is the outcome of Go reachability analysis for one advisory.
type goVerdict struct {
	Status ReachStatus
	// Reason explains the verdict in operator-facing prose. It is always set;
	// for REACH-003 it says why no verdict could be reached.
	Reason string
	// Evidence carries the proof for a reachable verdict — the call path from
	// this module's code to the vulnerable symbol. Empty otherwise.
	Evidence string
}

// goReachability answers reachability questions for Go advisories.
type goReachability interface {
	Verdict(v *VulnInfo) goVerdict
}

// goUnavailable is the goReachability used when the workspace could not be
// analysed at all. It reports the same honest reason for every advisory
// instead of letting a missing analysis masquerade as "not reachable".
type goUnavailable struct{ reason string }

func (g goUnavailable) Verdict(*VulnInfo) goVerdict {
	return goVerdict{Status: ReachUndetermined, Reason: g.reason}
}

// goIDPattern matches the Go vulnerability database's own identifier form.
// The Go database speaks GO ids; advisories arrive from OSV.dev as GHSA or
// CVE ids just as often, and are mapped through the alias index built from
// the scan itself.
var goIDPattern = regexp.MustCompile(`^GO-\d{4}-\d+$`)

// goScanResult indexes one govulncheck run.
type goScanResult struct {
	// known holds every advisory id the database matched to a module in this
	// build, regardless of whether the version in use is affected.
	known map[string]bool
	// evidence maps a GO id to the strongest evidence observed for it.
	evidence map[string]goEvidence
	// callPath maps a GO id to the call path proving a symbol is reached.
	callPath map[string]string
	// aliases maps an upper-cased GHSA/CVE id to the GO id it aliases.
	aliases map[string]string
	// modules names the module roots that were analysed, for the reason text.
	modules []string
}

func newGoScanResult() *goScanResult {
	return &goScanResult{
		known:    make(map[string]bool),
		evidence: make(map[string]goEvidence),
		callPath: make(map[string]string),
		aliases:  make(map[string]string),
	}
}

// Verdict classifies one advisory against the scan.
func (s *goScanResult) Verdict(v *VulnInfo) goVerdict {
	goID, ok := s.resolveGoID(v)
	if !ok {
		// Guessing here would be the expensive kind of wrong: an id the Go
		// database does not carry for any module in this build tells us
		// nothing at all about whether its code runs.
		return goVerdict{
			Status: ReachUndetermined,
			Reason: fmt.Sprintf("%s could not be mapped to an advisory in the Go vulnerability database for any module in this build (%s)", displayID(v), s.scope()),
		}
	}

	switch s.evidence[goID] {
	case goEvidenceSymbol:
		return goVerdict{
			Status:   ReachReachable,
			Reason:   fmt.Sprintf("call-graph analysis reaches a symbol named by %s", goID),
			Evidence: s.callPath[goID],
		}
	case goEvidencePackage:
		return goVerdict{
			Status: ReachUnreachable,
			Reason: fmt.Sprintf("a package named by %s is imported, but none of its vulnerable symbols are called", goID),
		}
	case goEvidenceModule:
		return goVerdict{
			Status: ReachUnreachable,
			Reason: fmt.Sprintf("the module is in the build graph, but no package named by %s is imported", goID),
		}
	default:
		// The database knows the advisory and matched it to a module here,
		// yet the analysis produced no finding: nothing in this build is
		// exposed to it, either because the selected version is not in the
		// affected range or because no vulnerable code is linked.
		return goVerdict{
			Status: ReachUnreachable,
			Reason: fmt.Sprintf("govulncheck found no path from this build to %s", goID),
		}
	}
}

// resolveGoID maps a finding's advisory id onto the GO id used by the scan,
// following the aliases the scan itself reported. Returns false when no
// mapping exists — the caller must then report REACH-003, not a verdict.
func (s *goScanResult) resolveGoID(v *VulnInfo) (goID string, ok bool) {
	candidates := make([]string, 0, 1+len(v.Aliases))
	if v.VulnID != "" {
		candidates = append(candidates, v.VulnID)
	}
	candidates = append(candidates, v.Aliases...)

	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if goIDPattern.MatchString(c) && s.known[c] {
			return c, true
		}
		if aliased, found := s.aliases[strings.ToUpper(c)]; found {
			return aliased, true
		}
	}
	return "", false
}

// scope describes which module roots the verdict is based on, so a REACH-003
// message says what was actually looked at.
func (s *goScanResult) scope() string {
	switch len(s.modules) {
	case 0:
		return "no module analysed"
	case 1:
		return "analysed module: " + s.modules[0]
	default:
		return fmt.Sprintf("analysed %d modules under the workspace root", len(s.modules))
	}
}

// observe folds one govulncheck finding into the result.
func (s *goScanResult) observe(f *govulncheckFinding) {
	if f == nil || f.OSV == "" {
		return
	}
	s.known[f.OSV] = true

	level, path := frameEvidence(f.Trace)
	if level > s.evidence[f.OSV] {
		s.evidence[f.OSV] = level
	}
	if level == goEvidenceSymbol && s.callPath[f.OSV] == "" {
		s.callPath[f.OSV] = path
	}
}

// frameEvidence reads the level of a finding out of its trace, and renders
// the call path when the trace proves a symbol is reached.
//
// govulncheck encodes the level structurally rather than in a field: a
// module-level finding is a single frame carrying only a module, a
// package-level finding adds the package, and a symbol-level finding adds the
// function plus the frames leading back to the entry point.
func frameEvidence(trace []*govulncheckFrame) (level goEvidence, callPath string) {
	if len(trace) == 0 {
		return goEvidenceNone, ""
	}
	vuln := trace[0]
	switch {
	case vuln.Function != "":
		return goEvidenceSymbol, renderCallPath(trace)
	case vuln.Package != "":
		return goEvidencePackage, ""
	default:
		return goEvidenceModule, ""
	}
}

// renderCallPath turns a trace into a caller-to-callee path. govulncheck
// orders frames from the vulnerable symbol outwards to the entry point, which
// is the reverse of how a stack reads.
func renderCallPath(trace []*govulncheckFrame) string {
	parts := make([]string, 0, len(trace))
	for i := len(trace) - 1; i >= 0; i-- {
		parts = append(parts, trace[i].symbol())
	}
	return strings.Join(parts, " → ")
}

// observeOSV records an advisory the database matched to this build, along
// with its aliases, so GHSA and CVE ids on incoming findings can be mapped.
func (s *goScanResult) observeOSV(e *govulncheckOSV) {
	if e == nil || e.ID == "" {
		return
	}
	s.known[e.ID] = true
	for _, alias := range e.Aliases {
		if alias = strings.TrimSpace(alias); alias != "" {
			s.aliases[strings.ToUpper(alias)] = e.ID
		}
	}
}

// --- govulncheck JSON stream ------------------------------------------------
//
// These mirror the message types in golang.org/x/vuln/internal/govulncheck,
// which is an internal package and so cannot be imported. Only the fields this
// plugin reads are declared; the stream is versioned by config.protocol_version
// and unknown fields are ignored by encoding/json.

type govulncheckMessage struct {
	Config  *govulncheckConfig  `json:"config,omitempty"`
	OSV     *govulncheckOSV     `json:"osv,omitempty"`
	Finding *govulncheckFinding `json:"finding,omitempty"`
}

type govulncheckConfig struct {
	ProtocolVersion string `json:"protocol_version"`
	ScanLevel       string `json:"scan_level,omitempty"`
	ScanMode        string `json:"scan_mode,omitempty"`
}

type govulncheckOSV struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
}

type govulncheckFinding struct {
	OSV   string              `json:"osv,omitempty"`
	Trace []*govulncheckFrame `json:"trace,omitempty"`
}

type govulncheckFrame struct {
	Module   string `json:"module"`
	Package  string `json:"package,omitempty"`
	Function string `json:"function,omitempty"`
	Receiver string `json:"receiver,omitempty"`
}

// symbol renders a frame as a qualified symbol name.
func (f *govulncheckFrame) symbol() string {
	name := f.Package
	if name == "" {
		name = f.Module
	}
	if f.Function == "" {
		return name
	}
	if f.Receiver != "" {
		return name + "." + f.Receiver + "." + f.Function
	}
	return name + "." + f.Function
}

// parseGoScanStream folds a govulncheck JSON stream into a result. The stream
// is a concatenation of JSON objects rather than an array, so it is decoded
// incrementally.
func parseGoScanStream(r io.Reader, into *goScanResult) error {
	dec := json.NewDecoder(r)
	sawConfig := false

	for {
		var msg govulncheckMessage
		err := dec.Decode(&msg)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("decoding govulncheck output: %w", err)
		}

		switch {
		case msg.Config != nil:
			sawConfig = true
			// A scan that did not run at symbol level cannot distinguish
			// "imported" from "called", so its findings must not be read as
			// if it could.
			if msg.Config.ScanLevel != "" && msg.Config.ScanLevel != "symbol" {
				return fmt.Errorf("govulncheck ran at %q scan level, which cannot establish symbol reachability", msg.Config.ScanLevel)
			}
		case msg.OSV != nil:
			into.observeOSV(msg.OSV)
		case msg.Finding != nil:
			into.observe(msg.Finding)
		}
	}

	if !sawConfig {
		// The config message is mandatory and always first. Its absence means
		// the stream is truncated or is not govulncheck output at all, and a
		// truncated stream would silently under-report reachability.
		return errors.New("govulncheck produced no config message; output is not a complete JSON stream")
	}
	return nil
}

// --- running the analysis ---------------------------------------------------

// goAnalyzer runs the Go reachability analysis over a workspace.
type goAnalyzer struct {
	// root is the workspace being scanned.
	root string
	// db overrides the vulnerability database URL. Empty uses govulncheck's
	// default (https://vuln.go.dev). Tests point it at a file:// fixture so
	// they never touch the network.
	db string
	// timeout bounds the whole analysis.
	timeout time.Duration
	// env overrides the child environment. Empty uses the process environment.
	env []string
}

// newGoReachability analyses the Go module(s) under root and returns a
// resolver for Go advisories. It never returns nil and never returns an
// error: every failure becomes a goUnavailable carrying the reason, because
// an operator reading "cannot determine, the module does not build" is served
// and an operator reading a fabricated "not reachable" is not.
func newGoReachability(ctx context.Context, root string) goReachability {
	return goAnalyzer{root: root, timeout: goScanTimeout}.analyze(ctx)
}

func (a goAnalyzer) analyze(ctx context.Context) goReachability {
	if a.root == "" {
		return goUnavailable{reason: "cannot determine Go reachability: no workspace root was provided, so no Go module could be analysed"}
	}

	dirs, err := goModuleDirs(a.root)
	if err != nil {
		return goUnavailable{reason: err.Error()}
	}

	timeout := a.timeout
	if timeout <= 0 {
		timeout = goScanTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result := newGoScanResult()
	for _, dir := range dirs {
		if err := a.scanModule(ctx, dir, result); err != nil {
			// One unanalysable module poisons the whole verdict rather than
			// part of it: the module that could not be loaded may be exactly
			// the one calling the vulnerable symbol.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return goUnavailable{reason: fmt.Sprintf("cannot determine Go reachability: the analysis exceeded its %s budget", timeout)}
			}
			return goUnavailable{reason: err.Error()}
		}
		result.modules = append(result.modules, relOrAbs(a.root, dir))
	}

	return result
}

// scanModule runs govulncheck over one module root and folds the result in.
func (a goAnalyzer) scanModule(ctx context.Context, dir string, into *goScanResult) error {
	args := []string{"-C", dir, "-format", "json", "-mode", "source", "-scan", "symbol"}
	if a.db != "" {
		args = append(args, "-db", a.db)
	}
	args = append(args, "./...")

	var stdout, stderr bytes.Buffer
	cmd := scan.Command(ctx, args...)
	// Stdin defaults to os.Stdin, which the plugin protocol owns. govulncheck
	// only reads it in convert mode, but handing it the real stdin risks
	// consuming bytes that belong to the host.
	cmd.Stdin = bytes.NewReader(nil)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Never let analysis mutate the go.mod of the repository under scan.
	cmd.Env = append(a.environ(), "GOFLAGS=-mod=readonly")

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cannot determine Go reachability: the analysis could not start for %s: %v", relOrAbs(a.root, dir), err)
	}
	if err := cmd.Wait(); err != nil && !isVulnerabilitiesFound(err) {
		return fmt.Errorf("cannot determine Go reachability: the analysis failed for %s: %v%s", relOrAbs(a.root, dir), err, stderrHint(stderr.String()))
	}

	if err := parseGoScanStream(&stdout, into); err != nil {
		return fmt.Errorf("cannot determine Go reachability: the analysis produced unusable output for %s: %v%s", relOrAbs(a.root, dir), err, stderrHint(stderr.String()))
	}
	return nil
}

func (a goAnalyzer) environ() []string {
	if len(a.env) > 0 {
		return append([]string(nil), a.env...)
	}
	return os.Environ()
}

// isVulnerabilitiesFound reports whether err is govulncheck's "vulnerabilities
// found" exit status rather than a failure. JSON output does not currently
// return it, but the exit code is part of govulncheck's contract and treating
// it as a failure would turn every real finding into REACH-003.
func isVulnerabilitiesFound(err error) bool {
	var coded interface{ ExitCode() int }
	return errors.As(err, &coded) && coded.ExitCode() == 3
}

// stderrHint appends a bounded excerpt of govulncheck's diagnostics. The
// reason an analysis failed — an unresolvable dependency, a build error — is
// only in stderr, and an operator cannot act on "it failed".
func stderrHint(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	const maxLen = 300
	if len(s) > maxLen {
		s = s[:maxLen] + "…"
	}
	return ": " + strings.ReplaceAll(s, "\n", "; ")
}

// goModuleDirs finds the module roots to analyse under root.
//
// The common case is a workspace that is itself a module. Otherwise nested
// modules are searched for, because a module nested below the root is not
// covered by any parent's ./... pattern.
func goModuleDirs(root string) ([]string, error) {
	if isGoModuleDir(root) {
		return []string{root}, nil
	}

	var dirs []string
	rootDepth := strings.Count(filepath.Clean(root), string(filepath.Separator))
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // an unreadable subtree is not a reason to abandon the walk
		}
		if !d.IsDir() {
			return nil
		}
		if path != root && (skippedDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
			return filepath.SkipDir
		}
		if strings.Count(filepath.Clean(path), string(filepath.Separator))-rootDepth > goModuleWalkDepth {
			return filepath.SkipDir
		}
		if isGoModuleDir(path) {
			dirs = append(dirs, path)
			// Packages of a nested module belong to that module; there is no
			// need to descend further looking for more roots under it.
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cannot determine Go reachability: searching %s for a Go module failed: %v", root, err)
	}

	switch {
	case len(dirs) == 0:
		return nil, fmt.Errorf("cannot determine Go reachability: no go.mod under %s, so this target is not a buildable Go module", root)
	case len(dirs) > goMaxModules:
		// Analysing only some of them could miss the module that calls the
		// vulnerable symbol, which would turn a real exposure into REACH-001.
		return nil, fmt.Errorf("cannot determine Go reachability: %s contains %d Go modules, more than the %d this plugin analyses", root, len(dirs), goMaxModules)
	}

	sort.Strings(dirs)
	return dirs, nil
}

func isGoModuleDir(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, "go.mod"))
	return err == nil && !info.IsDir()
}

// relOrAbs renders dir relative to root for readable messages, falling back to
// the absolute path when the two are unrelated.
func relOrAbs(root, dir string) string {
	if root == dir {
		return "."
	}
	if rel, err := filepath.Rel(root, dir); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return dir
}

// displayID renders the advisory id an operator would recognise from the
// original finding.
func displayID(v *VulnInfo) string {
	if v.VulnID != "" {
		return v.VulnID
	}
	return v.Package
}
