package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// A package that this workspace never names in source is not thereby unused:
// it is usually loaded by a package that IS named. express is imported; qs,
// cookie, body-parser and send are never imported by the application, and all
// of them execute on every request. Import text alone cannot tell the second
// kind of package from one nobody uses, so the lockfile's dependency graph is
// consulted, and "unreachable" is only ever concluded from a graph that was
// actually read, resolved completely, and walked from the imported packages.

// depNode is one resolved package instance in a lockfile.
type depNode struct {
	name    string // as written in the lockfile
	version string
	// dev is true only when the lockfile itself marks the instance as
	// development-only (package-lock.json "dev": true). Formats that do not
	// record this leave it false, which means "not known to be dev", never
	// "known to be production".
	dev  bool
	deps []string // ids of the nodes this instance loads
	// unresolved counts required dependencies that named no node. A graph with
	// holes cannot support a claim of absence.
	unresolved int
}

// DepGraph is the dependency graph of one lockfile.
type DepGraph struct {
	// Source is the lockfile the graph was read from.
	Source string
	eco    string
	nodes  map[string]*depNode
	byName map[string][]string // normalised name -> node ids
}

func newDepGraph(source, eco string) *DepGraph {
	return &DepGraph{Source: source, eco: eco, nodes: map[string]*depNode{}, byName: map[string][]string{}}
}

func (g *DepGraph) add(id string, n *depNode) {
	g.nodes[id] = n
	key := graphName(g.eco, n.name)
	g.byName[key] = append(g.byName[key], id)
}

// graphName normalises a package name for comparison within an ecosystem.
func graphName(eco, name string) string {
	switch eco {
	case EcosystemPyPI:
		n := strings.ToLower(name)
		for _, sep := range []string{"_", "."} {
			n = strings.ReplaceAll(n, sep, "-")
		}
		return n
	case EcosystemCargo:
		return strings.ReplaceAll(strings.ToLower(name), "-", "_")
	case EcosystemRubyGems:
		return strings.ToLower(name)
	default:
		return name
	}
}

// TraceKind is the outcome of walking the graph for one package.
type TraceKind int

const (
	// TraceMissing: the package is not in the lockfile at all.
	TraceMissing TraceKind = iota
	// TraceDirect: the package is itself imported by the workspace.
	TraceDirect
	// TraceTransitive: an imported package loads it, directly or not.
	TraceTransitive
	// TraceUnreached: in the lockfile, but no imported package leads to it.
	TraceUnreached
	// TraceIncomplete: not reached, but the graph had unresolved edges, so
	// absence cannot be concluded.
	TraceIncomplete
)

// Trace is the evidence behind a TraceKind.
type Trace struct {
	Kind TraceKind
	// Chain is the path of package names from an imported package to the
	// target, for TraceTransitive.
	Chain []string
	// DevOnly is set for TraceUnreached when the lockfile marks every instance
	// of the package as development-only.
	DevOnly bool
	// Unresolved is the number of unresolved edges, for TraceIncomplete.
	Unresolved int
}

// Trace walks the graph breadth-first from every node whose name the workspace
// imports (isRoot) and reports how, if at all, target is reached. Breadth-first
// order makes the reported chain the shortest one, and deterministic: ids are
// visited in sorted order.
func (g *DepGraph) Trace(target string, isRoot func(name string) bool) Trace {
	targets := g.byName[graphName(g.eco, target)]
	if len(targets) == 0 {
		return Trace{Kind: TraceMissing}
	}
	isTarget := map[string]bool{}
	for _, id := range targets {
		isTarget[id] = true
	}

	ids := make([]string, 0, len(g.nodes))
	for id := range g.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	parent := map[string]string{}
	var queue []string
	for _, id := range ids {
		if isRoot(g.nodes[id].name) {
			parent[id] = ""
			queue = append(queue, id)
		}
	}

	unresolved := 0
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		n := g.nodes[id]
		unresolved += n.unresolved
		if isTarget[id] {
			return g.found(id, parent)
		}
		for _, dep := range n.deps {
			if _, seen := parent[dep]; seen {
				continue
			}
			parent[dep] = id
			queue = append(queue, dep)
		}
	}

	if unresolved > 0 {
		return Trace{Kind: TraceIncomplete, Unresolved: unresolved}
	}
	dev := true
	for _, id := range targets {
		dev = dev && g.nodes[id].dev
	}
	return Trace{Kind: TraceUnreached, DevOnly: dev}
}

func (g *DepGraph) found(id string, parent map[string]string) Trace {
	var chain []string
	for cur := id; cur != ""; cur = parent[cur] {
		chain = append([]string{g.nodes[cur].name}, chain...)
	}
	if len(chain) == 1 {
		return Trace{Kind: TraceDirect, Chain: chain}
	}
	return Trace{Kind: TraceTransitive, Chain: chain}
}

// GraphSource supplies the dependency graph behind a finding. The second
// return value says why no graph is available, and is surfaced verbatim in the
// finding so that "could not determine" always carries its cause.
type GraphSource interface {
	GraphFor(v *VulnInfo) (*DepGraph, string)
}

// lockGraphs reads lockfiles from the workspace on demand, once each.
type lockGraphs struct {
	root  string
	cache map[string]graphResult
}

type graphResult struct {
	g   *DepGraph
	why string
}

func newLockGraphs(root string) *lockGraphs {
	return &lockGraphs{root: root, cache: map[string]graphResult{}}
}

// lockfileNames lists, per ecosystem, the lockfiles that carry a dependency
// graph, in preference order.
var lockfileNames = map[string][]string{
	EcosystemNPM:      {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"},
	EcosystemCargo:    {"Cargo.lock"},
	EcosystemRubyGems: {"Gemfile.lock"},
	EcosystemPyPI:     {"poetry.lock"},
}

// GraphFor finds the lockfile beside the file that declares the vulnerable
// dependency and parses it.
func (l *lockGraphs) GraphFor(v *VulnInfo) (g *DepGraph, why string) {
	eco := CanonicalEcosystem(v.Ecosystem)
	names := lockfileNames[eco]
	if len(names) == 0 {
		return nil, "no dependency graph is read for " + v.Ecosystem + " lockfiles"
	}
	if l.root == "" {
		return nil, "no workspace root, so no lockfile could be read"
	}
	decl := filepath.Join(l.root, filepath.FromSlash(v.File))
	if v.File == "" {
		decl = filepath.Join(l.root, "manifest")
	}
	if !within(l.root, decl) {
		return nil, "the declaring file is outside the workspace"
	}
	dir := filepath.Dir(decl)
	candidates := names
	if base := filepath.Base(decl); containsString(names, base) {
		candidates = append([]string{base}, names...)
	}
	for _, name := range candidates {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		return l.load(path, eco)
	}
	return nil, fmt.Sprintf("no lockfile (%s) beside %s", strings.Join(names, ", "), relOrSelf(l.root, decl))
}

func (l *lockGraphs) load(path, eco string) (g *DepGraph, why string) {
	if r, ok := l.cache[path]; ok {
		return r.g, r.why
	}
	parsed, err := parseLockfile(path, eco)
	r := graphResult{g: parsed}
	if err != nil {
		r = graphResult{why: fmt.Sprintf("lockfile %s could not be read: %v", relOrSelf(l.root, path), err)}
	}
	l.cache[path] = r
	return r.g, r.why
}

func parseLockfile(path, eco string) (*DepGraph, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rel := filepath.Base(path)
	switch filepath.Base(path) {
	case "package-lock.json", "npm-shrinkwrap.json":
		return parseNPMLock(data, rel, eco)
	case "yarn.lock":
		return parseYarnLock(data, rel, eco)
	case "pnpm-lock.yaml":
		return parsePnpmLock(data, rel, eco)
	case "Cargo.lock":
		return parseCargoLock(data, rel, eco)
	case "Gemfile.lock":
		return parseGemfileLock(data, rel, eco)
	case "poetry.lock":
		return parsePoetryLock(data, rel, eco)
	}
	return nil, fmt.Errorf("unrecognised lockfile")
}

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func relOrSelf(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return path
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
