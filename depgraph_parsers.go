package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// --- npm: package-lock.json / npm-shrinkwrap.json ---------------------------

type npmLockPkg struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dev                  bool              `json:"dev"`
	Link                 bool              `json:"link"`
	Resolved             string            `json:"resolved"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	PeerMeta             map[string]struct {
		Optional bool `json:"optional"`
	} `json:"peerDependenciesMeta"`
}

type npmLockV1Dep struct {
	Version      string                  `json:"version"`
	Dev          bool                    `json:"dev"`
	Requires     map[string]string       `json:"requires"`
	Dependencies map[string]npmLockV1Dep `json:"dependencies"`
}

type npmLockFile struct {
	Packages     map[string]npmLockPkg   `json:"packages"`
	Dependencies map[string]npmLockV1Dep `json:"dependencies"`
}

const nodeModules = "node_modules/"

func parseNPMLock(data []byte, source, eco string) (*DepGraph, error) {
	var lf npmLockFile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, err
	}
	pkgs := lf.Packages
	if len(pkgs) == 0 && len(lf.Dependencies) > 0 {
		pkgs = flattenNPMV1(lf.Dependencies)
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no packages recorded")
	}

	g := newDepGraph(source, eco)
	keys := make([]string, 0, len(pkgs))
	for k := range pkgs {
		if k != "" { // the root project: its declarations are not imports
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	for _, k := range keys {
		p := pkgs[k]
		name := p.Name
		if i := strings.LastIndex(k, nodeModules); i >= 0 {
			name = k[i+len(nodeModules):]
		} else if name == "" {
			name = k // a workspace member keyed by its path
		}
		g.add(k, &depNode{name: name, version: p.Version, dev: p.Dev})
	}
	for _, k := range keys {
		p, n := pkgs[k], g.nodes[k]
		if p.Link && p.Resolved != "" {
			if _, ok := g.nodes[p.Resolved]; ok {
				n.deps = append(n.deps, p.Resolved)
			}
		}
		for _, dep := range sortedKeys(p.Dependencies) {
			if id := resolveNPM(g, k, dep); id != "" {
				n.deps = append(n.deps, id)
			} else {
				n.unresolved++
			}
		}
		// Optional and peer dependencies that are installed are loaded; ones
		// that are absent were legitimately not installed.
		for _, m := range []map[string]string{p.OptionalDependencies, p.PeerDependencies} {
			for _, dep := range sortedKeys(m) {
				if id := resolveNPM(g, k, dep); id != "" {
					n.deps = append(n.deps, id)
				}
			}
		}
	}
	return g, nil
}

// resolveNPM applies Node's resolution: look in the package's own
// node_modules, then in each ancestor's, outward to the root.
func resolveNPM(g *DepGraph, from, dep string) string {
	for cur := from; ; {
		cand := nodeModules + dep
		if cur != "" {
			cand = cur + "/" + nodeModules + dep
		}
		if _, ok := g.nodes[cand]; ok {
			return cand
		}
		if cur == "" {
			return ""
		}
		if i := strings.LastIndex(cur, "/"+nodeModules); i >= 0 {
			cur = cur[:i]
		} else {
			cur = ""
		}
	}
}

// flattenNPMV1 rewrites the nested lockfileVersion 1 tree into the v2 shape.
func flattenNPMV1(tree map[string]npmLockV1Dep) map[string]npmLockPkg {
	out := map[string]npmLockPkg{}
	var walk func(prefix string, deps map[string]npmLockV1Dep)
	walk = func(prefix string, deps map[string]npmLockV1Dep) {
		for name, d := range deps {
			key := prefix + nodeModules + name
			out[key] = npmLockPkg{Version: d.Version, Dev: d.Dev, Dependencies: d.Requires}
			walk(key+"/", d.Dependencies)
		}
	}
	walk("", tree)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// --- yarn.lock (classic and berry) -----------------------------------------

func parseYarnLock(data []byte, source, eco string) (*DepGraph, error) {
	type entry struct {
		specs []string
		name  string
		deps  []string // "name@range" references
		opt   []string
	}
	var entries []*entry
	var cur *entry
	section := ""
	berry := bytes.Contains(data, []byte("__metadata:"))

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 1<<16), 1<<24)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		text := strings.TrimSpace(line)
		switch {
		case indent == 0 && strings.HasSuffix(text, ":"):
			cur, section = nil, ""
			if text == "__metadata:" {
				continue
			}
			cur = &entry{}
			for _, s := range strings.Split(strings.TrimSuffix(text, ":"), ",") {
				s = strings.Trim(strings.TrimSpace(s), `"`)
				cur.specs = append(cur.specs, s)
			}
			cur.name = yarnSpecName(cur.specs[0])
			entries = append(entries, cur)
		case cur == nil:
		case indent == 2:
			section = ""
			if text == "dependencies:" || text == "optionalDependencies:" {
				section = strings.TrimSuffix(text, ":")
			}
		case indent == 4 && section != "":
			name, rng := splitYarnDep(text, berry)
			ref := name + "@" + rng
			if section == "dependencies" {
				cur.deps = append(cur.deps, ref)
			} else {
				cur.opt = append(cur.opt, ref)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no packages recorded")
	}

	g := newDepGraph(source, eco)
	bySpec := map[string]string{}
	for _, e := range entries {
		id := e.specs[0]
		g.add(id, &depNode{name: e.name})
		for _, s := range e.specs {
			bySpec[s] = id
		}
	}
	resolve := func(ref string) string {
		if id, ok := bySpec[ref]; ok {
			return id
		}
		if i := strings.LastIndex(ref, "@"); i > 0 {
			return bySpec[ref[:i]+"@npm:"+ref[i+1:]]
		}
		return ""
	}
	for _, e := range entries {
		n := g.nodes[e.specs[0]]
		for _, ref := range e.deps {
			if id := resolve(ref); id != "" {
				n.deps = append(n.deps, id)
			} else {
				n.unresolved++
			}
		}
		for _, ref := range e.opt {
			if id := resolve(ref); id != "" {
				n.deps = append(n.deps, id)
			}
		}
	}
	return g, nil
}

// yarnSpecName returns the package name of "name@range" / "@scope/name@range".
func yarnSpecName(spec string) string {
	if i := strings.LastIndex(spec, "@"); i > 0 {
		return spec[:i]
	}
	return spec
}

func splitYarnDep(text string, berry bool) (name, rng string) {
	if berry {
		name, rng, _ = strings.Cut(text, ": ")
	} else {
		name, rng, _ = strings.Cut(text, " ")
	}
	return strings.Trim(name, `"`), strings.Trim(strings.TrimSpace(rng), `"`)
}

// --- pnpm-lock.yaml ---------------------------------------------------------

type pnpmSnapshot struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

type pnpmLock struct {
	Packages  map[string]pnpmSnapshot `yaml:"packages"`
	Snapshots map[string]pnpmSnapshot `yaml:"snapshots"`
}

func parsePnpmLock(data []byte, source, eco string) (*DepGraph, error) {
	var lf pnpmLock
	if err := yaml.Unmarshal(data, &lf); err != nil {
		return nil, err
	}
	// lockfile v9 keeps edges in snapshots; v5/v6 keep them in packages.
	snaps := lf.Snapshots
	if len(snaps) == 0 {
		snaps = lf.Packages
	}
	if len(snaps) == 0 {
		return nil, fmt.Errorf("no packages recorded")
	}

	g := newDepGraph(source, eco)
	keys := sortedKeys(snaps)
	byRef := map[string]string{}
	for _, k := range keys {
		name, ver := pnpmKey(k)
		g.add(k, &depNode{name: name, version: ver})
		byRef[name+"@"+ver] = k
		byRef[name+"/"+ver] = k
	}
	for _, k := range keys {
		n, s := g.nodes[k], snaps[k]
		for _, dep := range sortedKeys(s.Dependencies) {
			if id := resolvePnpm(g, byRef, dep, s.Dependencies[dep]); id != "" {
				n.deps = append(n.deps, id)
			} else {
				n.unresolved++
			}
		}
		for _, dep := range sortedKeys(s.OptionalDependencies) {
			if id := resolvePnpm(g, byRef, dep, s.OptionalDependencies[dep]); id != "" {
				n.deps = append(n.deps, id)
			}
		}
	}
	return g, nil
}

// pnpmKey splits "/name@1.0.0(peer@2)", "name@1.0.0" or "/name/1.0.0".
func pnpmKey(k string) (name, version string) {
	k = strings.TrimPrefix(k, "/")
	if i := strings.Index(k, "("); i > 0 {
		k = k[:i]
	}
	if i := strings.LastIndex(k, "@"); i > 0 {
		return k[:i], k[i+1:]
	}
	if i := strings.LastIndex(k, "/"); i > 0 {
		return k[:i], k[i+1:]
	}
	return k, ""
}

func resolvePnpm(g *DepGraph, byRef map[string]string, dep, ref string) string {
	if strings.HasPrefix(ref, "link:") {
		return "" // a workspace link; its own entry is not in packages
	}
	if i := strings.Index(ref, "("); i > 0 {
		ref = ref[:i]
	}
	if strings.HasPrefix(ref, "npm:") { // alias: npm:real@1.0.0
		target, ver := pnpmKey(strings.TrimPrefix(ref, "npm:"))
		dep, ref = target, ver
	}
	for _, c := range []string{dep + "@" + ref, dep + "/" + ref} {
		if id, ok := byRef[c]; ok {
			return id
		}
	}
	return ""
}

// --- Cargo.lock -------------------------------------------------------------

func parseCargoLock(data []byte, source, eco string) (*DepGraph, error) {
	type pkg struct {
		name, version string
		deps          []string
	}
	var pkgs []*pkg
	var cur *pkg
	inDeps := false

	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "[[package]]":
			cur = &pkg{}
			pkgs = append(pkgs, cur)
			inDeps = false
		case cur == nil:
		case inDeps:
			if line == "]" {
				inDeps = false
				continue
			}
			cur.deps = append(cur.deps, strings.Trim(strings.TrimSuffix(line, ","), `"`))
		case strings.HasPrefix(line, "name = "):
			cur.name = tomlString(line)
		case strings.HasPrefix(line, "version = "):
			cur.version = tomlString(line)
		case strings.HasPrefix(line, "dependencies = ["):
			rest := strings.TrimPrefix(line, "dependencies = [")
			if strings.HasSuffix(rest, "]") {
				for _, d := range strings.Split(strings.TrimSuffix(rest, "]"), ",") {
					if d = strings.Trim(strings.TrimSpace(d), `"`); d != "" {
						cur.deps = append(cur.deps, d)
					}
				}
			} else {
				inDeps = true
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no packages recorded")
	}

	g := newDepGraph(source, eco)
	for _, p := range pkgs {
		g.add(p.name+" "+p.version, &depNode{name: p.name, version: p.version})
	}
	for _, p := range pkgs {
		n := g.nodes[p.name+" "+p.version]
		for _, ref := range p.deps {
			parts := strings.Fields(ref)
			if len(parts) == 0 {
				continue
			}
			var ids []string
			if len(parts) >= 2 {
				if _, ok := g.nodes[parts[0]+" "+parts[1]]; ok {
					ids = []string{parts[0] + " " + parts[1]}
				}
			} else {
				ids = g.byName[graphName(eco, parts[0])]
			}
			if len(ids) == 0 {
				n.unresolved++
			}
			n.deps = append(n.deps, ids...)
		}
	}
	return g, nil
}

func tomlString(line string) string {
	_, v, _ := strings.Cut(line, "=")
	return strings.Trim(strings.TrimSpace(v), `"`)
}

// --- Gemfile.lock -----------------------------------------------------------

func parseGemfileLock(data []byte, source, eco string) (*DepGraph, error) {
	type spec struct {
		name string
		deps []string
	}
	var specs []*spec
	var cur *spec
	inSpecs := false

	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		text := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " "))
		switch {
		case text == "":
			inSpecs = false
		case indent == 0:
			inSpecs = false
		case indent == 2 && text == "specs:":
			inSpecs = true
		case !inSpecs:
		case indent == 4:
			name, _, _ := strings.Cut(text, " ")
			cur = &spec{name: name}
			specs = append(specs, cur)
		case indent == 6 && cur != nil:
			name, _, _ := strings.Cut(text, " ")
			cur.deps = append(cur.deps, name)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("no gems recorded")
	}

	g := newDepGraph(source, eco)
	for _, s := range specs {
		g.add(s.name, &depNode{name: s.name})
	}
	for _, s := range specs {
		n := g.nodes[s.name]
		for _, d := range s.deps {
			if _, ok := g.nodes[d]; ok {
				n.deps = append(n.deps, d)
			} else {
				n.unresolved++
			}
		}
	}
	return g, nil
}

// --- poetry.lock ------------------------------------------------------------

func parsePoetryLock(data []byte, source, eco string) (*DepGraph, error) {
	type pkg struct {
		name string
		deps []string
	}
	var pkgs []*pkg
	var cur *pkg
	inDeps := false

	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "[[package]]":
			cur = &pkg{}
			pkgs = append(pkgs, cur)
			inDeps = false
		case strings.HasPrefix(line, "["):
			inDeps = line == "[package.dependencies]"
		case cur == nil || line == "" || strings.HasPrefix(line, "#"):
		case inDeps:
			if k, _, ok := strings.Cut(line, "="); ok {
				cur.deps = append(cur.deps, strings.Trim(strings.TrimSpace(k), `"`))
			}
		case strings.HasPrefix(line, "name = "):
			cur.name = tomlString(line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no packages recorded")
	}

	g := newDepGraph(source, eco)
	for _, p := range pkgs {
		g.add(graphName(eco, p.name), &depNode{name: p.name})
	}
	for _, p := range pkgs {
		n := g.nodes[graphName(eco, p.name)]
		for _, d := range p.deps {
			if _, ok := g.nodes[graphName(eco, d)]; ok {
				n.deps = append(n.deps, graphName(eco, d))
			}
			// A dependency named here but absent is an optional extra poetry
			// did not lock; it was not installed, so it is not a hole.
		}
	}
	return g, nil
}
