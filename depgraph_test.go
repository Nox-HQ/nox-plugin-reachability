package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The defect: a package the workspace never names is not thereby unused. It is
// usually loaded by a package that IS named. These tests drive importResult
// over real lockfile text, because the bug lived in the seam between "what the
// source imports" and "what the lockfile says loads what".

const expressSrc = `const express = require('express');`

const npmLockV3 = `{"lockfileVersion":3,"packages":{
 "":{"name":"app","dependencies":{"express":"4.18.2","unused-lib":"1.0.0"},"devDependencies":{"jest":"29"}},
 "node_modules/express":{"version":"4.18.2","dependencies":{"body-parser":"1.20.1","send":"0.18.0"}},
 "node_modules/body-parser":{"version":"1.20.1","dependencies":{"qs":"6.11.0"}},
 "node_modules/body-parser/node_modules/qs":{"version":"6.11.0"},
 "node_modules/send":{"version":"0.18.0"},
 "node_modules/qs":{"version":"6.5.0"},
 "node_modules/unused-lib":{"version":"1.0.0"},
 "node_modules/jest":{"version":"29.0.0","dev":true},
 "node_modules/jest-util":{"version":"29.0.0","dev":true}}}`

func analyzeIn(t *testing.T, files map[string]string, v *VulnInfo) Result {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	imports, err := ExtractImports(dir)
	if err != nil {
		t.Fatal(err)
	}
	return importResult(v, imports, newLockGraphs(dir))
}

func npmVuln(pkg string) *VulnInfo {
	return &VulnInfo{Package: pkg, Ecosystem: "npm", VulnID: "GHSA-x", File: "package-lock.json"}
}

// Proposition: a transitive dependency of an imported package is reachable,
// and says how.
func TestTransitiveDependencyIsNotUnimported(t *testing.T) {
	files := map[string]string{"package-lock.json": npmLockV3, "src/app.js": expressSrc}
	for _, pkg := range []string{"body-parser", "send", "qs"} {
		r := analyzeIn(t, files, npmVuln(pkg))
		if r.Status != ReachReachable || r.RuleID != "REACH-002" {
			t.Fatalf("%s: Status=%v RuleID=%s, want reachable REACH-002 (reason: %s)", pkg, r.Status, r.RuleID, r.Reason)
		}
		if !strings.Contains(r.Reason, "pulled in by express (transitively loaded)") {
			t.Errorf("%s: reason %q does not name the importing package", pkg, r.Reason)
		}
		if !strings.HasPrefix(r.Evidence, "express -> ") {
			t.Errorf("%s: evidence %q is not a chain from express", pkg, r.Evidence)
		}
		if msg := messageFor(&r); strings.Contains(strings.ToLower(msg), "false positive") || strings.Contains(msg, "not imported") {
			t.Errorf("%s: message %q still reads as a refutation", pkg, msg)
		}
	}
}

// Counterexample: a package declared but never imported, with no dependents,
// must still be reported unreachable, or the fix is just "everything reachable".
func TestGenuinelyUnreachablePackageStaysUnreachable(t *testing.T) {
	files := map[string]string{"package-lock.json": npmLockV3, "src/app.js": expressSrc}
	r := analyzeIn(t, files, npmVuln("unused-lib"))
	if r.Status != ReachUnreachable || r.RuleID != "REACH-001" {
		t.Fatalf("Status=%v RuleID=%s, want unreachable REACH-001 (reason: %s)", r.Status, r.RuleID, r.Reason)
	}
	if !strings.Contains(r.Reason, "not reachable from any imported package") {
		t.Errorf("reason %q does not say what was established", r.Reason)
	}
}

// Nested resolution: qs under body-parser/node_modules is a different instance
// than the hoisted qs; either is reached, but a node_modules instance nobody
// depends on is not.
func TestNestedResolutionFollowsNodeSemantics(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{
 "":{"name":"app"},
 "node_modules/a":{"version":"1.0.0","dependencies":{"b":"1"}},
 "node_modules/a/node_modules/b":{"version":"1.0.0","dependencies":{"c":"1"}},
 "node_modules/c":{"version":"1.0.0"},
 "node_modules/orphan/node_modules/c":{"version":"0.1.0"},
 "node_modules/orphan":{"version":"1.0.0"}}}`
	files := map[string]string{"package-lock.json": lock, "i.js": `require('a')`}
	r := analyzeIn(t, files, npmVuln("c"))
	if r.Status != ReachReachable || r.Evidence != "a -> b -> c" {
		t.Fatalf("Status=%v evidence=%q, want reachable via a -> b -> c", r.Status, r.Evidence)
	}
	if r := analyzeIn(t, files, npmVuln("orphan")); r.Status != ReachUnreachable {
		t.Errorf("orphan: Status=%v, want unreachable (reason: %s)", r.Status, r.Reason)
	}
}

// Dev-only may be said, but only on the lockfile's evidence.
func TestDevOnlyNeedsLockfileEvidence(t *testing.T) {
	files := map[string]string{"package-lock.json": npmLockV3, "src/app.js": expressSrc}
	r := analyzeIn(t, files, npmVuln("jest-util"))
	if r.Status != ReachUnreachable || !strings.Contains(r.Reason, "development-only dependency") ||
		!strings.Contains(r.Reason, "dev: true") {
		t.Fatalf("Status=%v reason=%q, want a dev-only unreachable verdict citing dev: true", r.Status, r.Reason)
	}
	// unused-lib is not dev:true, so it must not be called dev-only.
	if r := analyzeIn(t, files, npmVuln("unused-lib")); strings.Contains(r.Reason, "development-only") {
		t.Errorf("unused-lib labelled dev-only without evidence: %q", r.Reason)
	}
}

// "Could not determine" is the default whenever the graph cannot settle it.
func TestUndeterminedWhenGraphCannotSettleIt(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		vuln  *VulnInfo
		want  string
	}{
		{"no lockfile", map[string]string{"src/app.js": expressSrc, "package.json": `{}`},
			&VulnInfo{Package: "qs", Ecosystem: "npm", File: "package.json"}, "no lockfile"},
		{"unparseable lockfile", map[string]string{"package-lock.json": `{not json`, "src/app.js": expressSrc},
			npmVuln("qs"), "could not be read"},
		{"package absent from lockfile", map[string]string{"package-lock.json": npmLockV3, "src/app.js": expressSrc},
			npmVuln("ghost"), "not recorded in package-lock.json"},
		{"dangling edge", map[string]string{"src/app.js": `require('a')`, "package-lock.json": `{"lockfileVersion":3,"packages":{
 "":{},"node_modules/a":{"version":"1","dependencies":{"missing":"1"}},"node_modules/z":{"version":"1"}}}`},
			npmVuln("z"), "cannot be concluded"},
		{"no graph for ecosystem", map[string]string{"A.java": `import org.foo.bar.Baz;`},
			&VulnInfo{Package: "org.x:y", Ecosystem: "maven", File: "pom.xml"}, "no dependency graph is read"},
		{"declaring file outside workspace", map[string]string{"src/app.js": expressSrc},
			&VulnInfo{Package: "qs", Ecosystem: "npm", File: "../../etc/package-lock.json"}, "outside the workspace"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := analyzeIn(t, tc.files, tc.vuln)
			if r.Status != ReachUndetermined || r.RuleID != "REACH-003" {
				t.Fatalf("Status=%v RuleID=%s, want undetermined REACH-003 (reason: %s)", r.Status, r.RuleID, r.Reason)
			}
			if !strings.Contains(r.Reason, tc.want) {
				t.Errorf("reason %q does not contain %q", r.Reason, tc.want)
			}
		})
	}
}

// Without any graph source the answer is undetermined, not unreachable.
func TestNilGraphSourceNeverRefutes(t *testing.T) {
	imports := NewImportSet()
	imports.Add(EcosystemNPM, "express")
	r := importResult(&VulnInfo{Package: "qs", Ecosystem: "npm"}, imports, nil)
	if r.Status != ReachUndetermined {
		t.Fatalf("Status=%v, want undetermined", r.Status)
	}
}

// Every lockfile format must report the same thing for the same tree:
// app imports a; a -> b -> c; solo is installed but depends on nothing imported.
func TestTransitiveAcrossLockfileFormats(t *testing.T) {
	cases := []struct {
		name, file, body, src, eco, pkg, solo string
		chain                                 string
	}{
		{"npm v1", "package-lock.json", `{"lockfileVersion":1,"dependencies":{
 "a":{"version":"1","requires":{"b":"1"},"dependencies":{"b":{"version":"1","requires":{"c":"1"}}}},
 "c":{"version":"1"},"solo":{"version":"1"}}}`, `require('a')`, "npm", "c", "solo", "a -> b -> c"},
		{"yarn classic", "yarn.lock", "# yarn lockfile v1\n\na@^1.0.0:\n  version \"1.0.0\"\n  dependencies:\n    b \"^1.0.0\"\n\nb@^1.0.0:\n  version \"1.0.0\"\n  dependencies:\n    c \"^1.0.0\"\n\nc@^1.0.0:\n  version \"1.0.0\"\n\n\"solo@^1.0.0\", solo@^1.1.0:\n  version \"1.1.0\"\n",
			`require('a')`, "npm", "c", "solo", "a -> b -> c"},
		{"yarn berry", "yarn.lock", "__metadata:\n  version: 6\n\n\"a@npm:^1.0.0\":\n  version: 1.0.0\n  dependencies:\n    b: ^1.0.0\n\n\"b@npm:^1.0.0\":\n  version: 1.0.0\n  dependencies:\n    c: ^1.0.0\n\n\"c@npm:^1.0.0\":\n  version: 1.0.0\n\n\"solo@npm:^1.0.0\":\n  version: 1.0.0\n",
			`require('a')`, "npm", "c", "solo", "a -> b -> c"},
		{"pnpm v9", "pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  a@1.0.0: {}\n  b@1.0.0: {}\n  c@1.0.0: {}\n  solo@1.0.0: {}\nsnapshots:\n  a@1.0.0:\n    dependencies:\n      b: 1.0.0\n  b@1.0.0(peer@1.0.0):\n    dependencies:\n      c: 1.0.0\n  c@1.0.0: {}\n  solo@1.0.0: {}\n",
			`require('a')`, "npm", "c", "solo", "a -> b -> c"},
		{"pnpm v6", "pnpm-lock.yaml", "lockfileVersion: '6.0'\npackages:\n  /a@1.0.0:\n    dependencies:\n      b: 1.0.0\n  /b@1.0.0:\n    dependencies:\n      c: 1.0.0\n  /c@1.0.0: {}\n  /solo@1.0.0: {}\n",
			`require('a')`, "npm", "c", "solo", "a -> b -> c"},
		{"cargo", "Cargo.lock", "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\ndependencies = [\n \"b 1.0.0 (registry+https://x)\",\n]\n\n[[package]]\nname = \"b\"\nversion = \"1.0.0\"\ndependencies = [\n \"c\",\n]\n\n[[package]]\nname = \"c\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"solo\"\nversion = \"1.0.0\"\n",
			"use a::run;", "crates.io", "c", "solo", "a -> b -> c"},
		{"gemfile", "Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    a (1.0)\n      b (~> 1.0)\n    b (1.0)\n      c\n    c (1.0)\n    solo (1.0)\n\nPLATFORMS\n  ruby\n",
			"require 'a'", "RubyGems", "c", "solo", "a -> b -> c"},
		{"poetry", "poetry.lock", "[[package]]\nname = \"a\"\nversion = \"1.0\"\n\n[package.dependencies]\nb = \">=1\"\n\n[[package]]\nname = \"b\"\nversion = \"1.0\"\n\n[package.dependencies]\nc = \"*\"\n\n[[package]]\nname = \"c\"\nversion = \"1.0\"\n\n[[package]]\nname = \"solo\"\nversion = \"1.0\"\n",
			"import a\n", "PyPI", "c", "solo", "a -> b -> c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := map[string]string{"crates.io": "lib.rs", "RubyGems": "app.rb", "PyPI": "app.py"}[tc.eco]
			if src == "" {
				src = "app.js"
			}
			files := map[string]string{tc.file: tc.body, src: tc.src}
			r := analyzeIn(t, files, &VulnInfo{Package: tc.pkg, Ecosystem: tc.eco, File: tc.file})
			if r.Status != ReachReachable || r.Evidence != tc.chain {
				t.Fatalf("%s: Status=%v evidence=%q, want reachable via %q (reason: %s)", tc.pkg, r.Status, r.Evidence, tc.chain, r.Reason)
			}
			r = analyzeIn(t, files, &VulnInfo{Package: tc.solo, Ecosystem: tc.eco, File: tc.file})
			if r.Status != ReachUnreachable {
				t.Fatalf("%s: Status=%v, want unreachable (reason: %s)", tc.solo, r.Status, r.Reason)
			}
		})
	}
}

// The graph is read beside the file that declares the dependency, so two
// projects in one workspace do not share a graph.
func TestGraphIsReadBesideTheDeclaringFile(t *testing.T) {
	files := map[string]string{
		"svc/package-lock.json": npmLockV3,
		"svc/src/app.js":        expressSrc,
	}
	v := &VulnInfo{Package: "qs", Ecosystem: "npm", File: "svc/package-lock.json"}
	if r := analyzeIn(t, files, v); r.Status != ReachReachable {
		t.Fatalf("Status=%v, want reachable (reason: %s)", r.Status, r.Reason)
	}
}
