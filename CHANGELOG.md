# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Symbol-level Go reachability** — Go advisories are now answered by
  `golang.org/x/vuln` (the library behind `govulncheck`), used in-process
  rather than by shelling out to a binary the operator may not have. The
  verdict is whether the *vulnerable symbol* is called: `REACH-002` when the
  call graph reaches it (with the call path attached as `call_path`),
  `REACH-001` when the module is in the build graph but no vulnerable symbol
  is called. Advisory ids are mapped through the aliases the scan reports, so
  GHSA- and CVE-identified findings resolve to the GO ids the Go database
  issues. Analysis is bounded by a timeout and degrades to `REACH-003` on
  overrun.
- **`method` and `reason` metadata** on every REACH finding and enrichment.
  `method` distinguishes a call-graph verdict (`symbol`) from an import-text
  one (`import`); `reason` states why the verdict was reached.

### Fixed

- **Every ecosystem except npm was silently unsupported.** nox tags VULN
  findings with its own internal ecosystem names (`go`, `pypi`, `cargo`,
  `maven`, `rubygems`, `nuget`) and only converts to OSV's spellings when it
  queries OSV.dev. This plugin matched on OSV's spellings (`Go`, `PyPI`,
  `crates.io`, …), so only `npm` — spelled identically in both — ever
  resolved. Everything else fell through to `REACH-003 … unsupported
  ecosystem go`, which reads like an analysis result but meant the analysis
  never ran. Ecosystem labels are now canonicalised before dispatch.
- **`REACH-003` no longer always blames the ecosystem.** The message carries
  the actual reason: no `go.mod` at the target, the module could not be
  loaded, the analysis exceeded its budget, or the advisory id could not be
  mapped to the Go vulnerability database.

### Changed

- Go import extraction was removed. It parsed every `.go` file in a workspace
  to answer a question nothing asks any more — module presence is not
  reachability, and Go is now decided by the call graph.

## [0.7.0] - 2026-07-18

### Added

- **Multi-language reachability** — import extraction for Rust (`use foo::`),
  Java (import statements collapsed to top-three segments), Ruby (`require` /
  `require_relative`) and C# (`using`), plus package-name normalisation for
  those ecosystems.
- **Documented precision class per language**, so a `REACH-00x` annotation is
  interpretable: Go is AST-based (class A); PyPI, npm, Cargo and RubyGems are
  regex-based (class B); Maven collapses import statements and over-reports
  (class C).

### Changed

- Build output is now ignored when walking a workspace — `target` (Rust),
  `.gradle`, `build`, `dist`, `bin`, `obj` (.NET). These were walked
  needlessly and could produce bogus reachability signal.

> This release reconciles work that had accumulated only in nox's `plugins/`
> directory, where a second copy of this plugin lived. nox bundles this plugin
> into its release archive; from nox's next release it sources the **published**
> module rather than that in-tree copy, so the bundled and standalone binaries
> are the same artifact.

## [0.1.0] - 2026-02-24

### Added
- Initial reachability plugin with import-based analysis
- 1 tool: analyze_reachability
- 3 rules (REACH-001 through REACH-003)
- Go import extraction via go/parser AST
- Python and JavaScript/TypeScript regex-based import extraction
- PyPI package name mapping (Pillow→PIL, scikit-learn→sklearn, etc.)
- SDK conformance and track conformance tests
- CI/CD, lint config, pre-commit hooks
