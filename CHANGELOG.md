# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
