# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
