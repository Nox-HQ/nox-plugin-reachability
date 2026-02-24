# nox-plugin-reachability

Import-based reachability analysis plugin for [Nox](https://github.com/nox-hq/nox).

## Overview

Classifies VULN findings as reachable, unreachable, or undetermined by cross-referencing vulnerable packages against actual import statements in the codebase. Supports Go, Python, and JavaScript/TypeScript ecosystems.

## Tools

- **analyze_reachability** — Classify VULN findings based on import analysis

## Rules

| ID | Description | Severity |
|----|-------------|----------|
| REACH-001 | Vulnerable package is NOT imported — likely false positive | Info |
| REACH-002 | Vulnerable package IS imported — confirmed risk | High |
| REACH-003 | Cannot determine reachability — unsupported ecosystem | Low |

## Build

```bash
make build
make test
make lint
```

## License

Apache-2.0
