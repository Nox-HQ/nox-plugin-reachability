# nox-plugin-reachability

Reachability analysis plugin for [Nox](https://github.com/nox-hq/nox).

## Overview

Classifies VULN findings as reachable, unreachable, or undetermined.

**Go** is analysed at symbol level with [`golang.org/x/vuln`](https://pkg.go.dev/golang.org/x/vuln)
— the library behind `govulncheck`, used in-process rather than by shelling
out to a binary the operator may not have installed. The question it answers
is whether the *vulnerable symbol* is called, not whether the module is
present: a module can sit in the build graph while none of the code an
advisory names is ever reached, and that distinction is the whole point of
reachability analysis.

**Every other ecosystem** is analysed by scanning import statements, which can
only observe that a package name appears in source.

## Tools

- **analyze_reachability** — Classify VULN findings by reachability

## Rules

| ID | Description | Severity |
|----|-------------|----------|
| REACH-001 | Not reachable — the vulnerable symbol is never called (Go), or the package is not imported | Info |
| REACH-002 | Reachable — the vulnerable symbol is called (Go), or the package is imported | High |
| REACH-003 | No verdict could be established; the finding's `reason` says why | Low |

`REACH-003` is not a synonym for "unsupported ecosystem". It is also what you
get when the target has no `go.mod`, the module will not load, the analysis
overran its budget, or the advisory id could not be mapped to the Go
vulnerability database. Every `REACH-003` carries the actual reason.

## Metadata

Each finding and enrichment carries:

| Key | Meaning |
|-----|---------|
| `reachable` | `true`, `false`, or `undetermined` |
| `method` | `symbol` (call-graph analysis) or `import` (import scanning) |
| `reason` | Why this verdict was reached |
| `call_path` | For a reachable Go verdict: the path from this module's code to the vulnerable symbol |

## Precision

Go is call-graph based. The import-scanned ecosystems are best-effort and
documented per extractor: PyPI, npm, Cargo and RubyGems are regex-based
(class B); Maven and NuGet collapse namespaces and over-report (class C).
Over-reporting is the safe direction — it inflates the apparent reachability
set rather than hiding an exploitable path.

## Build

```bash
make build
make test
make lint
```

Tests run the real Go analysis against fixture modules in `testdata`, pointed
at a fixture vulnerability database on disk. They need no network.

## License

Apache-2.0
