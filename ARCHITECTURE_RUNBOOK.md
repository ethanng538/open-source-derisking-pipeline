# 📓 Reachability Pipeline Architecture Runbook

This document serves as the chronological engineering ledger for this project. It details key design considerations and
core implementation details without all the loaded jargon.

---

## 📍 Phase 1: Thinking About the Result

### Caveats of Static Analysis and Reachability
Static analysis cannot resolve whether a file is actually reachable, only whether it contains evidence of exposure
should the file, or linked files, be executed.

The evaluation of a vulnerability should not only depend on whether it is executed either: a vulnerability that may be
unreachable at present may become active the moment a new execution path touches the file.

Consequently, analysing for structural risks necessitates a strategy that ensures visibility of all potential
vulnerabilities is maintained while providing the necessary precision to reduce alert fatigue.

### Leveraging the Framework
A [software bill of materials](https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity/software-supply-chain-security-guidance-20)
(SBOM) is the software equivalent of a shipping manifest: it contains details such as whether a file requires a
component from another and much more, with a [dependency graph](https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html)
acting as the underlying structure that records these relationships.

Perusing the EverShop framework for details relevant to a build-time guardrail, I found that it uses [webpack](https://webpack.js.org/concepts/dependency-graph/)
as the primary driver of its compilation process. [webpack natively builds a dependency graph](https://webpack.js.org/concepts/dependency-graph/)
but this graph does not show the granularity required for vulnerability detection. However, what it does contain is
information about which files are compiled.

### The Pipeline Output
The dependency graph enables files to receive human-readable classifications:
-   `CONFIRMED`: The file references an external module with active CVEs and the file is compiled during the build process.
-   `LIABLE`: The file references, directly or indirectly, an external module with active CVEs.
-   `AMBIGUOUS:` The file references an external module whose source is ambiguous and needs human triage to determine
    the presence of a vulnerability.

The EverShop framework provides many UI components and APIs that can be used when making an extension.
These classifications provide the visibility to see pre-existing vulnerabilities while also flagging if the use of one
of these assets results in a vulnerable file getting compiled.

## 📍 Phase 2: Finding Potential Vulnerabilities

import-and-invocation chain

- Checks if imports are actually used
- Checks if the components or functions that use the vulnerable imports have actual usage
- Actual usage means the file itself will be structurally included by EverShop or if another file that will be included
  references the file using the vulnerability

### Leveraging AST analysis
Unused imports are pruned at this stage.

### Producing the Initial Search Space

## 📍 Phase 3: Pipeline Tests

## Product Retrospective