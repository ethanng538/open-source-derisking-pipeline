# 📓 Architecture Runbook

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

Changes in member size of each classification can then be used to provide insights on the risk profile of the project.
For example, if the number of `LIABLE` files go down but there is an equal increase in number of `CONFIRMED` files,
it indicates that a change had caused a certain number of vulnerable files, that were potentially unused, to being
compiled.

## 📍 Phase 2: Finding Potential Vulnerabilities

### The Objective
Find vulnerable files, not just identify vulnerable packages, and produce a report that is high in precision and
low in noise.

### Identifying Tainted Elements
The vulnerable packages are identified by comparing the project's dependencies against a public vulnerability database.
Application code is then scanned for direct usage of these vulnerable packages.

However, taint is established at the file level. Instead, abstract syntax tree (AST) analysis is used to taint only the
components that invoke the vulnerable package(s).

- Vulnerable packages are identified
- Files that directly use these packages are identified
- Import-and-invocation chains are discovered
- This means if a file has, say, two exported components, but only one of those components use the vulnerable package,
  only files that use the vulnerable package have indirect exposure

### Tracing Taint


## Product Retrospective

