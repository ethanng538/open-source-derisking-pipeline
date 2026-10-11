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
Application code is then scanned for direct usage of these vulnerable packages. Files with ambiguous references, that is
files where it is unknown whether it is referencing a vulnerable package, are classified as ambiguous at this stage.

To maintain precision, taint should only occur if a component has actual exposure to a vulnerable package. For example,
a file that defines themed UI components may export two different product displays. Only one of these displays may
actually use the vulnerable package.

By tracking taint at the component level rather than the file level, files and components without actual exposure are
not falsely flagged.

### Tracing Taint
To track indirect usages, all files are scanned to see if they reference a tainted component. If they do, taint is
inherited into the consumer file.

The chains of exposure are also recorded along with whether a file is indirectly exposed to multiple vulnerable
import-to-invocation chains. For example, a menu may take multiple components from other files. If those components
independently carry taint, each chain of exposure is recorded along with the vulnerable packages from each chain.

https://osv.dev/vulnerability/GHSA-jjpr-9cvf-cq55

https://osv.dev/vulnerability/GHSA-6688-9rhm-gjv2

## Product Retrospective

It is a growing trends for teams and organisations to use open-source code to jump-start their development. My deep dive
revealed how visibility can be used to manage risk and inform security decisions throughout development.

What I took away was what could be gained by analysing the code provided by the framework. While not every open-source
framework may have something that provides a dependency graph, it reinforced the importance of carefully considering
the security scope and improved my ability to design bespoke security solutions.