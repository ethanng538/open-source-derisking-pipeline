# 📓 Reachability Pipeline Architecture Runbook

This document serves as the chronological engineering ledger for this project. It details my validation-first approach
to designing my security pipeline, key design considerations and core implementation details.

---

## 📍 Phase 1: Thinking About the Result

### The Objective
Static analysis cannot resolve whether a file is actually reachable, only whether it contains evidence of exposure
should the file, or linked files, be executed. The evaluation of a vulnerability should not just be whether it is executed either: a vulnerability that may be
unreachable at present may become active the moment a new execution path touches the file.

However, this does not mean you cannot extract more meaningful information besides the presence of a
potential vulnerability. The EverShop framework uses Webpack as part of its hybrid compilation process, meaning I can
use telemetry from Webpack to guarantee whether a certain subset of frontend and backend files are bundled.

### The Potential States
When considering the outcome of any analysis in our scope, a file would be in one of the following states:
-   `BUNDLED`: The file references an external module with active CVEs and the file is bundled during the build process.
-   `LIABLE`: The file references, directly or indirectly, an external module with active CVEs.
-   `AMBIGUOUS:` The file references an external module whose source is ambiguous.
-   `SAFE`: The file does not reference, directly or indirectly, external modules with active CVEs.

This enables any team see which vulnerabilities in EverShop's core modules that are definitely bundled, increasing
visibility on the attack surface before intensive development begins. 

## 📍 Phase 2: Finding Potential Vulnerabilities

### Leveraging AST analysis
Unused imports are pruned at this stage.

### Producing the Initial Search Space


## 📍 Phase 3: Evaluating for Reachability

import-and-invocation chain

- Checks if imports are actually used
- Checks if the components or functions that use the vulnerable imports have actual usage
- Actual usage means the file itself will be structurally included by EverShop or if another file that will be included
  references the file using the vulnerability

## Product Retrospective