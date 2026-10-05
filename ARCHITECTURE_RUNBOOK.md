# 📓 Architecture Runbook: Verifiable AppSec

This document serves as the chronological engineering ledger for this project. It details my validation-first approach
to designing my security pipeline, key design considerations and core implementation details.

---

## 📍 Phase 1: Thinking About the Result

### The Objective
An analysis engine cannot safely grade its own homework, meaning there must exist a separate process that evaluates the
accuracy of any reachability results. Moreover, EverShop uses a unique architecture that orchestrates its own
compilation loops behind the scenes, increasing the likelihood of data mapping errors in any implementation.

### The Invariant Matrix
When considering the output of a reachability analysis in the context of third-party dependencies, a file would receive
one of the following states:
-   `REACHABLE`: The file references an external module that introduces an accessible and exploitable
    vulnerability.
-   `MUTED`: The file references an external module that contains a vulnerability but the flaw cannot be accessed or
    exploited.
-   `AMBIGUOUS:` The file references an external module whose source is ambiguous.
-   `SAFE`: The file does not reference external modules with active CVEs.

To address the risks associated with EverShop's architecture as well as ensuring any implementation is producing
accurate results, I designed a safety net that is built on the following principles:

-   **Inclusion:** If a file is flagged as `REACHABLE`, it must be a file that was compiled.
-   **Completeness:** Every source file flagged as potentially containing a vulnerability and bundled by the compiler
    must have an explicit evaluation state.
-   **Causality:** If it is known the project uses a third-party dependency that contains a vulnerability, there
    must be non-zero `REACHABLE` or `MUTED` records flagged by the engine.

### Architectural Execution
Given EverShop's ["Modular Monolith" architecture](https://evershop.io/docs/development/knowledge-base/architecture-overview "EverShop Architecture Overview"),
there is no easy directory split between frontend and backend files. Client-side views and server-side logic are
encapsulated together inside the directories.

We must accurately handle these two worlds because they execute under entirely different processes:
-   **The Frontend Reality:** Client-side files go through compiler optimisation. If a frontend dependency isn't
    explicitly imported, the compiler completely strips it out (tree-shaking). Code not part of the tree physically
    cannot execute.
-   **The Backend Reality:** Server-side scripts run natively on the host. They are often triggered dynamically by
    incoming network routes or internal events rather than direct import statements. A backend vulnerability can be
    actively exposed and executable even if it appears completely detached from the main import tree.

To address these considerations, telemetry hooks were non-intrusively placed within EverShop's compilation loops, using
the compiler's own metadata to explicitly map web and node infrastructure:
-   **Search space definition:** Using compiler telemetry, it can be definitively determined whether a file was
    compiled.
-   **Environment-agnostic routing:** By validating files based on what the compilers actually did with them, the
    validator gracefully handles mixed, full-stack directories.

## 📍 Phase 2: Finding Potential Vulnerabilities

### Leveraging AST analysis
AST tools deterministically know the meanings of code statements.

### Producing the Initial Search Space


## 📍 Phase 3: Evaluating for Reachability

import-and-invocation chain

- Checks if imports are actually used
- Checks if the components or functions that use the vulnerable imports have actual usage
- Actual usage means the file itself will be structurally included by EverShop or if another file that will be included
  references the file using the vulnerability

## Product Retrospective