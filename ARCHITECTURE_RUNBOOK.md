# 📓 Architecture Runbook: Verifiable AppSec

This document serves as the chronological engineering ledger for this project. It details my validation-first approach
to designing this security pipeline, key design considerations and how I implemented my solution.

---

## 📍 Phase 1: Thinking About the Result

### The Objective
An analysis engine cannot safely grade its own homework. Moreover, EverShop uses a unique architecture that orchestrates
its own compilation loops behind the scenes, increasing the likelihood of data mapping errors in any implementation.

In addition, ambiguous code patterns (like dynamic strings inside a `require()` call) makes reachability analysis
non-deterministic. The reachability resolver would need to route such instances into a `WARNING` state to protect
the integrity of the pass/fail gates while isolating edge cases for explicit human review.

### The Invariant Matrix
To address the risks associated with EverShop's architecture as well as ensuring any implementation is producing
accurate results, I designed a safety net that is built on the following principles:

-   **Inclusion (reachable):** If a file is flagged as live risk, it must actively exist in the compiled asset graph.
-   **Completeness (anti-bypass):** Every source file bundled by the compiler must have an explicit evaluation state.
    The engine cannot silently ignore compiled files.

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
-   **Definitive scoping:** Using compiler telemetry, a definitive search space for reachable
    vulnerabilities can be defined.
-   **Environment-agnostic routing:** By validating files based on what the compilers actually did with them, the
    validator gracefully handles mixed, full-stack directories.

## 📍 Phase 2: Resolving Reachable Vulnerabilities


