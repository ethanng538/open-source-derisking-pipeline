# 📓 Architecture Runbook: Verifiable AppSec

This document serves as the chronological engineering ledger for this project. It details my validation-first approach
to designing this security pipeline, key design considerations and how I implemented my solution.

---

## 📍 Phase 1: Thinking About the Result

### The Objective
An analysis engine cannot safely grade its own homework. Moreover, EverShop uses a unique architecture that orchestrates
its own compilation loops behind the scenes, increasing the likelihood of data mapping errors in any implementation.

### The Invariant Matrix
To address the risks associated with EverShop's architecture as well as ensuring any implementation is producing
accurate results, I designed a safety net that is built on the following principles:

-   **Inclusion (Reachable):** If a file is flagged as live risk, it must actively exist in the compiled asset graph.
-   **Exclusion (Muted):** If a file is flagged as dead code, it must be absent from the compiled asset graph. If it is present, the dead-code logic has failed.
-   **Completeness (Anti-bypass):** Every source file bundled by the compiler must have an explicit evaluation state. The engine cannot silently ignore files.

### Managing Ambiguity
To address ambiguous code patterns (like dynamic strings inside a `require()` call), the architecture routes them into a
`WARNING` state. This protects the integrity of the pass/fail gates while isolating edge cases for explicit human review.

### Architectural Execution
Given EverShop's ["Modular Monolith" architecture](https://evershop.io/docs/development/knowledge-base/architecture-overview "EverShop Architecture Overview"),
there is no easy directory split between frontend and backend files. Client-side views and server-side logic are
encapsulated together inside the directories.

We must accurately separate these two worlds because they execute under entirely different processes:
-   **The Frontend Reality:** Client-side files go through an aggressive compiler optimisation pass. If a
    frontend dependency isn't explicitly imported, the compiler completely strips it out (tree-shaking). It physically
    cannot execute.
-   **The Backend Reality:** Server-side scripts run natively on the host. They are often triggered dynamically by
    incoming network routes or internal events rather than direct import statements. A backend vulnerability can be
    actively exposed and executable even if it appears completely detached from the main import tree.

If the reachability engine treats a backend script like a frontend asset, it will mistakenly assume the code is dead
and let a live server vulnerability pass through undetected. This is why I chose to rely entirely on live compiler
telemetry through three automated checks:
-   **Telemetry graph match:** The script merges the distinct frontend and backend compilation arrays into a single, unified tracking set. If a file is marked as `REACHABLE` but is missing from this active build graph, or is marked as `MUTED` but actively exists inside it, the pipeline flags a logic breach and halts.
-   **Environment-agnostic routing:** By validating files based on what the compilers actually did with them rather than guessing their subsystem context based on folder paths, the pipeline remains completely immune to edge cases caused by mixed full-stack directories.
-   **Completeness reverse-audit:** To prevent the analysis engine from taking shortcuts or skipping heavy modules to save execution time, the script performs a reverse sweep. It verifies that every single file actively bundled by the compiler has a corresponding record in the engine's payload, terminating the pipeline if any deployed asset was bypassed.