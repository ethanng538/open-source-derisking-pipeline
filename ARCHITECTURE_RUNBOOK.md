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
-   **Completeness (Anti-Bypass):** Every source file bundled by the compiler must have an explicit evaluation state. The engine cannot silently ignore files.

### Managing Ambiguity
To address ambiguous code patterns (like dynamic strings inside a `require()` call), the architecture routes them into a
`WARNING` state. This protects the integrity of the pass/fail gates while isolating edge cases for explicit human review.

### Architectural Execution
To implement this cleanly, the validation script must account for the fact that a full-stack framework executes code
across two separate environments.

The validation script handles this by splitting how it processes incoming paths:
-   **Frontend validation:** It matches client-side paths directly against the compiler's output. If a frontend file is
    marked as reachable but is missing from the build, or is muted but actively exists in the build, the pipeline flags
    a logic breach.
-   **Backend isolation:** Server-side controllers and database scripts run directly on the host environment and bypass
    the frontend compiler completely. The safety net isolates these paths to prevent false mismatches, tracking them
    independently through source import chains.
-   **Completeness reverse audit:** To prevent the engine from skipping heavy files to save execution time, the script
    performs a reverse sweep. It verifies that every single shipped frontend file has a corresponding record in
    the analysis payload, killing the pipeline if any deployed asset was skipped.