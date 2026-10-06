# Dependency Vulnerability Reachability Pipeline

> ## 📢 The Architectural Strategy
> This repository documents a self-directed architectural deep dive into reachability-driven vulnerability detection.
> The core focus centres on distinguishing between active risk and dormant vulnerabilities, analysing whether a flagged
> external module actually executes or sits inactive in the codebase.

## 🔬 The Scope
This pipeline is strictly constrained to known, publicly documented third-party dependency vulnerabilities (CVEs) to
establish a deterministic control group for validating reachability logic.

### Role in the Security Ecosystem
This pipeline operates strictly as a build-time gate. Its role is to enforce that no structural risks introduced
by external modules make it to deployment.

Reachability analysis domains such as dynamic reachability will not be incorporated given that it cannot be
optimally resolved inside a CI/CD pipeline. This maintains an acceptable build time while reducing design drift into
evaluating dynamic, build-time traces.

---

## 🛠️ System & Pipeline Architecture
My projects forks the [EverShop](https://github.com/evershopcommerce/evershop) repository to provide a real-world baseline for my pipeline. Using a modern tech
stack and an API that unifies both admin and storefront operations, it acts as a realistic benchmark to evaluate my
project outcomes.

The structure of my pipeline is as follows:
```text
[ 1. EXTRACT MANIFEST VULNERABILITIES ]
A list of vulnerable packages are extracted from the project's third-party dependencies.
              │
              ▼
[ 2. EXTRACT FILE DEPENDENCIES ]
Abstract Syntax Tree (AST) analysis is used to collate all external references used in
application code.
              │
              ▼        
[ 3. MAPPING TO VULNERABLE DEPENDENCIES ]
The external references found are mapped to the list of vulnerable packages.
              │
              ▼
[ 4. REACHABILITY RESOLUTION ]
The dependency vulnerability mappings are analysed for reachability.
              │
              ▼
[ 5. SAFETY NET ENFORCEMENT ]
Strict compliance gates are used to verify the system's output,
blocking the build if data contradictions or insufficient coverage is found.
```

👉 **To inspect the custom validation scripts, read the real execution telemetry records or review the step-by-step
pipeline logging outputs, view the** [Reachability Pipeline Architecture Runbook](./ARCHITECTURE_RUNBOOK.md).