# Dependency Vulnerability Reachability Pipeline

> ## 📢 The Architectural Strategy
> This repository documents a self-directed architectural deep dive into reachability-driven vulnerability detection.
> The core focus centres on a single engineering challenge: how to design a pipeline that maps application execution
> flows across a production codebase, explicitly separating active runtime exposure from dead code.

## 🔬 The Scope
To clearly defining what execution flows I am analysing, this project is intentionally constrained to
third-party dependency vulnerabilities. Focusing on public dependencies grounds the search space to known CVE data,
enabling the project to focus on reachability while allowing the system to validate its logic against actual risk.

### What This Pipeline Measures
This project focuses on a practical, real-world distinction: the difference between code sitting on disk and code that
actually ships to production.

- **Reachable code:** The dependency is actively imported, processed by the compiler and bundled into the
  final production assets. If it contains a vulnerability, that flaw is live and exposed.
- **Dead code:** The dependency is declared in the project but the compiler completely strips it out during compilation.
  Because it never makes it into the production bundle, it can never execute.

This pipeline intercepts the compiler to provide clear visibility into whether a vulnerable piece of code was
safely eliminated as dead weight or if it successfully made its way into the final application bundle.

------------------------------

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