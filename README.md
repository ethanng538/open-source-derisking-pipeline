# Dependency Vulnerability Reachability Pipeline

> ## 📢 The Architectural Strategy
> This repository documents a self-directed architectural deep dive into reachability-driven vulnerability detection.
> The core focus centres on a single engineering challenge: how to design a pipeline that maps application execution
> flows across a production codebase, explicitly separating active runtime exposure from dead code.

## 🔬 The Scope
To maintain technical accuracy, this project is intentionally constrained to third-party dependency vulnerabilities.

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
My projects forks the [EverShop](https://github.com/evershopcommerce/evershop) repository to provide a real-world
baseline for my pipeline.



👉 **To inspect the custom validation scripts, read the real execution telemetry records or review the step-by-step
pipeline logging outputs, view the** [Reachability Pipeline Architecture Runbook](./ARCHITECTURE_RUNBOOK.md).