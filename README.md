# Dependency Vulnerability Reachability Pipeline

> ### 📢 The Architectural Strategy
> This repository documents a self-directed architectural deep dive into reachability-driven vulnerability detection.
> The core focus centres on the identification of confirmed risk, de-risking the adoption of open-source code and
> flagging structural risks during development.

## 🔬 The Scope
My pipeline will operate purely within CI, using static analysis to map out a system's potential vulnerabilities
before evaluating whether they pose a confirmed risk.

This pipeline is deliberately constrained to vulnerabilities originating from third-party dependencies. Grounding my
reachability analysis to CVE data provides me a verified baseline and directly addresses weaknesses of static analysis
such as high numbers of false positives.

### Role in the Security Ecosystem
Functioning as a build-time security gate, its role is to enforce that no structural risks introduced
by external modules make it to deployment.

Reachability analysis domains such as dynamic reachability will not be incorporated given that it cannot be
optimally resolved inside a CI pipeline. This maintains an acceptable build time during development and merges while
reducing design drift into evaluating dynamic, build-time traces.

---

## 🛠️ System & Pipeline Architecture
My projects forks the [EverShop](https://github.com/evershopcommerce/evershop) repository to provide a real-world baseline for my pipeline.

The EverShop framework provides core modules to help anyone create a highly customisable e-commerce platform and serves
as a realistic benchmark to evaluate the effectiveness of my pipeline.

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

👉 **To view my design decisions in-depth, view the** [Reachability Pipeline Architecture Runbook](./ARCHITECTURE_RUNBOOK.md).