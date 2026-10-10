# Open-Source De-Risking Pipeline

> ### 📢 The Architectural Strategy
> This repository documents a self-directed architectural deep dive into how the adoption of an open-source framework
> could be de-risked. The core focus centres on the identification of confirmed vulnerabilities, distinguishing
> inherited and introduced security debt, and flagging structural risks during development.

## 🔬 The Scope
Functioning as a build-time security guardrail, my pipeline's role is to enforce that no structural risks introduced
by external modules remain hidden before deployment.

It is deliberately constrained to vulnerabilities originating from third-party dependencies. Grounding my analysis to
CVE data provides me a verified baseline and directly addresses weaknesses of static analysis such as high numbers of
false positives.

### Role in the Security Ecosystem
Inherited debt is not static.

Open-source frameworks often provide components and UIs that can be used to build on top of it. If an extension is
built using inherently vulnerable files, the project's security debt will grow beyond what was initially inherited.

My pipeline will operate purely within CI, using static analysis to map out a system's potential vulnerabilities and
provide visibility on the growth of security debt.

By evaluating both the framework's core modules and new additions at each commit, the pipelines become a ledger of
exactly what security debt is being inherited, what debt is being compounded and what risks are being introduced.

---

## 🛠️ System & Pipeline Architecture
My project forks the [EverShop](https://github.com/evershopcommerce/evershop)
repository.

The EverShop framework provides core modules to help anyone create a highly customisable e-commerce platform and serves
as a real-world benchmark to evaluate the effectiveness of my pipeline.

### Pipeline structure
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
[ 3. PARSE FILE GRAPH ]
Indirect usages are identified at the component-use level.
              │
              ▼
[ 4. MAP TO VULNERABLE DEPENDENCIES ]
The external references found are mapped to the list of vulnerable packages.
              │
              ▼
[ 5. VULNERABILITY CLASSIFICATION ]
Dependency vulnerabilities are classified, with the growth of these classifications
providing visibility on the project's security debt and where they originate from.
```

👉 **To view my design decisions in-depth, view the** [Reachability Pipeline Architecture Runbook](./ARCHITECTURE_RUNBOOK.md).