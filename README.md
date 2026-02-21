# 🛰️  OpenSec | Process mitigation auditing tool for OpenBSD.

OpenSec is an experimental auditing tool for OpenBSD that inspects process state via kvm(3) and struct kinfo_proc to determine whether pledge(2), unveil(2), and W^X protections are active.

It is intended for study, inspection, and system hardening analysis.

![License](https://img.shields.io/badge/license-MIT-green) ![Platform](https://img.shields.io/badge/platform-OpenBSD-yellow) ![Language](https://img.shields.io/badge/language-C-blue)

---

## 🔍 Overview

OpenSec reports mitigation state of running processes on OpenBSD by inspecting kernel-exposed metadata.

## 🔧 How It Works

OpenSec uses libkvm to read kernel process tables and evaluate fields within struct kinfo_proc. The tool does not modify kernel memory and operates strictly in read-only mode.

The tool evaluates:

- Whether pledge(2) restrictions are active
- Whether unveil(2) restrictions are present
- Indicators related to W^X enforcement

Classification is based exclusively on kernel-exposed state.
No syscall tracing, binary instrumentation, or static analysis is performed.

## 🧠 Design Philosophy

OpenSec adheres to a strict non-intrusive inspection model:

- No runtime instrumentation
- No binary rewriting
- No ptrace attachment
- Read-only kernel state inspection

The objective is deterministic classification based solely on kernel state.

## ⚠️  Limitations

- Relies exclusively on kernel-exposed metadata
- Does not infer intent or runtime behavior
- Cannot detect logic flaws inside pledged binaries

---

## 📸 Project in Action

![Initial Scan](./Imagens/opensec1.png)
*Figure 1: Automated baseline evaluation of the global security posture.*

![Mitigation Analysis](./Imagens/opensec2.png)
*Figure 2: Real-time monitoring of active security primitives and privilege levels.*

![Forensic Summary](./Imagens/opensec3.png)
*Figure 3: Forensic audit reporting with global mitigation statistics and risk assessment.*

---

## 🧩 Features

- Kernel process table inspection via libkvm
- pledge(2) and unveil(2) state reporting
- W^X-related enforcement indicators
- Userland vs kernel process differentiation

#### Color Legend (Standard Interpretation):
* **🟢 GREEN (ACTIVE):** Mitigation is strictly enforced by the kernel (Pledged/Unveiled).
* **🔴 RED (NONE):** No mitigation detected (Critical attack surface).
* **🔵 BLUE / 🟣 PURPLE (NATIVE):** Standard userland process context.
* **🟣 PURPLE / 💗 PINK (KERNEL):** Core system entity or kernel thread (e.g., PID 1 `init`).

> **🎨 Developer Note:** During validation on **Kitty** and **xfce4-terminal**, we observed that color shades vary (e.g., Pink vs Magenta) based on the terminal's ANSI palette. See [SECURITY_MODEL.md](./docs/SECURITY_MODEL.md) for details.

### ⚙️  Operational Integrity
OpenSec is built for systems where security and stability are inseparable:
* **Passive Observation:** Unlike intrusive debuggers, OpenSec reads kernel state without interrupting process execution.
* **Architectural Precision:** Designed specifically for OpenBSD’s process and memory model.

### 🕵️  Investigation Workflow
When OpenSec flags a critical process with **NONE** status, use native OpenBSD tools for deep analysis:
* **Syscall Audit:** `ktrace -p [PID] && kdump` (Analyze missing pledge(2) calls).
* **File Access:** `fstat -p [PID]` (Check descriptors accessed outside of an unveil(2) scope).
* **Memory Flags:** `vmstat -m` (Inspect global memory allocation patterns).

---

## 📦 Deployment

### Prerequisites
* **OS:** OpenBSD (Current/Stable)
* **Privileges:** Access to `/dev/mem` (requires `doas` or `root`)

### Build & Run
```bash
# Clone the repository
git clone https://github.com/jeffersoncesarantunes/OpenSec.git
cd OpenSec

# Compile and execute
make clean && make
doas ./bin/opensec
```
## 💻 Tech Stack

| Component | Technology |
| :--- | :--- |
| **Language** | C (C99/C11) with OpenBSD Extensions |
| **Interface** | libkvm (Kernel Data Access Library) |
| **Build Tool** | BSD Make |
| **Security Focus** | Pledge / Unveil / W^X |

## 🗺️  Roadmap

- [x] Kernel-level mitigation detection engine
- [x] Process-type differentiation (Native vs Kernel)
- [ ] Structured export (CSV/JSON) for compliance reporting
- [ ] Interactive TUI for real-time process monitoring
- [ ] Per-process mitigation history logging

---

## 📚 Technical Documentation

For in-depth information on security theory, performance, and forensic procedures, refer to our specialized guides:

* **[Security Model & Forensic Workflow](./docs/SECURITY_MODEL.md)**: A deep dive into the formal threat model, `libkvm` data integrity, and the step-by-step investigation path using `ktrace` and `fstat`.
* **[Performance Benchmarks](./docs/BENCHMARKS.md)**: Empirical data on CPU/RAM usage, scalability tests, and instructions on preventing system freezes via the **"Action Required"** selection.

---

## 📄 License

Distributed under the **MIT License**. Built for the security-conscious OpenBSD community.

---
*Because in OpenBSD, we don't just trust—we verify.*
