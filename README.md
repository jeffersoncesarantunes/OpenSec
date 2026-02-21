# 🛰️ OpenSec | Advanced OpenBSD Security Mitigation Auditor

High-precision forensic tool for auditing **pledge(2)**, **unveil(2)**, and **W^X** enforcement. Validate your system hardening in real-time.

![License](https://img.shields.io/badge/license-MIT-green) ![Platform](https://img.shields.io/badge/platform-OpenBSD-yellow) ![Language](https://img.shields.io/badge/language-C-blue)

---

## 🔍 Overview

**OpenSec** is a specialized security auditor designed for the OpenBSD ecosystem. It interfaces directly with the kernel via `kvm(3)` to monitor the security posture of active processes, pinpointing "naked" binaries that fail to leverage OpenBSD’s native exploit mitigations.

### 🛡️  Core Pillars
* **Kernel-Level Insight:** Leverages `libkvm` to query process structures (`struct kinfo_proc`) with surgical accuracy.
* **Sandboxing Validation:** Monitors the state of `pledge(2)` (syscall filtering) and `unveil(2)` (filesystem visibility).
* **Security Posture Triage:** Instantly distinguishes between hardened userland applications and essential kernel threads.

---

## 📸 Project in Action

![Initial Scan](./Imagens/opensec1.png)
*Figure 1: Automated baseline evaluation of the global security posture.*

![Mitigation Analysis](./Imagens/opensec2.png)
*Figure 2: Real-time monitoring of active security primitives and privilege levels.*

![Forensic Summary](./Imagens/opensec3.png)
*Figure 3: Forensic audit reporting with global mitigation statistics and risk assessment.*

---

## ✨ Key Capabilities

### 🛡️  Mitigation Auditing
Continuous monitoring of exploit prevention policies across all PIDs:
* **🟢 GREEN (ACTIVE):** Mitigation is strictly enforced (Pledged/Unveiled).
* **🔴 RED (NONE):** No mitigation detected (Increased attack surface).

### ⚙️ Operational Integrity
OpenSec is built for systems where security and stability are inseparable:
* **Passive Observation:** Unlike intrusive debuggers, OpenSec reads kernel state without interrupting process execution.
* **Architectural Precision:** Built specifically for OpenBSD’s memory model and security paradigms.

### 🛠️  Investigation Workflow
When OpenSec flags a critical process with **NONE** status, use native OpenBSD tools for deep analysis:
* **Syscall Audit:** `ktrace -p [PID] && kdump` (Analyze missing pledge(2) calls).
* **File Access:** `fstat -p [PID]` (Check descriptors accessed outside of an unveil(2) scope).
* **Memory Flags:** `vmstat -m` (Inspect global memory allocation patterns).

---

## 🚀 Deployment

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
## 🛠️  Tech Stack

| Component | Technology |
| :--- | :--- |
| **Language** | C (OpenBSD C Style) |
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
