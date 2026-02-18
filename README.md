# OpenSec - OpenBSD Process Security Analyzer

[![OpenBSD](https://img.shields.io/badge/OS-OpenBSD-yellow)](https://www.openbsd.org)
[![C](https://img.shields.io/badge/language-C-blue)](https://en.wikipedia.org/wiki/C_(programming_language))
[![License](https://img.shields.io/badge/license-BSD-green)](https://opensource.org/licenses/BSD-3-Clause)

OpenSec is a lightweight forensic tool for live process analysis on **OpenBSD**, specifically designed to audit the system's unique security mitigations.

## 📺 Live Demo

[![asciinema](https://asciinema.org/a/p3YjjVeuTJGIAwpj.svg)](https://asciinema.org/a/p3YjjVeuTJGIAwpj)

---

## ✨ Features

- **Pledge Analysis** – Audit processes utilizing the `pledge(2)` system call to restrict system operations.
- **Unveil Detection** – Identify processes operating under `unveil(2)` filesystem visibility restrictions.
- **W^X Enforcement** – Detect processes requesting memory pages that are simultaneously Writable and Executable, bypassing security policies.
- **Jail & Context Identification** – Spot processes running inside `chroot(2)` environments and distinguish between Kernel and Userland contexts.
- **KVM Integration** – High-performance auditing using the native Kernel Virtual Memory (`kvm(3)`) interface.

## 🧠 Concept & Internal Logic

**OpenSec** was born from a specific technical challenge: how to audit security flags that are internal to the kernel's process structure without relying on the `/proc` filesystem—which is not mounted by default on OpenBSD and is generally discouraged in hardened environments.

### The KVM Approach vs. Standard Tools
Unlike generic tools that parse text outputs, OpenSec interfaces directly with the **`kvm(3)`** (Kernel Data Access Library). This architectural choice allows the tool to:
- **Direct Memory Access:** Open a live snapshot of the kernel's memory via `/dev/mem` or `/dev/kmem`.
- **Structure Traversal:** Directly traverse the `kinfo_proc` structures within the kernel's process table.
- **Flag Extraction:** Access the `p_pflags` and `p_extflags` bitmasks to detect the presence of `P_PLEDGE` and `P_UNVEIL`, states that are often invisible to standard userland utilities.

### Technical Hurdles & Evolution
During development, the project evolved from high-level system calls to raw kernel accounting. This required:
1. **Header Deep-Dive:** Navigating `<sys/sysctl.h>` and `<sys/proc.h>` to map how the kernel stores mitigation states.
2. **Mitigation Visibility:** Since `pledge(2)` and `unveil(2)` are one-way transitions (restrictive only), OpenSec provides a "truth source" by reading the kernel's internal state rather than relying on process self-reporting.
3. **Security Model Awareness:** The tool is designed with OpenBSD's restrictive permission model in mind, requiring elevated privileges only because it accesses sensitive kernel memory structures.

### Why this matters:
- **Auditing:** Verification that `pledge(2)` promises are active and enforced.
- **Forensics:** Identification of "legacy" processes running without modern mitigations or with W^X violations.
- **Systems Engineering:** A practical demonstration of low-level systems programming and kernel-userland interaction on a secure-by-default OS.
---

## 🚀 Getting Started

### 📋 Prerequisites
* **OpenBSD** operating system.
* Standard C compiler (`cc`).
* `doas` or `sudo` configured.

## 🛠️  Compilation & Execution
To build and run the project using the optimized minimalist Makefile, execute:

```bash
# Clean previous builds, compile and run
make clean
make
doas ./bin/opensec
```

## 📄 License
This project is licensed under the BSD 3-Clause License - see the LICENSE file for details.

