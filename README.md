# 🐡 OpenSec | OpenBSD Process Security Auditor

**OpenSec** is a low-level forensic tool designed to audit security mitigations on **OpenBSD**. It queries the kernel to verify if running binaries are leveraging native exploit mitigations like `pledge(2)`, `unveil(2)`, and `W^X`.

## 🛡️ Why it exists
OpenSec acts as a security posture validator, identifying "naked" processes—those running without sandboxing in an otherwise hardened environment.

* **Pledge(2):** Validates syscall restriction. Processes labeled `NONE` have full kernel surface access.
* **Unveil(2):** Checks filesystem visibility. Identifies if a process can "see" the entire OS.
* **W^X:** Monitors enforcement of memory policies where pages cannot be both writable and executable.

---

## 🔍 Security Audit in Action
* **GREEN (ACTIVE):** Mitigation is strictly enforced.
* **RED (NONE):** No mitigation detected (increased attack surface).
* **Context Awareness:** Automatically distinguishes between **NATIVE** userland processes and **KERNEL** threads.

---

## 🖼️ Screenshots

<p align="center">
  <img src="Imagens/opensec1.png" width="800" alt="OpenSec Initial Scan">
  <br>
  <i>1. Initial System Scan: Evaluation of baseline security posture.</i>
</p>

<p align="center">
  <img src="Imagens/opensec2.png" width="800" alt="Mitigation Analysis">
  <br>
  <i>2. Mitigation Analysis: Monitoring active Pledge and Unveil security primitives.</i>
</p>

<p align="center">
  <img src="Imagens/opensec3.png" width="800" alt="Security Summary">
  <br>
  <i>3. Forensic Summary: Final audit reporting and global mitigation statistics.</i>
</p>

---

## 🚀 Build & Run
OpenSec interfaces with the kernel via `kvm(3)`, therefore it requires elevated privileges.

```bash
# Build
make clean && make

# Execute
doas ./bin/opensec
```

## 🕵️ Investigation Workflow
If OpenSec flags a critical process with **NONE** status, investigate using OpenBSD’s native trace tools:

* **Syscall Audit:** Run `ktrace -p [PID]` followed by `kdump` to analyze missing pledge(2) calls.
* **Filesystem Access:** Use `fstat -p [PID]` to check files accessed outside of an unveil(2) scope.

---

## 🛠 Project Architecture
* `src/`: Implementation of KVM kernel queries and security logic.
* `include/`: Header files for mitigation state definitions.
* `bin/`: Output directory for the compiled forensic binary.

---

## ⚖️ License
MIT License. Built for the OpenBSD security community.
