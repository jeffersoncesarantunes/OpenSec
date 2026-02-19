# OpenSec - OpenBSD Process Security Auditor

**OpenSec** is a low-level forensic tool designed to audit security mitigations on **OpenBSD**. Instead of just listing processes, it queries the kernel to verify if running binaries are actually leveraging OpenBSD’s native exploit mitigations like `pledge(2)`, `unveil(2)`, and `W^X`.

## 🛡️  Why it exists
OpenBSD provides powerful security primitives, but they are only effective if developers implement them. OpenSec acts as a security posture validator, allowing sysadmins and researchers to identify "naked" processes—those running without sandboxing in an otherwise hardened environment.

* **Pledge(2):** Validates syscall restriction. Processes labeled `NONE` have full kernel surface access.
* **Unveil(2):** Checks filesystem visibility. Identifies if a process is restricted to its own data or can "see" the entire OS.
* **W^X:** Monitors enforcement of memory policies where pages cannot be both writable and executable.

---

## 🔍 Security Audit in Action
The **v1.1 update** focused on UI precision and logic robustness, ensuring the audit table remains perfectly aligned across different terminal emulators.

* **GREEN (ACTIVE):** Mitigation is strictly enforced.
* **RED (NONE):** No mitigation detected (increased attack surface).
* **Context Awareness:** Automatically distinguishes between **NATIVE** userland processes and **KERNEL** threads (such as PID 1).

---

## 🖼️  Screenshots

<p align="center">
  <img src="Imagens/opensec1.png" width="800" alt="OpenSec Initial Scan">
  <br>
  <i>1. Initial System Scan: Detection of userland processes and evaluation of baseline security posture.</i>
</p>

<p align="center">
  <img src="Imagens/opensec2.png" width="800" alt="Mitigation Analysis">
  <br>
  <i>2. Mitigation Analysis: Real-time monitoring of system daemons leveraging active Pledge and Unveil security primitives.</i>
</p>

<p align="center">
  <img src="Imagens/opensec3.png" width="800" alt="Security Summary">
  <br>
  <i>3. Forensic Summary: Final security audit reporting W^X enforcement and global mitigation statistics.</i>
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

## 🕵️  Investigation Workflow
If OpenSec flags a critical process with NONE status, you should further investigate using OpenBSD’s native trace tools:

* **Syscall Audit:** Run `ktrace -p [PID]` followed by `kdump` to see why the binary hasn't been pledged.
* **Filesystem Access:** Use `fstat -p [PID]` to check what files the process is accessing outside of an unveil scope.

---

## 🛠  Changelog (v1.1)
* **UI Refactoring:** Fixed table misalignment by implementing fixed-width specifiers for consistent column synchronization.
* **Logic Hardening:** Added zero-division guards in the stats engine to handle edge cases in restricted environments.
* **Context Heuristics:** Improved detection of Kernel-space processes (e.g., PID 1) for more accurate reporting.

---

## ⚖️  License
MIT License. Built for the OpenBSD security community.
