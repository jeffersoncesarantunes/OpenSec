## ● Technical Specification: Security Model & Forensic Workflow

This document details the architectural logic of OpenSec and provides a formal guide on how to interpret and act upon the results using native OpenBSD forensic tools.

---

## 1. Philosophical Foundation

OpenSec is built on the **"Verify, then Trust"** principle. OpenSec identifies the "gap" between kernel capability and application adoption.

### 1.1 The "Naked Binary" Problem
A process running without `pledge(2)` or `unveil(2)` is considered a "Naked Binary," providing an unrestricted path to the Kernel API and the global Filesystem.

---

## 2. Kernel Telemetry & Visual Representation

### 2.1 Technical Data Source
* **Mechanism:** Direct inspection of `struct kinfo_proc` via `libkvm(3)`.
* **Data Integrity:** Bypasses text-based process lists to avoid TOCTOU vulnerabilities.

### 2.2 UI Chromatic Logic (ANSI Escape Codes)
OpenSec uses standard ANSI sequences to categorize process states. **Note on Environment Variability:**
During development and validation, tests were conducted on **Kitty** and **xfce4-terminal**. It was observed that:
* **Userland (NATIVE):** May appear as **Purple** (Kitty/Modern) or **Blue** (Xfce4/Classic).
* **System (KERNEL):** May appear as **Pink** (Kitty) or **Magenta** (Xfce4).
* **Mitigations:** Green (Active) and Red (None) remain consistent across most themes.

---

## 3. Post-Audit Investigation Workflow

### Step 1: Behavioral Capture & Dump Analysis
* **Live Trace:** `doas ktrace -idp [PID]` (Capture syscalls for 30-60s).
* **Binary Integrity:** `sha256sum /path/to/binary` (Check for tampering).
* **Static Analysis:** `strings /path/to/binary | less` (Search for hardcoded IPs/URLs).
* **Hex Inspection:** `hexdump -C /path/to/binary` (Investigate data offsets).

### Step 2: Filesystem & Access Mapping
* **Action:** `doas fstat -p [PID]` and `kdump | grep "NAMI"`.
* **Objective:** Identify unauthorized filesystem probing.

---

## 4. Operational Safety & Resolution

### 4.1 Handling "ACTION REQUIRED"
When prompted during an audit, selecting **Option 3 (Ignore)** is the recommended action. This prevents the auditor from waiting on a non-responsive PID, avoiding a potential system freeze.

### 4.2 Hardening Hierarchy
1. **Code Patching:** Implement `pledge()` and `unveil()` based on gathered data.
2. **Verification:** Rerun OpenSec to confirm **ACTIVE** status.
