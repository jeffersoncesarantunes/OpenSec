# 🐡 OpenSec

Lightweight OpenBSD process mitigation auditing tool focused on pledge, unveil, and W^X visibility.

[![Platform-OpenBSD](https://img.shields.io/badge/Platform-OpenBSD-FBD12B?style=flat-square&logo=openbsd&logoColor=black)](https://www.openbsd.org)
[![Language-C11](https://img.shields.io/badge/Language-C11-1793D1?style=flat-square&logo=c&logoColor=white)](https://gcc.gnu.org/)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-00FF41?style=flat-square)](#-roadmap)
[![Tested-On](https://img.shields.io/badge/Tested%20on-OpenBSD%207.8-blue?style=flat-square)](https://www.openbsd.org/78.html)
[![Domain](https://img.shields.io/badge/Domain-Digital%20Forensics-lightgrey?style=flat-square)](./docs/SECURITY_MODEL.md)

---

## ● Etymology & Origin

The name OpenSec comes from the fusion of *Open* and *Security*, directly inspired by the OpenBSD philosophy.

“Open” here is not just about source code — it reflects transparency, auditability, and predictable system behavior.

OpenSec follows the idea that security tools should be minimal, inspectable, and free from hidden logic.

---

## ● Overview

OpenSec is a minimal forensic utility designed to audit process-level mitigation mechanisms on OpenBSD.

It inspects kernel-exposed process metadata using:

* `kvm(3)`
* `struct kinfo_proc`

The tool evaluates whether active processes enforce core security primitives such as:

* `pledge(2)`
* `unveil(2)`

It also inspects kernel metadata related to W^X enforcement behavior.

All classification is based strictly on kernel-reported state.

---

## ● Why

OpenBSD provides strong built-in mitigations, but visibility into which processes actively enforce them is not centralized.

OpenSec provides:

* Clear mitigation visibility per process
* System-wide auditing
* Hardening validation support
* Live forensic triage assistance

---

## ● How It Works

OpenSec interfaces with **libkvm** to access the kernel process table in read-only mode.

For each process, it evaluates fields within **struct kinfo_proc** to determine:

* pledge restriction state
* unveil restriction state
* indicators of W^X enforcement

All inspection is passive and does not interfere with execution.

---

## ● Example Output

```text
PID      PROCESS          PLEDGE          UNVEIL          CONTEXT
--------------------------------------------------------------------
89905    opensec          NONE            NONE            NATIVE
80996    ksh              ACTIVE          NONE            NATIVE
96837    xfce4-terminal   NONE            NONE            NATIVE
20033    firefox          ACTIVE          NONE            NATIVE
18100    firefox          NONE            NONE            NATIVE
79750    accounts-daemon  NONE            NONE            NATIVE
```

*Output reflects kernel-reported mitigation state.*

---

## ● Project in Action

![Initial Scan](./Imagens/opensec1.png)
*1 - Build and initial kernel scan.*

![Mitigation Analysis](./Imagens/opensec2.png)
*2 - Structured output generation using --quiet and --format.*

![Forensic Summary](./Imagens/opensec3.png)
*3 - Validation of process-level mitigation data and integrity checks.*

---

## ● Features

* Kernel process table inspection via `libkvm`
* `pledge(2)` enforcement detection
* `unveil(2)` state visibility
* W^X-related indicators
* Deterministic classification
* Minimal runtime footprint

---

## ● Operational Integrity

OpenSec is designed for safe forensic usage:

* Read-only kernel access
* No process interaction
* No execution interference
* Graceful handling of restricted entries

---

## ● Deployment

### Requirements

* OpenBSD (release or -current)
* libkvm
* BSD make
* doas or root privileges

---

## ● Build and Run

```bash
# Clone the repository
git clone https://github.com/jeffersoncesarantunes/OpenSec.git
cd OpenSec

# Build
make clean && make

# Run
doas ./opensec

# Structured output
doas ./opensec --format json --quiet
doas ./opensec --format csv --quiet
```

---

## ● Repository Structure

```text
├── bin/
├── docs/
│   ├── BENCHMARKS.md
│   └── SECURITY_MODEL.md
├── Imagens/
│   ├── opensec1.png
│   ├── opensec2.png
│   └── opensec3.png
├── include/
├── src/
│   ├── engine.c
│   └── main.c
├── .gitignore
├── LICENSE
├── Makefile
└── README.md
```

---

## ● Forensic Export & Post-Analysis

OpenSec supports structured output for integration with forensic workflows.

### Generate Reports

```bash
doas ./opensec --format json --quiet
doas ./opensec --format csv --quiet
```

Generated files:

* output.json
* output.csv

---

### Integrity & Visualization

```bash
sha256 output.json

sed 's/"//g' output.csv | column -t -s ','
```

---

### Deep Analysis

```bash
# Binary integrity
sha256 /usr/local/bin/firefox

# Syscall tracing
doas ktrace -p [PID] && doas kdump -f ktrace.out | head -n 40

# File descriptors
doas fstat -p [PID]
```

---

## ● Tech Stack

* **Language:** C (C11)
* **Kernel Interface:** libkvm
* **Data Source:** struct kinfo_proc
* **Build Tool:** BSD make
* **Platform:** OpenBSD

---

## ● Roadmap

* [x] Core mitigation auditing engine
* [x] `pledge(2)` / `unveil(2)` visibility
* [x] Kernel state extraction via `libkvm(3)`
* [x] JSON/CSV export
* [x] Silent mode (`--quiet`)
* [ ] PID filtering (`--pid`)
* [ ] Parent process mapping (PPID)
* [ ] Per-process security scoring

---

## ● Documentation

[![Docs-Security](https://img.shields.io/badge/Security--Model-004080?style=flat-square\&logo=openbsd\&logoColor=white)](./docs/SECURITY_MODEL.md)
[![Docs-Benchmarks](https://img.shields.io/badge/Performance--Benchmarks-444444?style=flat-square\&logo=speedtest\&logoColor=white)](./docs/BENCHMARKS.md)

---

## ● License

[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square\&logo=opensourceinitiative\&logoColor=white)](./LICENSE)

*This project is licensed under the MIT License.*
