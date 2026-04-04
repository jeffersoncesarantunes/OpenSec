# 🐡 OpenSec

Lightweight OpenBSD process mitigation auditing tool focused on pledge, unveil, and W^X visibility.

[![Platform-OpenBSD](https://img.shields.io/badge/Platform-OpenBSD-FBD12B?style=flat-square&logo=openbsd&logoColor=black)](https://www.openbsd.org)
[![Language-C11](https://img.shields.io/badge/Language-C11-1793D1?style=flat-square&logo=c&logoColor=white)](https://gcc.gnu.org/)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
![Status](https://img.shields.io/badge/Status-Active-00FF41?style=flat-square)

---

## ● Etymology & Origin

The name OpenSec was born from the fusion of Open and Security, directly inspired by the OpenBSD philosophy.

Open represents more than free software. It stands for transparency, auditability, and deterministic security design.

OpenSec reflects the principle that security tools must be inspectable, minimal, and free from hidden logic.  
It is security through clarity.

---

## ● Overview

OpenSec is a minimal forensic utility designed to audit process-level mitigation mechanisms on OpenBSD.

It inspects kernel-exposed process metadata through:

- `kvm(3)`
- `struct kinfo_proc`

The tool evaluates whether active processes enforce core security primitives such as:

- `pledge(2)`
- `unveil(2)`

Additionally, it inspects kernel metadata that may indicate W^X enforcement behavior.

Classification is derived strictly from kernel-reported state.

OpenSec does not perform tracing, behavioral inference, or runtime instrumentation.

---

## ● Why

OpenBSD provides strong built-in mitigation primitives. However, visibility into which processes actively enforce them is not centralized.

OpenSec provides:

- Deterministic mitigation visibility
- System-wide process auditing
- Hardening validation support
- Live forensic triage assistance
- Security posture verification

---

## ● How It Works

OpenSec interfaces with **libkvm** to access the kernel process table in read-only mode.

For each active process, it evaluates fields within **struct kinfo_proc** to determine:

- Whether pledge restrictions are active
- Whether unveil restrictions are present
- Whether memory protection aligns with W^X principles

All inspection is passive.

The tool does not:

- Attach via ptrace
- Inject code
- Modify process memory
- Suspend execution
- Instrument binaries

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

*Output reflects kernel-reported mitigation state only.*

---

## ● Project in Action

![Initial Scan](./Imagens/opensec1.png)  
*1 - Build Process and Initialization: Environment preparation and initial active kernel scanning.*

![Mitigation Analysis](./Imagens/opensec2.png)  
*2 - Silent Execution and Report Generation: Using --quiet and --format flags to generate clean JSON/CSV data.*

![Forensic Summary](./Imagens/opensec3.png)  
*3 - Data Integrity and Security Audit: Verifying file hashes with sha256 and inspecting process-level restrictions (pledge, unveil) in a tabulated view.*

---

## ● Features

- Kernel process table inspection via \`libkvm\`
- `pledge(2)` enforcement detection
- `unveil(2)` state reporting
- W^X-related enforcement indicators
- Deterministic classification model
- Clean terminal output
- Minimal runtime footprint

---

## ● Operational Integrity

OpenSec is built for stability and forensic neutrality:

- Read-only kernel state access
- No process interruption
- No execution state modification
- Graceful handling of restricted entries

---

## ● Deployment

### Requirements

- OpenBSD (release or -current)
- libkvm
- BSD make
- doas or root privileges

---

## ● Build and Run

```bash
# Clone the repository
git clone https://github.com/jeffersoncesarantunes/OpenSec.git
cd OpenSec

# Build the project
make clean && make

# Standard execution
doas ./bin/opensec

# Generate structured reports
doas ./bin/opensec --format json --quiet
doas ./bin/opensec --format csv --quiet
```

---

## ● Repository Structure

```text
├── bin/
├── docs/
├── examples/
├── Imagens/
├── include/
├── src/
├── LICENSE
├── Makefile
└── README.md
```

---

## ● Forensic Export & Post-Analysis

OpenSec supports structured data export for seamless integration with forensic workflows and security analysis pipelines.

### 1. Generating Reports

Use the --format flag combined with --quiet to generate clean data files for auditing.

```bash
doas ./bin/opensec --format json --quiet
doas ./bin/opensec --format csv --quiet
```

Generated files:
- output.json
- output.csv

---

### 2. Integrity & Data Visualization

```bash
# Verify report integrity
sha256 output.json

# View CSV as a formatted table
sed 's/"//g' output.csv | column -t -s ','
```

---

### 3. Deep Binary & Syscall Audit

```bash
# Verify binary integrity
sha256 /usr/local/bin/firefox

# Capture syscall activity
doas ktrace -p [PID] && kdump | head -n 40

# Inspect file descriptors and sockets
doas fstat -p [PID]
```

Note: Replace [PID] and paths with values obtained during analysis.

---

## ● Tech Stack

- **Language:** C (C99/C11 with OpenBSD extensions)
- **Kernel Interface:** libkvm
- **Data Source:** struct kinfo_proc
- **Build Tool:** BSD make
- **Target Platform:** OpenBSD

---

## ● Roadmap

- [x] Core mitigation auditing engine
- [x] `pledge(2)` / `unveil(2)` visibility
- [x] Kernel state extraction via `libkvm(3)`
- [x] Structured export formats (JSON/CSV)
- [x] Integrity validation with `sha256`
- [x] Silent mode (`--quiet`)
- [ ] Active PID filtering support (`--pid`)
- [ ] Parent-Process (PPID) relationship mapping
- [ ] Automated security score per process

---

## ● Documentation

[![Docs-Full](https://img.shields.io/badge/Documentation-Full_Guide-00599C?style=flat-square&logo=gitbook&logoColor=white)](./docs/)
[![Docs-Security](https://img.shields.io/badge/Security-Model-CC0000?style=flat-square&logo=shisno&logoColor=white)](./docs/SECURITY_MODEL.md)
[![Docs-Benchmarks](https://img.shields.io/badge/Performance-Benchmarks-444444?style=flat-square&logo=speedtest&logoColor=white)](./docs/BENCHMARKS.md)

---

## ● License

[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=opensourceinitiative&logoColor=white)](./LICENSE)

*This project is licensed under the MIT License.*
