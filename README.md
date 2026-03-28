# 🐡 OpenSec

Lightweight OpenBSD process mitigation auditing tool focused on pledge, unveil, and W^X visibility.

[![Platform-OpenBSD](https://img.shields.io/badge/Platform-OpenBSD-FBD12B?style=flat-square&logo=openbsd&logoColor=black)](https://www.openbsd.org)
[![Language-C11](https://img.shields.io/badge/Language-C11-1793D1?style=flat-square&logo=c&logoColor=white)](https://gcc.gnu.org/)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
![Version](https://img.shields.io/badge/Version-1.0.0-333333?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-00FF41?style=flat-square)

## ● Project Information

- **Project:** OpenSec (Open Security Auditor)
- **Author:** Jefferson Cesar Antunes
- **License:** MIT
- **Version:** 1.0.0
- **Description:** Passive kernel-state mitigation auditing tool for OpenBSD.

## ● Etymology & Origin

The name OpenSec was born from the fusion of Open and Security, directly inspired by the OpenBSD philosophy.

Open represents more than free software. It stands for transparency, auditability, and deterministic security design.

OpenSec reflects the principle that security tools must be inspectable, minimal, and free from hidden logic.  
It is security through clarity.

## ● Overview

OpenSec is a minimal forensic utility designed to audit process-level mitigation mechanisms on OpenBSD.

It inspects kernel-exposed process metadata through:

    kvm(3)
    struct kinfo_proc (kernel process table)

The tool evaluates whether active processes enforce core security primitives such as:

    pledge(2)
    unveil(2)

Additionally, it inspects kernel metadata that may indicate W^X enforcement behavior.

Classification is derived strictly from kernel-reported state.

OpenSec does not perform tracing, behavioral inference, or runtime instrumentation.

## ● Why

OpenBSD provides strong built-in mitigation primitives. However, visibility into which processes actively enforce them is not centralized.

OpenSec provides:

- Deterministic mitigation visibility
- System-wide process auditing
- Hardening validation support
- Live forensic triage assistance
- Security posture verification

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

## ● Project in Action

![Initial Scan](./Imagens/opensec1.png)
*1- Build Process and Initialization: Environment preparation and initial active kernel scanning.*

![Mitigation Analysis](./Imagens/opensec2.png)
*2- Silent Execution and Report Generation: Using --quiet and --format flags to generate clean JSON/CSV data.*

![Forensic Summary](./Imagens/opensec3.png)
*3- Data Integrity and Security Audit: Verifying file hashes with sha256 and inspecting process-level restrictions (pledge, unveil) in a tabulated view.*

## ● Features

- Kernel process table inspection via `libkvm`
- `pledge(2)` enforcement detection
- `unveil(2)` state reporting
- W^X-related enforcement indicators
- Deterministic classification model
- Clean terminal output
- Minimal runtime footprint

## ● Operational Integrity

OpenSec is built for stability and forensic neutrality:

- Read-only kernel state access
- No process interruption
- No execution state modification
- Graceful handling of restricted entries

## ● Deployment

**Requirements:**

- OpenBSD (release or -current)
- libkvm
- BSD make
- doas or root privileges

## ● Build and Run

```bash
# Clone the repository
git clone https://github.com/jeffersoncesarantunes/OpenSec.git
cd OpenSec

# Build (clean old binaries first)
make clean && make

# Standard execution (Requires privileges to access /dev/kmem)
doas ./bin/opensec

# Silent mode (Export only, no terminal pollution)
doas ./bin/opensec --format json --quiet
doas ./bin/opensec --format csv --quiet

# Post-Analysis (Verifying generated reports with system tools)
sha256 output.json
hexdump -C output.csv | head -n 5
sed 's/"//g' output.csv | column -t -s ','
``` 

## ● Repository Structure

```text
├── bin/                # Compiled binaries (locally built)
├── docs/               # Technical specs & Security model
├── examples/           # Sample outputs (JSON/CSV) for testing
├── Imagens/            # Execution flow screenshots
├── include/            # Header files (opensec.h)
├── src/                # Core engine logic (engine.c, main.c)
├── LICENSE             # MIT License terms
├── Makefile            # POSIX compliant build system
└── README.md           # Project entry point
```

## ● Export Formats

OpenSec can generate structured output for further analysis or reporting.

### CSV Export

Ideal for spreadsheet analysis or quick terminal filtering:
```bash
doas ./bin/opensec --format csv --quiet
```

Sample snippet (output.csv):
```csv
pid,name,pledge,unveil,wxneeded,chrooted,context
19286,opensec,0,0,0,0,NATIVE
85953,firefox,1,0,0,0,NATIVE
```

### JSON Export
```bash
doas ./bin/opensec --format json --quiet
```

Sample snippet (output.json):
```json
[
  {
    "pid": 19286,
    "name": "opensec",
    "pledge": false,
    "unveil": false,
    "wxneeded": false,
    "chrooted": false,
    "context": "NATIVE"
  },
  {
    "pid": 85953,
    "name": "firefox",
    "pledge": true,
    "unveil": false,
    "wxneeded": false,
    "chrooted": false,
    "context": "NATIVE"
  }
]
```

**Note:** Choose the format with `--format json` or `--format csv`. If omitted, OpenSec prints output to the terminal only. Use the `--quiet` flag to suppress standard output during file generation.

## ● Post-Analysis & Investigation

OpenSec is designed to integrate with native OpenBSD forensic tools. After identifying a process with suspicious mitigations (e.g., NONE in pledge/unveil), you can proceed with a deeper audit:

### 1. Data Integrity & Visualization

Verify that your reports haven't been tampered with and transform raw CSV data into a readable security dashboard:

Verify report integrity
```bash
sha256 output.json
```

View as a tabulated dashboard
```bash
sed 's/"//g' output.csv | column -t -s ','
```

### 2. Deep Binary & Syscall Audit

Investigate the binary on disk and trace its real-time behavior to understand why mitigations are missing:

Verify the binary on disk (Example follows the author's local environment)
```bash
sha256 /usr/local/bin/firefox
```

Real-time syscall auditing
```bash
doas ktrace -p [PID] && kdump | head -n 40
```

File descriptor inspection
```bash
fstat -p [PID]
```

**Note:**The binary path /usr/local/bin/firefox is an example. Replace it with any process identified by OpenSec during your audit.

## ● Tech Stack

- **Language:** C (C99/C11 with OpenBSD extensions)
- **Kernel Interface:** libkvm
- **Data Source:** struct kinfo_proc
- **Build Tool:** BSD make
- **Target Platform:** OpenBSD

## ● Roadmap

- [x] Core mitigation auditing engine
- [x] pledge(2) / unveil(2) visibility
- [x] Kernel state extraction via libkvm(3)
- [x] Structured export formats (JSON / CSV)
- [x] Integration with sha256 for binary integrity validation
- [x] Silent mode for automation (--quiet)
- [ ] Fine-grained W^X violation detection

## ● License

Distributed under the MIT License. See [LICENSE](./LICENSE) for details.
