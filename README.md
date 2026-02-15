# OpenSec - OpenBSD Process Security Analyzer

[![OpenBSD](https://img.shields.io/badge/OS-OpenBSD-yellow)]()
[![C](https://img.shields.io/badge/language-C-blue)]()

OpenSec é uma ferramenta forense de análise ao vivo de processos para OpenBSD, focada nos recursos exclusivos de segurança do sistema.

## ✨ Funcionalidades

- **Análise detalhada de pledges** - Quais promises cada processo tem
- **Monitoramento W^X** - Detecção de violações de Write XOR eXecute
- **Detecção de unveil e chroot** - Isolamento de processos
- **Auditoria de sysctl hardening** - Configurações de segurança do kernel
- **Hierarquia processo/thread** - Visualização clara

## 🚀 Compilação

```bash
git clone https://github.com/seu-usuario/OpenSec.git
cd OpenSec
make
./bin/opensec
