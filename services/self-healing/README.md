# Self-Healing Service

Self-Healing Code DNA (SHCD) for CyberShield-X — applications detect their own compromise and autonomously fix vulnerable code.

## Features
- LLVM IR-based code genome capture at build time
- eBPF runtime integrity monitoring (CFI, memory, syscalls)
- AI-powered patch synthesis via Claude API
- Generational memory for instant re-application
- Fleet-wide patch sharing via encrypted Kafka

## Build
```bash
cargo build --release
```
