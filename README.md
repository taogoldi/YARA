# YARA Detection Rules

This repository contains production-oriented YARA signatures for malware triage, threat hunting, and retro-hunt workflows.

## Scope

The rules are organized by malware class:

- `botnets/`
- `stealers/`
- `ransomware/`

Each rule is intended to be readable, testable, and traceable to published analysis material.

## Rule Metadata Standard

Rules in this repository follow a consistent `meta` layout:

- `author = "taogoldi"`
- `reference = "https://taogoldi.github.io/reverse-engineer/"`
- `description` for analyst context
- Optional sample hashes, family labels, and version fields

## Usage

Compile-check all rules:

```bash
yara -w -r . >/dev/null
```

Scan a target file:

```bash
yara -r botnets/mirai/mirai_like_stage1_family_heuristic.yar /path/to/sample.bin
```

Scan recursively against a corpus:

```bash
yara -r . /path/to/samples/
```

## Quality Notes

- Rules are tuned from real reverse-engineering workflows and can still require environment-specific tuning.
- High-fidelity rules target known samples and close variants.
- Heuristic/family rules trade precision for broader detection and should be validated in your environment.

## Operational Guidance

- Use high-fidelity rules for blocking and deterministic retro-hunts.
- Use heuristic rules for triage enrichment and clustering.
- Keep a false-positive review loop before broad enforcement.

## Disclaimer

These signatures are provided for defensive security operations and research. Test thoroughly before production deployment.
