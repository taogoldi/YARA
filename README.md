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

## Generated Rules (`auto_*.yar`)

Files named `auto_<family>_<slot>_v<N>.yar` are produced by an automated pipeline (AegisLattice
yara-forge: yarGen-Go for native samples, a name-and-literal generator for .NET builds), not
written by hand. A generated rule is published only after it has:

- 0 hits on a corpus of about 41,700 clean Windows binaries from eight software sources;
- 0 hits on recent samples of more than 120 other malware families;
- matched held-out samples of its own family that it was not built from.

Each such rule's `meta` records exactly that: `training_samples`, `validation_goodware_files`,
`validation_other_families`, `validation_heldout_hits`, and, once it has run in production,
`live_precision` against independent family labels and the date it was measured. Rules are
re-checked twice a week; one whose precision drops is withdrawn from this repository at the next
update. Treat them as family-triage rules: precise, deliberately not high-recall (most samples
of a family are crypters around the payload, which a string rule cannot see).

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
