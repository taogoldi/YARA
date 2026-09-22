# YARA Detection Rules

Production-oriented YARA signatures for malware triage, threat hunting and retro-hunts. Two
kinds of rule live here:

- **Hand-written rules** from reverse-engineering work, each traceable to the analysis behind it
  (write-ups at https://taogoldi.github.io/reverse-engineer/).
- **Generated rules** (`auto_*.yar`), produced and validated by an automated pipeline and kept
  in sync with its measurements. See [Generated rules](#generated-rules-auto_yar).

## Layout

Rules are organised by malware class, then family: `<class>/<family>/<rule>.yar`.

| Class | Families |
|---|---|
| `backdoors/` | Destover (Lazarus wiper, 2014), Factory-v3 Go implant |
| `botnets/` | Chaos/Kaiji Ares variant, Kaiji-like Go ELF, Mirai-like stage-1 clusters |
| `hvnc/` | StudioSecGhost hidden-VNC agent |
| `injectors/` | PoolParty thread-pool injection patterns |
| `loaders/` | AnimateClipper (stage 1, Go dropper), FUD Crypt (test payload, VerShadow), GuLoader NSIS installer, GCleaner*, SmokeLoader* |
| `ransomware/` | Bisamware, Crytox, Dagon Locker (packed and unpacked) |
| `rats/` | AsyncRAT*, DcRAT build, NanoCore*, njRAT im523 and njRAT*, Pulsar, Quasar native loader, Remcos*, VioletRAT v6, XWorm crypter and RAT |
| `stealers/` | Amadey cred64 and Amadey*, IRoveroll, Pony/Fareit, Pulsar, Raccoon v2, SnakeKeylogger*, Vidar-like stage 1/2 and Vidar* |

`*` generated rule.

## Rule kinds

- **High-fidelity** rules target known samples and their close variants: use them for blocking
  and deterministic retro-hunts.
- **Heuristic / family** rules trade precision for reach: use them for triage enrichment and
  clustering, and validate them in your environment first.
- **Generated** rules are family-triage rules: precise by construction, deliberately not
  high-recall (most samples of a family are crypters around the payload, which a string rule
  cannot see).

## Metadata standard

Every rule carries a `meta` block with at least:

- `description`: what it detects and, for hand-written rules, the analysis it comes from
- `author = "Tao Goldi"` (older rules use `"taogoldi"`; both are the same author)
- `reference = "https://taogoldi.github.io/reverse-engineer/"`
- `date` (`YYYY-MM` or `YYYY-MM-DD`), `version`
- `family`, and where known `variant`, `severity`, `mitre_attack`, sample `sha256` / `hash1..3`

## Generated rules (`auto_*.yar`)

Files named `auto_<family>_<slot>_v<N>.yar` are produced by AegisLattice **yara-forge**: yarGen-Go
for native samples, and a name-and-literal generator for .NET builds. A generated rule is
published only after it has:

- 0 hits on a corpus of about 41,700 clean Windows binaries from eight software sources;
- 0 hits on recent samples of more than 120 other malware families, including their unpacked
  payloads;
- matched held-out samples of its own family that it was not built from.

Each rule's `meta` records exactly that (`training_samples`, `validation_goodware_files`,
`validation_other_families`, `validation_heldout_hits`) and, once it has run in production,
`live_precision` against independent family labels with the date it was measured
(`live_measured`). `hash1..3` are training samples. The pipeline re-checks its rules twice a
week; a rule whose precision drops is retired, and this repository is updated automatically
after every promotion and retirement and once a day for refreshed metadata. A generated rule
that disappears from here was retired.

## Usage

Compile-check all rules (a few hand-written rules carry unreferenced strings kept for
documentation; they compile with warnings):

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

## Operational guidance

- Use high-fidelity rules for blocking and deterministic retro-hunts.
- Use heuristic rules for triage enrichment and clustering.
- Use generated rules as family evidence to be corroborated, not as a verdict on their own.
- Keep a false-positive review loop before broad enforcement.

## Licence and disclaimer

MIT. These signatures are provided for defensive security operations and research. Test
thoroughly before production deployment.
