<p align="center">
  <img src="assets/binatomy-logo.svg" alt="Binatomy" width="88" height="88">
</p>

<h1 align="center">YARA Detection Rules</h1>

<p align="center">
  Malware detection rules from reverse-engineering work and from the <strong>Binatomy</strong> analysis platform.<br>
  For triage, threat hunting and retro-hunts.
</p>

<p align="center">
  <a href="LICENSE"><img alt="Licence: MIT" src="https://img.shields.io/badge/licence-MIT-2f81f7"></a>
  <img alt="YARA 4.x" src="https://img.shields.io/badge/YARA-4.x-5b6b7c">
  <img alt="Generated rules refreshed daily" src="https://img.shields.io/badge/generated%20rules-refreshed%20daily-3fb950">
  <a href="https://taogoldi.github.io/reverse-engineer/"><img alt="Write-ups" src="https://img.shields.io/badge/write--ups-reverse--engineer-8957e5"></a>
</p>

---

## What is here

| Kind | Files | Where it comes from |
|---|---|---|
| **Hand-written** | `*.yar`, `*.yara` | Reverse-engineering work. Each rule can be traced to the analysis behind it; most have a write-up at [taogoldi.github.io/reverse-engineer](https://taogoldi.github.io/reverse-engineer/). |
| **Generated** | `auto_*.yar` | Built and validated by Binatomy's rule generator from live samples, and published here automatically. See [Generated rules](#generated-rules). |

## Binatomy

<img src="assets/binatomy-logo.svg" alt="" width="20" height="20" align="left">&nbsp;**Binatomy** is a malware analysis and threat-intelligence platform. It takes samples apart layer by layer: it unpacks and decodes them, emulates them, decompiles them, classifies them by family, and ties each one to its configuration and infrastructure.

The generated rules in this repository are one of its outputs. Every day the platform also builds a threat feed (a JSON file covering the last 24 hours) that links each classified sample to the rules here that match it.

## Quick start

```bash
git clone https://github.com/taogoldi/YARA.git && cd YARA

# compile-check everything (-w: a few hand-written rules keep unreferenced strings for documentation)
yara -w -r . /dev/null

# one rule against one file
yara -r botnets/mirai/mirai_like_stage1_family_heuristic.yar /path/to/sample.bin

# every rule against a folder of samples
yara -r . /path/to/samples/
```

## Layout

Rules are organised by malware class, then family: `<class>/<family>/<rule>.yar`.

| Class | Families |
|---|---|
| `adware/` | AdwareNeoreklami* |
| `backdoors/` | Destover (Lazarus wiper, 2014), Factory-v3 Go implant (in `gsb/`) |
| `botnets/` | Chaos/Kaiji Ares variant; Diicot (Mexals) shc-compiled installers with their miner and SSH brute-force scripts; Kaiji-like Go ELF; Mirai-like stage-1 clusters; Mozi P2P bot and its tampered UPX packing; Linux bots that keep their C2 on a blockchain (`chain_c2/`: Boatnet, Kimwolf and Mirai forks reading Polygon contracts or ENS records) |
| `hvnc/` | StudioSecGhost hidden-VNC agent |
| `injectors/` | PoolParty thread-pool injection patterns |
| `loaders/` | Moonshine loader (in `animateclipper/`, with the AnimateClipper Go dropper), FUD Crypt (test payload, VerShadow), GuLoader NSIS installer and dropped padding |
| `packers/` | shc-compiled shell scripts (any build or architecture; identifies the wrapper, not the script's purpose) |
| `ransomware/` | Bisamware, Crytox, Dagon Locker (packed and unpacked), INC Linux/ESXi encryptor (Rust generation, eight architectures) |
| `rats/` | AsyncRAT*, Ave Maria*, DcRAT build, NanoCore*, njRAT im523 and njRAT*, Pulsar, Quasar native loader, Remcos*, ValleyRAT*, VioletRAT v6, XWorm crypter and RAT |
| `stealers/` | Amadey cred64; CloudSyncD (macOS fake installer and stager); DarkCloud*; IRoveroll; Loki*; MassLogger*; Pony/Fareit; Pulsar; Raccoon v2; Remus*; Rhadamanthys*; RisePro*; SnakeKeylogger*; Vidar-like stage 1/2 and Vidar* |

`*` generated rules. Generated families come and go as rules are promoted and retired, so check the folder for the current set.

## Choosing a rule

| Rule kind | Use it for | Notes |
|---|---|---|
| **High-fidelity** | Blocking and deterministic retro-hunts | Targets known samples and their close variants. |
| **Heuristic / family** (`*_Generic`, `*_heuristic`) | Triage enrichment and clustering | Trades precision for reach. Validate in your environment first. |
| **Generated** (`auto_*`) | Family evidence, to be corroborated | Precise by construction, deliberately not high-recall: most samples of a family are crypters wrapped around the payload, which a string rule cannot see. |

Keep a false-positive review loop before enforcing any rule broadly.

## Generated rules

Files named `auto_<family>_<slot>_v<N>.yar` are produced by Binatomy's **yara-forge** pipeline:
- yarGen-Go for native samples;
- a name-and-literal generator for .NET builds.

A generated rule is published only after it has:
- **0 hits** on a corpus of about 41,700 clean Windows binaries from eight software sources;
- **0 hits** on recent samples of more than 120 other malware families, including their unpacked payloads;
- **matched held-out samples** of its own family that it was not built from.

Each rule's `meta` records exactly that:
- `training_samples`, `validation_goodware_files`, `validation_other_families`, `validation_heldout_hits`;
- once the rule has run in production, `live_precision` against independent family labels, with the date it was measured (`live_measured`).

`hash1..3` are training samples.

The pipeline re-checks its rules twice a week and retires any rule whose precision drops. This repository is updated automatically:
- after every promotion and retirement;
- once a day for refreshed metadata.

A generated rule that disappears from here was retired. `supersedes` in a rule's `meta` names the version it replaced.

## Metadata standard

Every rule carries a `meta` block with at least:

| Field | Content |
|---|---|
| `description` | What it detects and, for hand-written rules, the analysis it comes from |
| `author` | `"Tao Goldi"` (older rules use `"taogoldi"`; same author). Generated rules add the pipeline name. |
| `reference` | `https://taogoldi.github.io/reverse-engineer/` |
| `date`, `version` | `YYYY-MM` or `YYYY-MM-DD`; generated rules count versions per family slot |
| `family` | Plus, where known, `variant`, `severity`, `mitre_attack`, sample `sha256` / `hash1..3` |

## Contributing and reporting

Found a false positive or a missed variant? Open an issue with:
- the rule name;
- the sample's SHA-256;
- where it was seen.

Please do not attach live samples to issues.

## Licence and disclaimer

[MIT](LICENSE). These signatures are provided for defensive security operations and research, as is and without warranty. Test them thoroughly before production deployment.
