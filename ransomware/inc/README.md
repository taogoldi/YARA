# INC ransomware, Linux/ESXi encryptor

`inc_linux.yar`, rule `Linux_INC_Ransomware_RustEncryptor` (2026-11-03).

The 2026 INC Linux encryptor is a Rust build (rustc 1.85.0, clap, curve25519-dalek) compiled for x64, arm, arm64,
ppc, ppc64, riscv, s390 and sparc64. Its strings are not encrypted: the operator error messages for stopping ESXi
VMs, removing ESXi snapshots, writing the MOTD note and daemon mode are shared by every build.

## Measured (2026-11-03)

| Set | Result |
|---|---|
| INC Linux builds, Rust generation, all eight architectures | 41 of 41 matched |
| INC Linux builds, other generations (x64 only) | 0 of 8 (not covered) |
| Non-INC Linux malware, 30,000 files | 0 matched |
| Linux builds of other ransomware families, 68 files (LockBit, Babuk, Conti, Chaos, Qilin, Akira, Royal, Hive, Black Basta, Interlock, BlackCat, Play, Clop, REvil, MarioLocker) | 0 matched |
| Clean Linux ELF files, 14,698 | 0 matched |

INC labels come from MalwareBazaar (signature `INC`). The eight uncovered builds are three small 2024-2025 C
builds of about 80 KB and five large 2-10 MB x64 builds, one of them UPX-packed.

Reference sample (arm64 build):
`26eb4e606d4a18f15b7c03bd0f479101727bdf550db0c5d71325d889a986c58b`
