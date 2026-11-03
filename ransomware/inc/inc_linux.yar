/*
   INC ransomware, Linux/ESXi encryptor (Rust generation)
   Author: Tao Goldi
   TLP:WHITE

   The 2026 INC Linux encryptor is a Rust build (rustc 1.85.0, clap, curve25519-dalek) compiled for eight
   architectures: x64, arm, arm64, ppc, ppc64, riscv, s390 and sparc64. Its strings are not encrypted, and the
   operator error messages for stopping ESXi virtual machines, removing ESXi snapshots, writing the ransom note to
   the MOTD and running as a daemon are the same in every build. The rule needs the ESXi-stop and MOTD messages
   plus two of the other four, so it holds across architectures without relying on code bytes.

   Older INC Linux builds (2024-2025 C builds of about 80 KB and some large x64 builds) are a different generation
   and are not covered.
*/

rule Linux_INC_Ransomware_RustEncryptor
{
    meta:
        description  = "INC ransomware Linux/ESXi encryptor, Rust generation (x64, arm, arm64, ppc, ppc64, riscv, s390, sparc64): operator error strings for ESXi VM shutdown, snapshot removal, MOTD ransom note and daemon mode"
        author       = "Tao Goldi"
        reference    = "https://taogoldi.github.io/reverse-engineer/"
        date         = "2026-11-03"
        version      = 1
        family       = "INC"
        severity     = "critical"
        mitre_attack = "T1486, T1490"
        scope        = "file"
        sha256       = "26eb4e606d4a18f15b7c03bd0f479101727bdf550db0c5d71325d889a986c58b"

    strings:
        $esxi_stop = "' while stopping ESXi machines" ascii
        $motd      = "Error: '' while setting motd!" ascii
        $daemon    = "' while running as a daemon" ascii
        $settings  = "' while parsing settings" ascii
        $esxi_snap = "Error '' while removing ESXi snapshots" ascii
        $prompt    = "Press [ENTER] / [RETURN] to continue..." ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 15MB and
        $esxi_stop and $motd and
        2 of ($daemon, $settings, $esxi_snap, $prompt)
}
