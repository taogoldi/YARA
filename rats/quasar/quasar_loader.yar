import "pe"

rule QuasarRAT_CustomLoader_ByteCipher
{
    meta:
        description = "Detects the custom native x64 loader that decrypts Quasar RAT using byte-swap + SUB + XOR + ROR cipher"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        sha256 = "58c0f6f8f34d79ea67065761fd2bfc32101c1611cb7d16f5c15f8c19f8572e65"
        severity = "critical"
        family = "Quasar Loader"
        mitre_attack = "T1140,T1027"

    strings:
        // Anti-sandbox sleep: mov ecx, 0x1388 (5000ms)
        $sleep = { B9 88 13 00 00 }

        // Decryption loop bound: cmp r9d, 0x31D5FF (3,266,047)
        $loop_bound = { 81 F9 FF D5 31 00 }

        // SUB 0x10 in the per-byte cipher
        $sub_10 = { 80 E9 10 }

        // ROR cl, 5 in the per-byte cipher
        $ror_5 = { C0 C9 05 }

        // XOR cl, al (part of the cipher chain)
        $xor_cl_al = { 32 C8 }

        // .fptable section name (characteristic of this loader family)
        $fptable = ".fptable" ascii

        // ShellExecuteA import
        $shell = "ShellExecuteA" ascii

    condition:
        uint16(0) == 0x5A4D and filesize > 2MB and filesize < 10MB and
        (
            ($loop_bound and $ror_5 and $sub_10) or
            ($sleep and $loop_bound and $xor_cl_al) or
            ($fptable and $loop_bound and $ror_5)
        )
}

rule QuasarRAT_v141_Payload
{
    meta:
        description = "Detects Quasar RAT v1.4.1 payload with CJK-obfuscated class names"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        sha256 = "6bb333f45cbb5db45f63379e81b737956804cdde4b436e81612da722d7c9a725"
        severity = "critical"
        family = "Quasar RAT"

    strings:
        $quasar1 = "Quasar Client" ascii wide
        $quasar2 = "Quasar.Common.Messages" ascii wide
        $quasar3 = "MaxXor" ascii wide
        $quasar4 = "ClientIdentificationResult" ascii wide

        // Quasar's custom PBKDF2 salt (first 8 bytes)
        $salt = { BF EB 1E 56 FB CD 97 3B }

        // PBKDF2 iteration count 50000 = 0xC350
        $iterations = { 50 C3 00 00 }

    condition:
        uint16(0) == 0x5A4D and
        pe.imports("mscoree.dll") and
        (
            (2 of ($quasar*)) or
            ($salt and $iterations) or
            ($quasar1 and $salt)
        )
}

rule QuasarRAT_Config_54_172
{
    meta:
        description = "Detects this specific Quasar build with C2 at 54.172.72.215"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        severity = "critical"
        family = "Quasar RAT"

    strings:
        $key = "45567C0614C4584B61EF8AB3B378784EFE4A57F8" ascii wide
        $mutex = "Office04" ascii wide
        $c2_enc = "cM6dedB3MxmXiZNaVITAymTPRcnO6npI" ascii wide
        $quasar = "Quasar" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (($key and $quasar) or ($key and $mutex) or ($c2_enc and $quasar))
}
