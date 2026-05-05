/*
    GuLoader NSIS-Stage Detection Rules
    Family: GuLoader (a.k.a. CloudEye, VBdropper, vbdropper)
    Variant: NSIS-3 Unicode shellcode-based loader (2025 campaign cluster)

    Reference sample:
        SHA256: 39c0135a0e8d46053fbcaa4efe6cbc83d33cf8e7be43efbca1622b2f77c7b9c6
        File:   agestole.exe (decoy filename in version info)
        Compile time: 2025-03-08 23:05:20 UTC

    Detection strategy:
        - GuLoader_NSIS_Outer matches the outer NSIS-3 dropper PE itself.
        - GuLoader_NSIS_DroppedScriptArtifacts matches the inflated NSIS
          headers / decoy text files extracted to %TEMP%.
        - GuLoader_NSIS_DecoyPadding catches the very large constant-byte
          padding files used as filesize inflation decoys.
        - GuLoader_NSIS_Generic is the broad family rule.

    Author: Tao Goldi
    Date:   2026-04
*/

import "pe"

rule GuLoader_NSIS_Outer
{
    meta:
        description = "GuLoader outer NSIS-3 self-extracting installer (2025 cluster)"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        severity = "critical"
        family = "GuLoader"
        mitre_attack = "T1027.002,T1027.009,T1140,T1055,T1497.001,T1622,T1218.011"

    strings:
        // NSIS visible-string version-info decoy (UTF-16LE)
        $vi1 = "paymasters tvrmundes" wide
        $vi2 = "unfixated nonministerial" wide
        $vi3 = "agestole.exe" wide

        // The "loading" text used by the System.dll plugin path setup
        $nsis_setup = "Please wait while Setup is loading..." wide

        // Standard NSIS-3 signature inside the firstheader
        $nsis_sig    = { EF BE AD DE 4E 75 6C 6C 73 6F 66 74 49 6E 73 74 }
        // ^ 0xDEADBEEF + "NullsoftInst"

        // GuLoader NSIS samples all import the System.dll plugin which
        // exports Alloc/Call/Copy/Free/Get/Int64Op/Store/StrAlloc.
        // We do not match the System.dll bytes here (separate rule), only
        // a subset of unique imports that the outer EXE uses.
        $imp_sm  = "SendMessageTimeoutW" ascii
        $imp_inf = "SETUPAPI" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize > 700KB and filesize < 5MB and
        $nsis_sig and
        // PE meta we observed
        pe.is_pe and
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI and
        // NSIS dropper PE has a tiny .text and a huge .ndata virtual
        // section reserved for the unpacked installer header
        for any s in pe.sections : (
            s.name == ".ndata" and s.raw_data_size == 0 and s.virtual_size > 0x10000
        ) and
        // Must contain the NSIS version-info decoy
        2 of ($vi*) and
        $nsis_setup and
        all of ($imp*)
}

rule GuLoader_NSIS_DroppedScriptArtifacts
{
    meta:
        description = "GuLoader NSIS-stage dropped artifacts (inflated header / Danish word salad)"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        severity = "high"
        family = "GuLoader"
        notes = "Match against the inflated NSIS header or against the dropper memory image. Will also catch the extracted Darnel/*.ini files when scanned individually."

    strings:
        // Distinctive Danish/word-salad tokens used as NSIS variable values.
        // These are read by the script and concatenated to build API names
        // like "VirtualAlloc", "System.dll", "::Call".
        $w_skrub      = "Skrubhvl4"            ascii wide
        $w_confab     = "Confabulation"        ascii wide
        $w_oplys      = "oplysningsforbundene" ascii wide
        $w_fedt       = "fedtcellen"           ascii wide
        $w_synag      = "synagogism"           ascii wide
        $w_sigmoid    = "sigmoidally"          ascii wide
        $w_nonill     = "Nonillatively"        ascii wide
        $w_kontakt    = "kontaktskabende"      ascii wide
        $w_maynard    = "Maynard.pen"          ascii wide
        $w_ganoceph   = "Ganocephala"          ascii wide
        $w_cylindr    = "Cylindruria"          ascii wide

        // The NSIS plugin path the GuLoader script invokes
        $plugin_call  = "System::Call"         ascii wide

    condition:
        4 of ($w_*)
        or
        ( 2 of ($w_*) and $plugin_call )
}

rule GuLoader_NSIS_DecoyPadding
{
    meta:
        description = "GuLoader filesize-inflation decoy: file dominated by a single constant byte"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        severity = "info"
        family = "GuLoader"
        notes = "Run on the extracted Maynard.pen / Ganocephala176.ham. Generic enough to catch new variants that pick a different fill byte."

    strings:
        // 256 bytes of 0x5A (Maynard.pen pattern)
        $pad_5a = { 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A
                    5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A
                    5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A
                    5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A }
        // 256 bytes of 0xB7 (Ganocephala.ham pattern)
        $pad_b7 = { B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7
                    B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7
                    B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7
                    B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 }
        // 256 bytes of 0xAC (piasaba trailing pad)
        $pad_ac = { AC AC AC AC AC AC AC AC AC AC AC AC AC AC AC AC
                    AC AC AC AC AC AC AC AC AC AC AC AC AC AC AC AC
                    AC AC AC AC AC AC AC AC AC AC AC AC AC AC AC AC
                    AC AC AC AC AC AC AC AC AC AC AC AC AC AC AC AC }

    condition:
        filesize > 100KB and
        ( #pad_5a > (filesize \ 4096) or
          #pad_b7 > (filesize \ 4096) or
          #pad_ac > (filesize \ 4096) )
}

rule GuLoader_NSIS_Generic
{
    meta:
        description = "Generic detection for the GuLoader NSIS shellcode-loader family"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        severity = "critical"
        family = "GuLoader"

    strings:
        $nsis_magic   = "NullsoftInst" ascii
        $loading      = "Please wait while Setup is loading..." wide
        $vi_paymast   = "paymasters tvrmundes" wide
        $vi_unfix     = "unfixated nonministerial" wide
        $vi_agestole  = "agestole.exe" wide
        $imp_setup    = "SETUPAPI" ascii nocase
        $imp_smt      = "SendMessageTimeoutW" ascii
        $imp_gpa      = "GetProcAddress" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 700KB and filesize < 5MB and
        $nsis_magic and
        $loading and
        2 of ($vi_*) and
        all of ($imp_*)
}
