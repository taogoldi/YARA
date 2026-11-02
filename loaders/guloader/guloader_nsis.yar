/*
    GuLoader NSIS-Stage Detection Rules
    Family: GuLoader (a.k.a. CloudEye, VBdropper, vbdropper)
    Variant: NSIS-3 Unicode shellcode-based loader (2025 campaign cluster)

    Reference sample:
        SHA256: 39c0135a0e8d46053fbcaa4efe6cbc83d33cf8e7be43efbca1622b2f77c7b9c6
        File:   agestole.exe (decoy filename in version info)
        Compile time: 2025-03-08 23:05:20 UTC

    Detection strategy:
        - GuLoader_NSIS_Outer matches the outer NSIS-3 dropper PE of the
          2025 cluster (its version-info decoy text).
        - GuLoader_NSIS_DroppedScriptArtifacts matches the same cluster's
          inflated NSIS headers / decoy text files extracted to %TEMP%.
        - GuLoader_NSIS_DecoyPadding is the family-level rule: it catches the
          multi-megabyte padding files the installers drop, across clusters.

    Why there is no family-wide rule for the outer installer: about 95% of
    GuLoader PEs are NSIS installers, and their stub is the stock NSIS stub.
    The script, the file names and the shellcode sit in the LZMA-compressed
    header and data blocks, so no string in the outer file separates
    GuLoader from a benign NSIS installer. GuLoader_NSIS_Generic, which
    keyed on the 2025 cluster's version-info text exactly like
    GuLoader_NSIS_Outer, was removed in November 2026 as a duplicate. Scan
    the extracted members (7-Zip: 7z x -tNsis) for family coverage.

    Author: Tao Goldi
    Date:   2026-04
*/

import "pe"
import "math"

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
        description = "GuLoader filesize-inflation decoy dropped by the NSIS stage: megabytes of one fill byte with data scattered through it"
        author = "Tao Goldi"
        date = "2026-04"
        version = 3
        severity = "medium"
        family = "GuLoader"
        notes = "Run on the files extracted from the installer (7z x -tNsis). v3 replaces the 64-byte run counts of v1/v2, which matched any file with long runs of 0x5A, 0xB7 or 0xAC (92 other-family samples, 2 benign files) and hit the YARA match limit on large files. Measured on the reference sample: Maynard.pen (8.9 MB) and Ganocephala176.ham (8.6 MB) are 99.0% one byte (0x5A, 0xB7) with all 256 values present; piasaba is not padding (7.6% 0xAC). Matches a padding member in 48 of 299 GuLoader installers and in none of the 57,653 members of 178 benign NSIS installers."

    condition:
        filesize > 1MB and
        uint16(0) != 0x5A4D and
        // the fill byte opens the file and is still there half way through;
        // zero and 0xFF fills are left to sparse files and disk images
        uint8(0) != 0x00 and uint8(0) != 0xFF and
        uint8(0) == uint8(filesize \ 2) and
        math.percentage(uint8(0)) > 0.95 and
        // not a pure fill: the scattered bytes give a little entropy
        math.entropy(0, filesize) > 0.05
}

