/*
   VioletRAT v6 (a.k.a. VioletWorm) - VB.NET commodity RAT / stealer / clipper
   Author: taogoldi
   Reference sample: 2bf04b9a583e6f1efa661a43d357bc8ea143bcb53fa87f81081347ee2feb80eb

   Note: this is a .NET assembly; user strings live in the #US heap as UTF-16LE,
   so the obfuscated Base64 markers are matched with the `wide` modifier.
*/

import "pe"

rule VioletRAT_v6_strings
{
    meta:
        description = "VioletRAT v6 (VioletWorm) VB.NET stub - obfuscated string layer and family markers"
        author      = "taogoldi"
        version     = 1
        date        = "2026-06-25"
        hash        = "2bf04b9a583e6f1efa661a43d357bc8ea143bcb53fa87f81081347ee2feb80eb"
        tlp         = "TLP:CLEAR"
        family      = "VioletRAT"

    strings:
        // family / version self-identification (Base64-encoded, stored UTF-16LE)
        $violet_tag = "PFZpb2xldD4=" wide      // "<Violet>"  (C2 field separator + tag)
        $violet_ver = "VmlvbGV0IHY2" wide      // "Violet v6"
        $aes_pw     = "WFNYU1hTWA==" wide      // "XSXSXSX"   (default AES password)
        $xor_key    = "VEZpSUpyUA==" wide      // "TFiIJrP"   (string-layer XOR key)

        // VB.NET runtime markers
        $vb1 = "Microsoft.VisualBasic" ascii
        $clr = "_CorExeMain" ascii

    condition:
        uint16(0) == 0x5A4D and pe.number_of_sections >= 2 and
        $clr and $vb1 and
        2 of ($violet_tag, $violet_ver, $aes_pw, $xor_key)
}

rule VioletRAT_v6_winrar_masquerade
{
    meta:
        description = "VioletRAT v6 builds that spoof WinRAR 7.x version info with internal name antimalwaver.exe"
        author      = "taogoldi"
        version     = 1
        date        = "2026-06-25"
        hash        = "2bf04b9a583e6f1efa661a43d357bc8ea143bcb53fa87f81081347ee2feb80eb"
        tlp         = "TLP:CLEAR"
        family      = "VioletRAT"

    strings:
        $company  = "Alexander Roshal" wide
        $product  = "WinRAR" wide
        $internal = "antimalwaver.exe" wide
        $violet   = "VmlvbGV0IHY2" wide       // "Violet v6"

    condition:
        uint16(0) == 0x5A4D and
        $violet and 2 of ($company, $product, $internal)
}

rule VioletRAT_v6_command_protocol
{
    meta:
        description = "VioletRAT v6 C2 command tokens and WMI AV enumeration (Base64 literals, UTF-16LE)"
        author      = "taogoldi"
        version     = 1
        date        = "2026-06-25"
        hash        = "2bf04b9a583e6f1efa661a43d357bc8ea143bcb53fa87f81081347ee2feb80eb"
        tlp         = "TLP:CLEAR"
        family      = "VioletRAT"

    strings:
        // plaintext command markers, stored as Base64 in the #US heap
        $c1 = "JWNvbW1hbmRTZW5kRmlsZSU=" wide   // "%commandSendFile%"
        $c2 = "JWNvbW1hbmQ2NCU=" wide           // "%command64%"
        $c3 = "JWNvbW1hbmQ2NSU=" wide           // "%command65%"
        $c4 = "JWNvbW1hbmQ3MSU=" wide           // "%command71%"
        // WMI AV enumeration used by the stub (Base64)
        $w1 = "U2VsZWN0ICogZnJvbSBBbnRpdmlydXNQcm9kdWN0" wide  // "Select * from AntivirusProduct"
        $w2 = "XHJvb3RcU2VjdXJpdHlDZW50ZXIy" wide              // "\root\SecurityCenter2"

    condition:
        uint16(0) == 0x5A4D and
        (3 of ($c*) and 1 of ($w*))
}

rule VioletRAT_v6_amsi_bypass
{
    meta:
        description = "VioletRAT v6 in-memory AMSI bypass (AmsiScanBuffer patch) tied to the Violet plugin loader"
        author      = "taogoldi"
        version     = 1
        date        = "2026-06-25"
        hash        = "2bf04b9a583e6f1efa661a43d357bc8ea143bcb53fa87f81081347ee2feb80eb"
        tlp         = "TLP:CLEAR"
        family      = "VioletRAT"

    strings:
        $amsi   = "amsi.dll" wide
        $proc   = "AmsiScanBuffer" wide
        $vp     = "VirtualProtect" ascii
        $gpa    = "GetProcAddress" ascii
        $violet = "VmlvbGV0IHY2" wide        // "Violet v6"

    condition:
        uint16(0) == 0x5A4D and
        $amsi and $proc and $vp and $gpa and $violet
}
