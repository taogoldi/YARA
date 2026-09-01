/*
   AnimateClipper stage-1 NativeAOT loader
   Author: taogoldi
   TLP:WHITE
*/

import "pe"
import "math"

rule AnimateClipper_StringDecryptor_Constants
{
    meta:
        author      = "taogoldi"
        reference   = "https://taogoldi.github.io/reverse-engineer/blog/animateclipper-nativeaot-loader/"
        license     = "Apache-2.0"
        date        = "2026-08-01"
        version     = 1
        description = "AnimateClipper stage-1 keystream string decryptor constant triplet"
        hash        = "21bf44a654a0059f7bb974ffe6252db63e998d5f95937454d45da4d700267471"
        tlp         = "TLP:WHITE"
        fidelity    = "high"

    strings:
        // Full instruction encodings from the key schedule at 0x14000134E.
        // Far more specific than the bare constants, which also occur in
        // benign code that uses the same well-known values.
        $seed_xor  = { 81 F3 D5 C1 B3 A7 }        // xor ebx, 0A7B3C1D5h
        $golden    = { 81 F3 B9 79 37 9E }        // xor ebx, 09E3779B9h
        $rol13     = { C1 C3 0D }                 // rol ebx, 13
        $mt_imul   = { 69 C1 65 89 07 6C }        // imul r8d, ecx, 6C078965h

    condition:
        uint16(0) == 0x5A4D and
        all of them
}

rule AnimateClipper_Loader_GfxSection
{
    meta:
        author      = "taogoldi"
        reference   = "https://taogoldi.github.io/reverse-engineer/blog/animateclipper-nativeaot-loader/"
        license     = "Apache-2.0"
        date        = "2026-08-01"
        version     = 1
        description = "NativeAOT loader carrying an encrypted payload in a .gfx section"
        hash        = "21bf44a654a0059f7bb974ffe6252db63e998d5f95937454d45da4d700267471"
        tlp         = "TLP:WHITE"
        fidelity    = "medium"

    strings:
        $aot1 = "System.Private.TypeLoader.dll" ascii
        $aot2 = "System.Private.Reflection.Execution" ascii
        $mod  = "Moonshine.Core.dll" ascii

    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_sections >= 6 and
        for any i in (0 .. pe.number_of_sections - 1) : (
            pe.sections[i].name == ".gfx" and
            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.9
        ) and
        2 of ($aot1, $aot2, $mod)
}

rule AnimateClipper_Composite
{
    meta:
        author      = "taogoldi"
        reference   = "https://taogoldi.github.io/reverse-engineer/blog/animateclipper-nativeaot-loader/"
        license     = "Apache-2.0"
        date        = "2026-08-01"
        version     = 1
        description = "AnimateClipper stage-1: keystream constants + NativeAOT + aethsync identity"
        hash        = "21bf44a654a0059f7bb974ffe6252db63e998d5f95937454d45da4d700267471"
        tlp         = "TLP:WHITE"
        fidelity    = "high"

    strings:
        $seed_xor  = { 81 F3 D5 C1 B3 A7 }       // xor ebx, 0A7B3C1D5h
        $golden    = { 81 F3 B9 79 37 9E }       // xor ebx, 09E3779B9h
        $rol13     = { C1 C3 0D }                // rol ebx, 13
        $mt_imul   = { 69 C1 65 89 07 6C }       // imul r8d, ecx, 6C078965h
        $aeth      = "aethsync" ascii wide
        $moon      = "Moonshine.Core" ascii

    condition:
        uint16(0) == 0x5A4D and
        pe.machine == pe.MACHINE_AMD64 and
        all of ($seed_xor, $golden, $rol13, $mt_imul) and
        1 of ($aeth, $moon)
}

rule AnimateClipper_PayloadContainer
{
    meta:
        author      = "taogoldi"
        reference   = "https://taogoldi.github.io/reverse-engineer/blog/animateclipper-nativeaot-loader/"
        license     = "Apache-2.0"
        date        = "2026-08-28"
        version     = 1
        description = "AnimateClipper encrypted stage-2 container carried as a PE overlay"
        hash        = "be06aab9e611d76a76f37a89cdef1df2ea59e591ff2654c8c679bfed0f7710bb"
        hash2       = "3ee1860c0f5353263b70752681bd78872a5b9abf642b93669993f28f83933215"
        tlp         = "TLP:WHITE"
        fidelity    = "medium"

    strings:
        // Container header: 4-byte magic followed by a little-endian length.
        // The earlier builds append the encrypted stage 2 to the file rather
        // than parking it in a .gfx section, so the rules above that key on
        // section layout do not see it.
        $magic = { 42 EE FF C0 }

    condition:
        uint16(0) == 0x5A4D and
        // Requiring the length field to describe exactly the bytes remaining
        // is what makes a four-byte magic safe to match on. A chance
        // occurrence will not also be self-consistent with the file size.
        for any i in (1 .. #magic) : (
            uint32(@magic[i] + 4) == filesize - @magic[i] - 8 and
            uint32(@magic[i] + 4) > 65536 and
            math.entropy(@magic[i] + 8, uint32(@magic[i] + 4)) > 7.9
        )
}
