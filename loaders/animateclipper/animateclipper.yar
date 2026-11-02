/*
   Moonshine loader (C# compiled with NativeAOT), first analysed as the
   AnimateClipper stage-1 loader
   Author: taogoldi
   TLP:WHITE

   The loader is a crypter, not part of AnimateClipper: its own build paths
   name it (F:\Projects\Moonshine-Csharp\out\native\aethsync.pdb,
   MoonshineStub.exe, Moonshine.Core.dll), and builds carry AnimateClipper,
   XWorm, PhantomStealer, Formbook and NeedleStealer. The rules were renamed
   from AnimateClipper_* to Moonshine_Loader_* in November 2026 so that a
   match names the loader rather than one of its payloads.
*/

import "pe"
import "math"

rule Moonshine_Loader_StringDecryptor_Constants
{
    meta:
        author      = "taogoldi"
        reference   = "https://taogoldi.github.io/reverse-engineer/blog/animateclipper-nativeaot-loader/"
        license     = "Apache-2.0"
        date        = "2026-08-01"
        version     = 2
        description = "Moonshine loader keystream string decryptor constants (formerly AnimateClipper_StringDecryptor_Constants)"
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

rule Moonshine_Loader_GfxSection
{
    meta:
        author      = "taogoldi"
        reference   = "https://taogoldi.github.io/reverse-engineer/blog/animateclipper-nativeaot-loader/"
        license     = "Apache-2.0"
        date        = "2026-08-01"
        version     = 2
        description = "Moonshine loader build carrying an encrypted payload in a .gfx section (formerly AnimateClipper_Loader_GfxSection)"
        hash        = "21bf44a654a0059f7bb974ffe6252db63e998d5f95937454d45da4d700267471"
        tlp         = "TLP:WHITE"
        fidelity    = "medium"

    strings:
        $aot1 = "System.Private.TypeLoader.dll" ascii
        $aot2 = "System.Private.Reflection.Execution" ascii
        $mod  = "Moonshine.Core.dll" ascii
        // v2: builds that keep the .gfx section but ship without the NativeAOT
        // reflection metadata still carry the loader's own module name or its
        // build path
        $aeth_exe = "aethsync.exe" ascii wide
        $aeth_dll = "aethsync.dll" ascii wide
        $pdb      = "\\Moonshine-Csharp\\" ascii

    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_sections >= 6 and
        for any i in (0 .. pe.number_of_sections - 1) : (
            pe.sections[i].name == ".gfx" and
            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.9
        ) and
        (
            2 of ($aot1, $aot2, $mod) or
            any of ($aeth_exe, $aeth_dll, $pdb)
        )
}

rule Moonshine_Loader_Composite
{
    meta:
        author      = "taogoldi"
        reference   = "https://taogoldi.github.io/reverse-engineer/blog/animateclipper-nativeaot-loader/"
        license     = "Apache-2.0"
        date        = "2026-08-01"
        version     = 2
        description = "Moonshine loader: keystream constants + aethsync / Moonshine.Core identity (formerly AnimateClipper_Composite)"
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

rule Moonshine_Loader_PayloadContainer
{
    meta:
        author      = "taogoldi"
        reference   = "https://taogoldi.github.io/reverse-engineer/blog/animateclipper-nativeaot-loader/"
        license     = "Apache-2.0"
        date        = "2026-08-28"
        version     = 2
        description = "Moonshine loader encrypted stage-2 container carried as a PE overlay (formerly AnimateClipper_PayloadContainer)"
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

rule XorRamp_Overlay_Inflation
{
    meta:
        author      = "taogoldi"
        reference   = "https://taogoldi.github.io/reverse-engineer/blog/animateclipper-nativeaot-loader/"
        license     = "Apache-2.0"
        date        = "2026-11-02"
        version     = 1
        description = "Size-inflation overlay: whole megabytes of one repeating 4-byte pattern x, x^1, x^2, x^3. Seen on Moonshine loader builds and on unattributed NativeAOT builds filed as AnimateClipper; it marks the inflation step, not a family"
        tlp         = "TLP:WHITE"
        fidelity    = "medium"

    condition:
        uint16(0) == 0x5A4D and
        pe.overlay.size >= 1048576 and
        pe.overlay.size % 1048576 == 0 and
        uint8(pe.overlay.offset + 1) == uint8(pe.overlay.offset) ^ 1 and
        uint8(pe.overlay.offset + 2) == uint8(pe.overlay.offset) ^ 2 and
        uint8(pe.overlay.offset + 3) == uint8(pe.overlay.offset) ^ 3 and
        // the same four bytes at the start, a quarter in, half way and at the end
        uint32(pe.overlay.offset + 4) == uint32(pe.overlay.offset) and
        uint32(pe.overlay.offset + pe.overlay.size \ 4) == uint32(pe.overlay.offset) and
        uint32(pe.overlay.offset + pe.overlay.size \ 2) == uint32(pe.overlay.offset) and
        uint32(filesize - 4) == uint32(pe.overlay.offset)
}
