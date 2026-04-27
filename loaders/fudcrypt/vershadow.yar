import "pe"

rule VerShadow_Loader
{
    meta:
        author      = "Tao Goldi"
        description = "VerShadow: 64-bit MinGW DLL that masquerades as VERSION.dll, ETW+AMSI bypass, downloads and runs a .NET assembly from catbox.moe (FUD Crypt VERSION.dll carrier)"
        family      = "FUD Crypt"
        reference   = "c73947cf188f442bed228f62a3ba5611009fdc2f1878aaed7065db95ede05521"
        date        = "2026-04-26"
        version     = 1
        tlp         = "white"
        // Notes for hunters:
        // - $rc4key and $key32 are likely PER-BUILD on the FUD Crypt platform; they
        //   may not match other carriers. The condition therefore weights structural
        //   signals (URL fragments, ROR-13 hashes, resolver body, AMSI bypass shape)
        //   so a build with rotated keys still hits.
        // - $url* fragments will rotate when the operator changes the catbox path.
        // - $h_etw, $h_amsi, $resolver, $amsi_xor, $antidbg, $amsi_einval encode the
        //   loader's tradecraft and should survive routine builder rebuilds.
        // - PE module gates (VERSION.dll exports + WININET + SetThreadContext) keep
        //   false positives near zero across normal MinGW DLL corpora.

    strings:
        // catbox.moe URL stack-string fragments materialised in DoWork
        $url1 = { 68 74 74 70 73 3A 2F 2F }                          // "https://"
        $url2 = { 66 69 6C 65 73 2E 63 61 }                          // "files.ca"
        $url3 = { 74 62 6F 78 2E 6D 6F 65 }                          // "tbox.moe"

        // ROR-13 hashes of the resolved targets, written as imm32 in the
        // "mov edx, <hash>" instructions before calls into the resolver.
        $h_etw   = { BA EE C3 47 20 }                                // mov edx, 0x2047C3EE  (ntdll!EtwEventWrite)
        $h_amsi  = { BA 1E 15 50 95 }                                // mov edx, 0x9550151E  (amsi!AmsiScanBuffer)

        // ROR-13 GetProcAddress-by-hash core: "ror edx, 0x0d ; add rcx,1 ; add edx,eax"
        $resolver = { C1 CA 0D 48 83 C1 01 01 C2 0F BE 01 84 C0 75 F0 }

        // RC4 key in .data (likely per-build; may not match other FUD Crypt carriers)
        $rc4key = { 30 89 F0 10 89 76 26 B2 35 AC 34 72 3F 5E D6 4C }

        // 32-byte secondary post-RC4 key in .data, immediately after the RC4 key
        // (also likely per-build)
        $key32  = { 32 55 80 3F 11 5D 04 01 41 45 C5 D6 85 F6 FB 26
                    E1 E5 31 5F D3 E2 06 DD 6C B2 16 07 F2 97 CB 63 }

        // amsi.dll string XOR-encoded with 0x11 (decoded inline before LoadLibraryA)
        $amsi_xor = { 70 7C 62 78 3F 75 7D 7D }

        // Anti-debug XOR constant baked into the decoy branch
        $antidbg  = { 35 B2 BD 05 67 }                               // xor eax, 0x6705BDB2

        // VEH-driven AMSI bypass: writes E_INVALIDARG (0x80070057) into Rax-slot of CONTEXT
        $amsi_einval = { BA 57 00 07 80 41 B8 FF FF FF FF }

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        pe.machine == pe.MACHINE_AMD64 and
        // Sample is a DLL that proxies VERSION.dll exports.
        pe.exports("VerQueryValueA") and
        pe.exports("GetFileVersionInfoA") and
        pe.imports("WININET.dll", "InternetOpenUrlA") and
        pe.imports("KERNEL32.dll", "CheckRemoteDebuggerPresent") and
        pe.imports("KERNEL32.dll", "SetThreadContext") and
        // Three of the nine distinctive byte patterns must hit. Even if both keys
        // ($rc4key, $key32) and all three URL fragments rotate, the four tradecraft
        // patterns ($h_etw, $h_amsi, $resolver, $amsi_einval, $amsi_xor, $antidbg)
        // give a 4-of-6 cushion that still trips this rule on rebuilds.
        3 of ($url*, $h_etw, $h_amsi, $resolver, $rc4key, $key32, $amsi_xor, $antidbg, $amsi_einval)
}

rule VerShadow_Resolver_Generic
{
    meta:
        author      = "Tao Goldi"
        description = "Generic match for the ROR-13 GetProcAddress-by-hash resolver body, as shipped in the FUD Crypt VERSION.dll carrier and in many other 64-bit MinGW loaders"
        date        = "2026-04-26"
        version     = 1
        tlp         = "white"
        // Known false-positive surface: the ROR-13 hash resolver pattern is widely
        // copy-pasted across the offensive-tooling ecosystem. This rule will also
        // hit on:
        //   - Cobalt Strike beacon stagers using the classic ROR-13 PEB walk
        //   - Metasploit reverse_https stagers
        //   - Public sRDI / DonutLoader templates
        //   - Reflective DLL loaders compiled with MinGW
        // Triage hits with the gating PE characteristics from VerShadow_Loader, or
        // pair this rule with corpus-based scoring.

    strings:
        // The full body of ZI7vPLTiiXSV: hash inner loop + post-loop import lookup arithmetic
        $resolver_body = {
            C1 CA 0D                  // ror edx, 0xd
            48 83 C1 01               // add rcx, 1
            01 C2                     // add edx, eax
            0F BE 01                  // movsx eax, byte ptr [rcx]
            84 C0                     // test al, al
            75 F0                     // jne <top>
            44 39 DA                  // cmp edx, r11d
        }

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        pe.machine == pe.MACHINE_AMD64 and
        $resolver_body
}
