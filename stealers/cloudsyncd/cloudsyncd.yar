/*
   CloudSyncD macOS fake installer and its stager
   Author: Tao Goldi
   TLP:WHITE

   The installer fakes an app setup (Zoom, StreamYard and Snair lures seen), asks for the login password in its
   own AuthDialog, checks it with dscl and keeps it, then starts the stager it carries in __TEXT,__const without
   touching disk. The stager installs itself under ~/.local/share/cloudsync and fetches ChaCha20-Poly1305
   encrypted tasks from its server. Both hide their configuration with the cloudsync_impl::sobf string
   obfuscator:

       out[i] = ct[i] ^ K[i & 31] ^ K[salt & 31] ^ ((salt * 0x83 + 0x11 * i) & 0xff)

   C2 servers decoded from the builds seen: bjzhishang[.]com and clampacks[.]com (path /macos/jquery.js).
   They are encrypted in the binaries, so they are IOCs and not YARA strings.
*/

rule CloudSyncD_Sobf_Reveal
{
    meta:
        description = "CloudSyncD sobf::reveal string decoder (x86_64 or arm64 code), present in the installer and the stager"
        author      = "Tao Goldi"
        reference   = "https://taogoldi.github.io/reverse-engineer/"
        date        = "2026-11-01"
        version     = 1
        family      = "CloudSyncD"
        severity    = "high"
        mitre_attack = "T1056.002, T1027, T1553.001, T1620"
        sha256      = "8d13fb2cd4942e7757a3c409ff0efc9e299a1440d3953f8e2f3791c25879c9fd"
        tlp         = "TLP:WHITE"
        fidelity    = "high"

    strings:
        // imul eax, r12d, 0x83 ; and r12d, 31 ; mov rcx, [rip+K] ; movzx edx, byte [rcx+r12]
        $x64_salt = { 41 6B C4 83 41 83 E4 1F 48 8B 0D ?? ?? ?? ?? 42 0F B6 14 21 }
        // add al, 0x11 ; cmp r14, rdi ; je ; mov r9d, edi ; and r9d, 31 ; movzx r8d, [r15+rdi] ;
        // xor r8b, al ; xor r8b, [rcx+r9] ; xor r8b, dl
        $x64_loop = { 04 11 49 39 FE 74 ?? 41 89 F9 41 83 E1 1F 45 0F B6 04 3F 41 30 C0 46 32 04 09 41 30 D0 }
        // mov w9, #0x83 ; mul x9, x22, x9 ; and x11, x22, #0x1f
        $a64_salt = { 69 10 80 52 C9 7E 09 9B CB 12 40 92 }
        // eor w12, w12, w9 ; eor w12, w12, w11 ; eor w12, w12, w13
        $a64_xor  = { 8C 01 09 4A 8C 01 0B 4A 8C 01 0D 4A }
        // add x8, x8, #1 ; add x9, x9, #0x11 ; cmp x20, x8
        $a64_step = { 08 05 00 91 29 45 00 91 9F 02 08 EB }

    condition:
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xBEBAFECA) and
        (($x64_salt and $x64_loop) or all of ($a64_*))
}

rule CloudSyncD_Installer
{
    meta:
        description = "CloudSyncD fake app installer: password dialog classes plus an embedded stager (a second sobf decoder)"
        author      = "Tao Goldi"
        reference   = "https://taogoldi.github.io/reverse-engineer/"
        date        = "2026-11-01"
        version     = 1
        family      = "CloudSyncD"
        severity    = "high"
        mitre_attack = "T1056.002, T1027, T1553.001, T1620"
        sha256      = "8d13fb2cd4942e7757a3c409ff0efc9e299a1440d3953f8e2f3791c25879c9fd"
        tlp         = "TLP:WHITE"
        fidelity    = "high"

    strings:
        $cls1 = "AuthDialog" ascii
        $cls2 = "ModernStatusWindow" ascii
        $cls3 = "CSURLInsecureDelegate" ascii
        $ns   = "14cloudsync_impl" ascii
        $x64_salt = { 41 6B C4 83 41 83 E4 1F 48 8B 0D ?? ?? ?? ?? 42 0F B6 14 21 }
        $a64_salt = { 69 10 80 52 C9 7E 09 9B CB 12 40 92 }

    condition:
        uint32(0) == 0xBEBAFECA and
        (
            (#x64_salt >= 2 or #a64_salt >= 2) or     // the installer's decoder and its stager's
            (all of ($cls*) and $ns)
        )
}

rule CloudSyncD_Config_Symbols
{
    meta:
        description = "CloudSyncD build with its symbol table: sobf config constants named _ct_APP_*"
        author      = "Tao Goldi"
        reference   = "https://taogoldi.github.io/reverse-engineer/"
        date        = "2026-11-01"
        version     = 1
        family      = "CloudSyncD"
        severity    = "high"
        mitre_attack = "T1056.002, T1027, T1553.001, T1620"
        sha256      = "18f071ee32fa5210aaca10ff5310e8747152e3f842d70631b5233eeb7c62da8d"
        tlp         = "TLP:WHITE"
        fidelity    = "high"

    strings:
        $ns  = "14cloudsync_impl4sobf" ascii
        $ct1 = "_ct_APP_OPS_URLE" ascii
        $ct2 = "_ct_APP_OPS_CHACHA_KEYE" ascii
        $ct3 = "_ct_APP_INSTALL_DIRE" ascii
        $ct4 = "_ct_APP_DAEMON_NAMEE" ascii
        $ct5 = "_ct_APP_PROCESS_DISGUISE_NAMEE" ascii
        $ct6 = "_ct_APP_PACKAGE_DAEMON_BINE" ascii
        $ct7 = "_ct_APP_AUTH_JSON_NAMEE" ascii
        $ct8 = "_ct_APP_SPAWN_TEMP_PREFIX_TASKE" ascii

    condition:
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xBEBAFECA) and
        $ns and 3 of ($ct*)
}
