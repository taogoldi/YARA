/*
   Diicot (Mexals) shc-compiled installers and the scripts inside them
   Author: Tao Goldi
   TLP:WHITE

   Diicot, a Romanian cryptojacking group, ship their bash installers as shc-compiled x86-64 ELF files. shc stores
   the script RC4-encrypted in .data, so the ELF carries nothing of the script in clear. The builds covered here
   are statically linked, compiled at -O2 with the .comment section stripped, and the compiler inlined shc's
   RC4 key schedule into chkenv() and key_with_file(). Those inlined sequences come from Diicot's own build
   toolchain: other shc builds in the same corpus (static Ubuntu GCC 9.4, Red Hat GCC 4.8, dynamic builds,
   and a fresh Debian GCC 12 static -O2 build) do not contain them.

   Linux_Diicot_SHC_Wrapper matches the compiled ELF. It is a build-cluster rule: anyone who compiles shc with
   the same toolchain and options would match it too, so recover the script (any shc decoder) to confirm.

   The two script rules match the decrypted bash: the miner installer that downloads .report_system into
   /var/tmp/.rcu_gp and sets up cron persistence, and the SSH brute-force launcher (ps, brute, bios.txt, retele).
*/

import "elf"

rule Linux_Diicot_SHC_Wrapper
{
    meta:
        description  = "Diicot (Mexals) shc-compiled bash installer, x86-64 static build: shc runtime strings plus the RC4 key schedule as inlined by Diicot's build toolchain (chkenv self-keying, key_with_file stat buffer)"
        author       = "Tao Goldi"
        reference    = "https://taogoldi.github.io/reverse-engineer/"
        date         = "2026-11-03"
        version      = 1
        family       = "Diicot"
        severity     = "high"
        mitre_attack = "T1027.002, T1059.004, T1496"
        scope        = "file"
        sha256       = "f6371d8b3bcc784017d4fbb544550873281cdc4aa4167ffac91526126d3b4e01"

    strings:
        $shc1 = "E: neither argv[0] nor $_ works." ascii
        $shc2 = "=%lu %d" ascii
        $shc3 = "%lu %d%c" ascii
        // chkenv(): stte_0() state fill, then key() over the function's own code bytes
        $k1 = { 88 04 11 83 C0 01 3D 00 01 00 00 75 F0 4C 8D 0D ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 4C 29 C8 41 89 C0 85 C0 0F 8E }
        // key_with_file(): struct stat fields copied into the key buffer
        $k2 = { 48 8B 44 24 1C 48 89 84 24 AC 00 00 00 48 8B 44 24 30 48 89 84 24 C0 00 00 00 48 8B 44 24 58 48 89 84 24 E8 00 00 00 }
        // inlined key(buf, 144): index % sizeof(struct stat) by multiply-shift
        $k3 = { 48 69 D2 39 8E E3 38 46 0F B6 0C 17 48 C1 EA 25 }

    condition:
        uint32(0) == 0x464c457f and
        filesize < 4MB and
        elf.machine == elf.EM_X86_64 and
        ($shc1 or ($shc2 and $shc3)) and
        2 of ($k*)
}

rule Linux_Diicot_Miner_Installer_Script
{
    meta:
        description  = "Diicot (Mexals) miner installer bash script (the payload of the shc wrapper): downloads .report_system from a /.puscarie/ path into /var/tmp/.rcu_gp, writes the 'diicot' watchdog and cron persistence, Romanian messages"
        author       = "Tao Goldi"
        reference    = "https://taogoldi.github.io/reverse-engineer/"
        date         = "2026-11-03"
        version      = 1
        family       = "Diicot"
        severity     = "high"
        mitre_attack = "T1053.003, T1105, T1496"
        scope        = "file"
        sha256       = "2130bc318632f761c9d503b9731f2ed93690e7940462d1903bd88789a3222d0f"

    strings:
        $a1 = "/var/tmp/.rcu_gp" ascii
        $a2 = "/.puscarie/.report_system" ascii
        $a3 = "DIICOT_FILE=" ascii
        $a4 = "create_diicot_file" ascii
        $a5 = "Nu s-a gasit nici wget, nici curl" ascii
        $a6 = "Merge bn mineru serifule" ascii
        $b1 = ".report_system" ascii
        $b2 = "/.ps4" ascii
        $b3 = "/.ps5" ascii

    condition:
        filesize < 64KB and
        (2 of ($a*) or ($a1 and 2 of ($b*)))
}

rule Linux_Diicot_SSH_Brute_Launcher_Script
{
    meta:
        description  = "Diicot (Mexals) SSH scan-and-brute launcher bash script (the payload of the shc wrapper): runs ./ps over a network class on port 22, then ./brute with bios.txt, Romanian usage and error messages"
        author       = "Tao Goldi"
        reference    = "https://taogoldi.github.io/reverse-engineer/"
        date         = "2026-11-03"
        version      = 1
        family       = "Diicot"
        severity     = "high"
        mitre_attack = "T1110.001, T1046"
        scope        = "file"
        sha256       = "5d53373e8dcf5ab6f9ae2976b02c7d6907f07849507cd41e6db296a25c132882"

    strings:
        $usage = "Utilizare: $0 <clasa>" ascii
        $error = "Eroare: Fisierul 'ps' nu exista." ascii
        $scan  = "./ps \"$clasa\" \"$port\"" ascii
        $brute = /\.\/brute [0-9]{2,5} "?bios\.txt"? pass/ ascii
        $net   = "retele" ascii

    condition:
        filesize < 16KB and
        3 of them
}
