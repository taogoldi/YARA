/*
   Mozi P2P IoT botnet: the bot itself, and the UPX packing it ships in
   Author: Tao Goldi
   TLP:WHITE

   Mozi builds its peer network on the BitTorrent DHT, takes over routers through their TR-069 management settings,
   and closes the ports it came in through with iptables. Almost every copy in the wild is a 32-bit MIPS or ARM ELF
   packed with UPX and then damaged on purpose: the three p_info fields after UPX's l_info header are zeroed and the
   trailing PackHeader is wiped, so `upx -d` refuses the file ("header corrupted"). The compressed blocks are
   intact, and a short NRV2B decoder recovers the bot.

   Linux_Mozi_Payload matches the bot: the closing tags of its signed configuration ([/cnc], [/atk], [/dip], ...),
   plus either the DHT bootstrap nodes or one of its own paths and router settings (/usr/networks, "acsMozi",
   S95baby.sh, notitms). Use it on unpacked copies and on memory.

   Linux_Mozi_UPX_Tampered matches the packed form by the tampering alone: an ELF32 file with UPX's l_info, all
   three p_info fields zero and no PackHeader. It says nothing about the content. In a corpus of 193,379 ELF files
   it matched 771, and every one of the 339 that decoded far enough to read was Mozi (the rest are truncated
   copies). Another family adopting the same trick would match too, so confirm with the payload rule after
   decoding when it matters.
*/

rule Linux_Mozi_Payload
{
    meta:
        description  = "Mozi P2P IoT bot (unpacked): configuration closing tags plus BitTorrent DHT bootstrap nodes or Mozi's own paths and TR-069 settings"
        author       = "Tao Goldi"
        reference    = "https://taogoldi.github.io/reverse-engineer/"
        date         = "2026-11-04"
        version      = 1
        family       = "Mozi"
        severity     = "high"
        mitre_attack = "T1190, T1562.004, T1090.003"
        scope        = "file, memory"
        sha256       = "003d54ad5c9f8105ec03c0e6e52b9bcd414fde4a7812ff7335ad1394b5ea1fc5"

    strings:
        // closing tags of the signed configuration block
        $t1 = "[/cnc]" ascii
        $t2 = "[/atk]" ascii
        $t3 = "[/dip]" ascii
        $t4 = "[/ver]" ascii
        $t5 = "[/cpu]" ascii
        $t6 = "[/count]" ascii
        // DHT bootstrap nodes
        $d1 = "dht.transmissionbt.com:6881" ascii
        $d2 = "router.bittorrent.com:6881" ascii
        $d3 = "router.utorrent.com:6881" ascii
        $d4 = "bttracker.debian.org:6881" ascii
        // its own paths and router settings
        $m1 = "/usr/networks" ascii
        $m2 = "\"acsMozi\"" ascii
        $m3 = "/etc/init.d/S95baby.sh" ascii
        $m4 = "ConnectionRequestUsername notitms" ascii

    condition:
        uint32be(0) == 0x7f454c46 and
        filesize < 8MB and
        3 of ($t*) and
        (2 of ($d*) or any of ($m*))
}

rule Linux_Mozi_UPX_Tampered
{
    meta:
        description  = "Mozi packed form: ELF32 UPX file whose p_info fields are zeroed and whose PackHeader is wiped, so upx -d refuses it; a packer trait, confirm with Linux_Mozi_Payload after decoding"
        author       = "Tao Goldi"
        reference    = "https://taogoldi.github.io/reverse-engineer/"
        date         = "2026-11-04"
        version      = 1
        family       = "Mozi"
        severity     = "medium"
        mitre_attack = "T1027.002"
        scope        = "file"
        sha256       = "05d459c9f944cbc3586ceac0c277268e5c611fb9962bab9744dc2893b23ee248"

    strings:
        $upx = "UPX!"

    condition:
        uint32be(0) == 0x7f454c46 and
        uint8(4) == 1 and                      // ELF32
        filesize < 4MB and
        #upx == 1 and                          // l_info only: the trailing PackHeader is gone
        @upx[1] < 0x400 and
        uint32(@upx[1] + 8) == 0 and           // p_info.p_progid
        uint32(@upx[1] + 12) == 0 and          // p_info.p_filesize
        uint32(@upx[1] + 16) == 0              // p_info.p_blocksize
}
