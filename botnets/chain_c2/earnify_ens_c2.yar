rule Linux_Earnify_ENS_Announcement_C2_Resolver
{
    meta:
        description = "Earnify: Rust bot presented as a bandwidth-sharing client and Android SDK, with flood, tunnel and exec modules. Reads a ChaCha20-Poly1305 encrypted server announcement from the ENS text record proof; later builds mask every string with an unseeded SplitMix64 sequence"
        author = "Tao Goldi"
        date = "2026-11-05"
        version = "1.0"
        family = "Earnify"
        sha256 = "37bdcdb26c04c38ee4c123fd986dc0f8c0449fc8456fe25dd7f4fd9d0a1c8d7f"
        sha256_2 = "a4e560c61861c4c3d6d614217d93f38fadea8ee6b127ccd85618ff4312582600"
    strings:
        $call = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"" ascii
        $m1 = "ENS text record is empty" ascii
        $m2 = "no resolver set for this ENS name" ascii
        $m3 = "Failed to decrypt ENS announcement" ascii
        $a1 = "earnify-core/src/" ascii
        $a2 = "io_earnify_sdk" ascii
        $a3 = "Earnify Client" ascii
        $name = "russianaltushkawantsdickinside.eth" ascii
        $name_masked = { dd b4 bd 9e a3 3b 6e b6 5a 10 bf ee 6b 94 5f 72 66 0d 46 37 e8 ae 69 bd 2d 67 a9 e3 08 15 e0 8f 75 c0 }
        $key = "am-yisrael-chai-from-the-river!!" ascii
        $key_masked = { ce ac e3 94 a3 29 72 b6 53 08 e7 fe 6b 9e 57 28 61 11 5d 29 a1 b3 62 b3 69 7b b3 fc 09 02 ef cb }
    condition:
        uint32(0) == 0x464c457f and filesize < 8MB and $call and 1 of ($m*)
        and (1 of ($a*) or $name or $name_masked or $key or $key_masked)
}
