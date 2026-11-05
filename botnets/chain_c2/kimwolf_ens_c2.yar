rule Linux_Kimwolf_ENS_Addr_C2_Resolver
{
    meta:
        description = "Kimwolf Linux bot: resolves a .eth name's address record through the ENS registry and XORs the last four bytes (93 14 17 15) into its C2 IPv4; strings sit in a per-entry xorshift table"
        author = "Tao Goldi"
        date = "2026-11-05"
        version = "1.0"
        family = "Kimwolf"
        sha256 = "25418594755f57298e0f0c81a91205c28c0af91709af755e919d4b896ccce212"
    strings:
        $call = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"0x%s\",\"data\":\"0x%s\"},\"latest\"],\"id\":1}" ascii
        $eth = ".eth\x00" ascii
        $s1 = "%s/%s%08x.lock" ascii
        $s2 = "%s/bot" ascii
        $s3 = "%s.new" ascii
        $s4 = "%s.bak" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 4MB and $call and $eth and 3 of ($s*)
}
