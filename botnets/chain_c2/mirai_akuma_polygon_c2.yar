rule Linux_Mirai_Akuma_Polygon_C2_Resolver
{
    meta:
        description = "Mirai fork (bot id akuma.*): resolves its C2 from a Polygon contract; contract, selector and port are hidden as XOR shares, the reply is a fake 2001:db8:: IPv6 string"
        author = "Tao Goldi"
        date = "2026-11-05"
        version = "1.0"
        family = "Mirai"
        sha256 = "15d10a6db45fd36d394efa01528a05706afb9021fcf7d5f97e1af205acd65199"
        sha256_2 = "16f650696596a2b46a317d17e8c9b7e6a1dfc65d843a50769b87dd3944417d7e"
        sha256_3 = "a5329baa1b3530c4f1df576e5e2f02bf565c491e69b465050ce6e139be2b37f9"
    strings:
        $fmt = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"%s\",\"data\":\"%s\"},\"latest\"],\"id\":1}" ascii
        $len = "%8lx" ascii
        $res = "\"result\"" ascii
        $r1 = "polygon-bor-rpc.publicnode.com" ascii
        $r2 = "polygon.drpc.org" ascii
        $r3 = "rpc-polygon.blockmachine.io" ascii
        $r4 = "poly.api.pocket.network" ascii
        $r5 = "matic.rpc.sentio.xyz" ascii
        $r6 = "polygon-bor-rpc.blockreq.com" ascii
        $id = "akuma." ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 6MB and $fmt and $len and $res and (2 of ($r*) or $id)
}
