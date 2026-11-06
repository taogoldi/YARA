rule Linux_Mirai_UNS_IPFS_C2_Resolver
{
    meta:
        description = "Mirai fork that asks the Unstoppable Domains ProxyReader on Base for a domain's IPFS records (getMany of dweb.ipfs.hash and ipfs.html.value) and fetches ips.txt under that content id from a public IPFS gateway. In the build seen the request's array offsets are malformed, so the call reverts and the bot uses the address in its own table"
        author = "Tao Goldi"
        date = "2026-11-05"
        version = "1.0"
        family = "Mirai"
        sha256 = "8388d1a320874a8399e134f8304966a369a7322c590adbcadb4f90a24c32fb41"
    strings:
        $call = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"%s\",\"data\":\"0x%s\"},\"latest\"],\"id\":1}" ascii
        $get_many = "1bd8cc1a00000000000000000000000000000000000000000000000000000000000000400" ascii
        $key1 = "647765622e697066732e68617368" ascii          // dweb.ipfs.hash
        $key2 = "697066732e68746d6c2e76616c7565" ascii        // ipfs.html.value
        $ipfs = "GET /ipfs/%s/ips.txt HTTP/1.1" ascii
        $ua = "User-Agent: bot/1.0" ascii
        $cid1 = "62616679" ascii fullword                     // "bafy", the CIDv1 prefix it looks for in the answer
        $cid0 = "516d" ascii fullword                         // "Qm"
    condition:
        uint32(0) == 0x464c457f and filesize < 4MB and $ipfs and ($get_many or all of ($key*)) and ($call or $ua or all of ($cid*))
}
