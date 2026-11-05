rule Linux_Mirai_ENS_Ouroboros_C2_Resolver
{
    meta:
        description = "Mirai-based bot that reads its C2 from the ENS text record 'ouroboros' of bossmen.eth: value '::ffff:x:x:x', six bytes XOR 0xDE = IPv4 and port"
        author = "Tao Goldi"
        date = "2026-11-05"
        version = "1.0"
        family = "Mirai"
        sha256 = "6b4b3724c21b93a773823853c561d4da1b2d216879f30d40c20965cbef66f50e"
    strings:
        $call = "\"method\":\"eth_call\"" ascii
        $resolver = "0x0178b8bf" ascii
        $text = "0x59d1d43c" ascii
        $key = "ouroboros" ascii
        $name = "bossmen.eth" ascii
        $fmt = "%x:%x:%x" ascii
        $v6 = "::ffff:" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 4MB and $call and $resolver and $text
        and ($name or ($key and $fmt and $v6))
}

rule Linux_Mirai_ENS_Rc4_TextRecord_C2_Resolver
{
    meta:
        description = "Mirai-based bot that reads an RC4-encrypted IPv4 from an ENS text record (key 'GET/dlr.'); the name sits in an RC4 string table. Second form asks the ENS universal resolver"
        author = "Tao Goldi"
        date = "2026-11-05"
        version = "1.0"
        family = "Mirai"
        sha256 = "15466df1a1f5d04f6e3b3a7628c2ddea263266acc7d28cb6c6217b595c2e42e4"
        sha256_2 = "9387db1c3801abb24e49d8a1cc7878dffb09588017d957be29a35720137c29ab"
    strings:
        $call = "\"method\":\"eth_call\"" ascii
        $a1 = "\"data\":\"0x0178b8bf%s\"" ascii
        $a2 = "0x59d1d43c%s" ascii
        $a3 = "%2x%2x%2x%2x" ascii
        $b1 = "User-Agent: ens-resolver/1.0" ascii
        $b2 = "resolve(bytes,bytes)" ascii
        $k = "GET/dlr." ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 4MB and $call and $k and (all of ($a*) or all of ($b*))
}

rule Linux_Bot_ENS_ProxyIps_C2_Resolver
{
    meta:
        description = "Linux bot that reads a comma-separated IPv4 list from the ENS text record 'proxy.ips' of a hard-coded node"
        author = "Tao Goldi"
        date = "2026-11-05"
        version = "1.0"
        sha256 = "80faa91681af2522632deab56bb2200ec51f795f0b8d8d0506014d724a54b040"
    strings:
        $call = "\"method\":\"eth_call\"" ascii
        $resolver = "0x0178b8bf" ascii
        $text = "0x59d1d43c" ascii
        $key = "970726f78792e697073" ascii      // length 9, "proxy.ips"
    condition:
        uint32(0) == 0x464c457f and filesize < 4MB and all of them
}

rule Linux_Mirai_ENS_IpRecords_C2_Resolver
{
    meta:
        description = "Mirai/Gafgyt-based DVR bot that reads IPv4 text records (ip, ip2 .. ip14) of an ENS name and swaps their two halves (record C.D.A.B is host A.B.C.D); name, RPC hosts and record keys sit in a ChaCha20 string table"
        author = "Tao Goldi"
        date = "2026-11-05"
        version = "1.1"
        family = "Mirai"
        sha256 = "3461b097ea026c9161113f0f590e75c47908cebd3d6a30de3b821c10a85ea9fc"
    strings:
        $call = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"0x%s\",\"data\":\"%s\"},\"latest\"],\"id\":1}" ascii
        $tag = "ens-rpc" ascii
        $hex20 = "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 4MB and all of them
}

rule Linux_Mirai_ENS_Drunkasfk_C2_Resolver
{
    meta:
        description = "Mirai-based bot with the build marker 'drunkasfk': builds its eth_call request by concatenation and resolves an ENS name (2busydrinkingcodeine.eth in the August 2026 builds, hidden later)"
        author = "Tao Goldi"
        date = "2026-11-05"
        version = "1.0"
        family = "Mirai"
        sha256 = "369194a0cfbe5f3524dbe1f3f9726547cbe6bc62a266e8c07e3f14409c78a621"
        sha256_2 = "8e3df94a5ee61add57686c5939b1173aefa8be5814b0e76aec69cbf133cbd53d"
    strings:
        $t1 = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"\x00" ascii
        $t2 = "\",\"data\":\"\x00" ascii
        $t3 = "\"},\"latest\"]}\x00" ascii
        $res = "\"result\":\"0x" ascii
        $marker = "drunkasfk" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 4MB and all of them
}

rule SUSP_ELF_ENS_Registry_Lookup
{
    meta:
        description = "Small ELF that asks the ENS registry or the ENS public resolver for a record over JSON-RPC: Linux bots that keep their C2 address in an ENS record"
        author = "Tao Goldi"
        date = "2026-11-05"
        version = "1.1"
        heuristic = "true"
    strings:
        $call = "\"method\":\"eth_call\"" ascii
        $registry = "00000000000C2E074eC69A0dFb2997BA6C7d2e1e" ascii nocase
        $selector = "0178b8bf" ascii
        $public_resolver = "f29100983e058b709f3d539b0c765937b804ac15" ascii nocase
    condition:
        uint32(0) == 0x464c457f and filesize < 3MB and $call and (($registry and $selector) or $public_resolver)
}
