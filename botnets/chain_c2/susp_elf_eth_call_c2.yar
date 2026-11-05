rule SUSP_ELF_EthCall_C2_Resolver
{
    meta:
        description = "ELF that carries a hand-built eth_call JSON-RPC request: seen in Linux bots that keep their C2 address in a smart contract or an ENS record (Boatnet, Kimwolf, several Mirai forks)"
        author = "Tao Goldi"
        date = "2026-11-05"
        version = "1.2"
        heuristic = "true"
    strings:
        $m1 = "\"method\":\"eth_call\",\"params\":[{\"to\":\"" ascii
        $m2 = "\"method\":\"eth_call\",\"params\":[{\"data\":\"" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 10MB and 1 of them
}
