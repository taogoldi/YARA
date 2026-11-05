rule Linux_Boatnet_Polygon_C2_Resolver
{
    meta:
        description = "Boatnet Linux bot: reads its encrypted C2 list from a Polygon contract with a hard-coded eth_call to get() (0x6d4ce63c)"
        author = "Tao Goldi"
        date = "2026-11-05"
        version = "1.0"
        family = "Boatnet"
        sha256 = "de1733fa9e993bd7cd54e0e1998ef2024f593592cb6be7a370120ba6d625c796"
        sha256_2 = "d12cd0ac7f6d8b48c3422c5a0c4a1d232109d995433b0a295935b951fab2fd28"
        note = "UPX-packed copies (dcfe5f3e03e2c249...) match after unpacking only"
    strings:
        $call = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"" ascii
        $tail = "\"},\"latest\"],\"id\":1}" ascii
        $get = "6d4ce63c" ascii
        $res = "result\":\"0x" ascii
        $b1 = "boat_mutex_v" ascii
        $b2 = "boatnet-unit" ascii
        $b3 = ".upd_boat" ascii
        $k1 = ".ksoftirqd" ascii
        $k2 = ".rcu_sched" ascii
        $k3 = ".kblockd" ascii
        $k4 = ".scsi_eh" ascii
        $k5 = ".ata_sff" ascii
        $k6 = ".cpuhp" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 6MB and $call and $tail and $get and $res
        and (1 of ($b*) or 5 of ($k*))
}
