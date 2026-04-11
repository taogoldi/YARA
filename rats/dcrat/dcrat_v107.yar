rule DcRAT_Config_Update35630
{
    meta:
        description = "Detects this specific DcRAT build targeting update35630.duckdns.org"
        author = "Tao Goldi"
        date = "2026-04"
        sha256 = "21117a9986e6c46e6ded575f875b254218d4d9b9588c1391fddf3b8b7cfa7e61"
        severity = "critical"
        family = "DcRAT"

    strings:
        $key = "SExzRk9tZTVTenBLU1JEa0huSU4xQndzdTJzOXg3Tm8=" ascii wide
        $mutex_enc = "SmrPhYgAD5HylIvTTc4vUYeqfyukZO6y0l91cJgEBCRGN6QUWN" ascii wide
        $host_enc = "WT5Kqz1F9xJ+HQfLdBBg0nU4iSQL6i2Jc17coZD6434zPQsBlUu7Rlo3" ascii wide
        $salt = "DcRatByqwqdanchun" ascii wide
        $net = "mscoree.dll" ascii

    condition:
        uint16(0) == 0x5A4D and $net and
        (
            ($key and $salt) or
            ($host_enc and $salt) or
            ($key and $mutex_enc)
        )
}

rule DcRAT_Generic
{
    meta:
        description = "Generic DcRAT / Dark Crystal RAT family detection"
        author = "Tao Goldi"
        date = "2026-04"
        severity = "high"
        family = "DcRAT"

    strings:
        $salt = "DcRatByqwqdanchun" ascii wide
        $mutex_prefix = "DcRatMutex_" ascii wide
        $ns1 = "Client.Algorithm" ascii wide
        $ns2 = "Client.Connection" ascii wide
        $ns3 = "Client.Helper" ascii wide
        $ns4 = "Client.Install" ascii wide
        $msgpack = "MessagePackLib" ascii wide
        $amsi = "AmsiScanBuffer" ascii wide
        $pong = "Po_ng" ascii wide
        $plugin = "plu_gin" ascii wide
        $save = "save_Plugin" ascii wide
        $net = "mscoree.dll" ascii

    condition:
        uint16(0) == 0x5A4D and $net and
        (
            $salt or
            $mutex_prefix or
            (3 of ($ns*) and $msgpack) or
            ($pong and $plugin and $save)
        )
}
