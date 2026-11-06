rule Linux_IEM_Bot_Encrypted_Config_ENS_Capable
{
    meta:
        description = "Linux bot with build tags of the form IEM-<date>-v1 (July 2026; picotls, locker, killer, persist and self-replication modules). Its C2 hosts come from a ChaCha20-encrypted key=value config (cnc_hosts, cnc_port, doh1..3, ens_gateways); a host ending in .eth is resolved through an ENS gateway, any other through DNS over HTTPS"
        author = "Tao Goldi"
        date = "2026-11-05"
        version = "1.0"
        family = "Mirai"
        sha256 = "c1c9c2e2936bf0492c896647531f6212d9271f1881c8b95d692d4aee48b4d472"
        sha256_2 = "7607a6631a90eb57ad892bb0cca2bd6618940822daed745392676f6aec4a33f4"
    strings:
        $k1 = "cnc_hosts" ascii fullword
        $k2 = "ens_gateways" ascii fullword
        $k3 = "doh_port1" ascii fullword
        $k4 = "locker_watch_dirs" ascii fullword
        $k5 = "selfrep_enabled" ascii fullword
        $k6 = "killer_scan_interval" ascii fullword
        $r1 = "/resolve/%s" ascii
        $r2 = "/dns-query?dns=%s" ascii
        $r3 = "\"data\":\"0x0178b8bf%s\"" ascii
        $tag = /IEM-[A-Z][a-z]{2} [0-9]{1,2} 20[0-9]{2}-[0-9:]{8}-v[0-9]/ ascii
        $l1 = "LOCKER: %s (%s)" ascii
        $l2 = "Locker daemon starting" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 4MB and 4 of ($k*) and 1 of ($r*) and ($tag or 1 of ($l*))
}
