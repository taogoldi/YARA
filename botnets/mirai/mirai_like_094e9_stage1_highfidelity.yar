rule MIRAI_LIKE_094E9_STAGE1_HighFidelity
{
  meta:
    author = "taogoldi"
    date = "2026-03-07"
    version = "1"
    sha256 = "094e9d6ee057d38f40c35f018488e35ab6ccd006ed261b17322e78fd5ea2c0cb"
    description = "High-fidelity rule for the validated Mirai-like variant (094e...)"

  strings:
    $s1 = "watchdog_maintain" ascii
    $s2 = "watchdog_pid" ascii
    $s3 = "udpfl00d" ascii
    $s4 = "tcpFl00d" ascii
    $s5 = "ovhudpflood" ascii
    $s6 = "TSource Engine Query" ascii
    $s7 = "KHserverHACKER" ascii
    $s8 = "/etc/config/resolv.conf" ascii
    $s9 = "__open_nameservers" ascii
    $s10 = "dnslookup.c" ascii

  condition:
    uint32(0) == 0x464c457f and 7 of ($s*)
}
