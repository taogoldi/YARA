rule MIRAI_LIKE_STAGE1_Family_Heuristic
{
  meta:
    author = "taogoldi"
    date = "2026-03-07"
    version = "2"
    description = "Family-level heuristic intended to match both d40... and 094e... Mirai-like variants"

  strings:
    $core1 = "/etc/config/resolv.conf" ascii
    $core2 = "__open_nameservers" ascii
    $core3 = "dnslookup.c" ascii
    $core4 = "opennameservers.c" ascii
    $core5 = "__dns_lookup" ascii

    $old1 = "!SIGKILL" ascii
    $old2 = "M-SEARCH * HTTP/1.1" ascii
    $old3 = "Via: SIP/2.0/UDP 192.168.1.1:5060" ascii
    $old4 = "udpburst" ascii
    $old5 = "udpslam" ascii

    $new1 = "watchdog_maintain" ascii
    $new2 = "udpfl00d" ascii
    $new3 = "tcpFl00d" ascii
    $new4 = "ovhudpflood" ascii
    $new5 = "TSource Engine Query" ascii

  condition:
    uint32(0) == 0x464c457f and
    3 of ($core*) and
    (2 of ($old*) or 2 of ($new*))
}
