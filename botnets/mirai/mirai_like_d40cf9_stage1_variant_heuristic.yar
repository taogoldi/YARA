rule MIRAI_LIKE_D40CF9_STAGE1_VariantHeuristic
{
  meta:
    author = "taogoldi"
    date = "2026-02-26"
    version = "1"
    sha256 = "d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28"
    description = "Heuristic Mirai-like detector for this cluster family"

  strings:
    $m1 = "udpslam" ascii
    $m2 = "udpburst" ascii
    $m3 = "raknet" ascii
    $m4 = "M-SEARCH * HTTP/1.1" ascii
    $m5 = "Via: SIP/2.0/UDP 192.168.1.1:5060" ascii
    $m6 = "/proc/%s/cmdline" ascii
    $m7 = "/proc/%s/maps" ascii
    $m8 = "/bin/busybox" ascii
    $m9 = "disable_infection_tools" ascii
    $m10 = "scan_and_kill" ascii

  condition:
    uint32(0) == 0x464c457f and
    7 of ($m*)
}
