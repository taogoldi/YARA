rule MIRAI_LIKE_D40CF9_STAGE1_HighFidelity
{
  meta:
    author = "taogoldi"
    date = "2026-02-26"
    version = "1"
    sha256 = "d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28"
    description = "High-fidelity rule for the analyzed Mirai-like ELF sample"

  strings:
    $s1 = "[*] Connected to authorized server (%s)" ascii
    $s2 = "[!!!] SECURITY ALERT: Command from unauthorized IP: %s (expected: %s)" ascii
    $s3 = "144.172.108.230" ascii
    $s4 = "!SIGKILL" ascii
    $s5 = "1337SoraLOADER" ascii
    $s6 = "method_udpburst" ascii
    $s7 = "[*] Killer thread started." ascii

  condition:
    uint32(0) == 0x464c457f and 5 of ($s*)
}
