import "pe"

rule VIDAR_LIKE_22_STAGE2_Variant_Heuristic
{
  meta:
    author = "taogoldi"
    date = "2026-02-24"
    description = "Variant-oriented stage2 heuristic from this cluster"
    version = 1
    sha256 = "5fa52aa9046334c86da1e9746dfe9d7bb23ec69a8b2ab77d98efd2cb1af012f3"
    confidence = "medium"

  strings:
    $s1 = "ChromeBuildTools" ascii wide
    $s2 = "\\Network\\Cookies" ascii wide
    $s3 = "%DOWNLOADS%" ascii wide

  condition:
    uint16(0) == 0x5A4D and
    pe.imports("USER32.dll", "CreateDesktopA") and
    pe.imports("USER32.dll", "OpenDesktopA") and
    pe.imports("ADVAPI32.dll", "GetCurrentHwProfileA") and
    2 of ($s*)
}
