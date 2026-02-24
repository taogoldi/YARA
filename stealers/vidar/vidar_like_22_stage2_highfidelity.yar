import "pe"

rule VIDAR_LIKE_22_STAGE2_HighFidelity
{
  meta:
    author = "taogoldi"
    date = "2026-02-24"
    description = "High-fidelity rule for decrypted stage2 from 22.exe"
    stage2_sha256 = "5fa52aa9046334c86da1e9746dfe9d7bb23ec69a8b2ab77d98efd2cb1af012f3"
    confidence = "high"

  strings:
    $s1 = "ChromeBuildTools" ascii wide
    $s2 = "\\Network\\Cookies" ascii wide
    $s3 = "11111111111111111111111111111111111111111111111111111%DOWNLOADS%" ascii wide

  condition:
    uint16(0) == 0x5A4D and
    pe.machine == pe.MACHINE_AMD64 and
    pe.number_of_sections == 5 and
    pe.imports("USER32.dll", "CreateDesktopA") and
    pe.imports("USER32.dll", "OpenDesktopA") and
    pe.imports("ADVAPI32.dll", "GetCurrentHwProfileA") and
    pe.imports("USER32.dll", "EnumDisplayDevicesA") and
    all of ($s*)
}
