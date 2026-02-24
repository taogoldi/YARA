import "pe"

rule VIDAR_LIKE_22_STAGE1_HighFidelity
{
  meta:
    author = "taogoldi"
    date = "2026-02-24"
    description = "High-fidelity rule for 22.exe-like stage1 loader/decryptor with AMSI+ETW patching"
    sample_sha256 = "0cb5a2e3c8aa7c80c8bbfb3a5f737c75807aa0e689dd4ad0a0466d113d8a6b9d"
    confidence = "high"

  strings:
    // API patch targets
    $api1 = "AmsiScanBuffer" ascii wide
    $api2 = "AmsiOpenSession" ascii wide
    $api3 = "EtwEventWrite" ascii wide
    $api4 = "EtwEventWriteTransfer" ascii wide
    $api5 = "NtTraceEvent" ascii wide

    // Anti-analysis cluster in this family/build
    $anti1 = "\\\\.\\pipe\\cuckoo" ascii wide
    $anti2 = "cuckoomon.dll" ascii wide
    $anti3 = "SbieDll.dll" ascii wide
    $anti4 = "SOFTWARE\\Wine" ascii wide
    $anti5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie" ascii wide
    $anti6 = "ProcessHacker.exe" ascii wide
    $anti7 = "injector.exe" ascii wide

    // Patch bytes used by stage1 routines
    $patch_amsi = { B8 57 00 07 80 C3 }
    $patch_etw1 = { 31 C0 C3 }
    $patch_etw2 = { C2 14 00 }

    // Orchestrator / decrypt wrapper / reflective handoff chains
    $sig_orchestrator = {
      53 48 83 EC 40 E8 ?? ?? ?? ??
      C7 44 24 34 00 00 00 00
      48 C7 44 24 38 00 00 00 00
      E8 ?? ?? ?? ?? 85 C0 89 C3 75 ?? 31 DB
    }

    $sig_stage_decrypt_wrapper = {
      41 B8 00 30 00 00
      41 B9 04 00 00 00
      FF 15 ?? ?? ?? ??
      31 D2 48 85 C0 48 89 06 74 ??
      41 89 D8 48 89 FA 48 89 C1 E8 ?? ?? ?? ??
      48 8D 7C 24 20
      4C 8D 05 ?? ?? ?? ??
      48 89 F9
      48 8D 15 ?? ?? ?? ??
      E8 ?? ?? ?? ??
      48 8B 16 41 89 D8 48 89 F9 E8 ?? ?? ?? ??
    }

    $sig_reflective_handoff = {
      E8 ?? ?? ?? ?? 85 C0 74 ??
      48 8B 4C 24 38
      8B 54 24 34
      48 89 4C 24 28
      E8 ?? ?? ?? ??
      31 D2
      48 8B 4C 24 28
      41 B8 00 80 00 00
    }

  condition:
    uint16(0) == 0x5A4D and
    pe.machine == pe.MACHINE_AMD64 and
    pe.number_of_sections >= 6 and
    all of ($api*) and
    4 of ($anti*) and
    $patch_amsi and $patch_etw1 and $patch_etw2 and
    $sig_orchestrator and $sig_stage_decrypt_wrapper and $sig_reflective_handoff
}


rule VIDAR_LIKE_22_STAGE1_Variant_Heuristic
{
  meta:
    author = "taogoldi"
    date = "2026-02-24"
    description = "Variant-oriented stage1 heuristic for this cluster (less strict than high-fidelity)"
    confidence = "medium"

  strings:
    $api1 = "AmsiScanBuffer" ascii wide
    $api2 = "AmsiOpenSession" ascii wide
    $api3 = "EtwEventWrite" ascii wide
    $api4 = "EtwEventWriteTransfer" ascii wide
    $api5 = "NtTraceEvent" ascii wide

    $anti1 = "\\\\.\\pipe\\cuckoo" ascii wide
    $anti2 = "cuckoomon.dll" ascii wide
    $anti3 = "SbieDll.dll" ascii wide
    $anti4 = "SOFTWARE\\Wine" ascii wide
    $anti5 = "ProcessHacker.exe" ascii wide
    $anti6 = "injector.exe" ascii wide

    $sig_kexp = {
      41 0F B6 4B 1F
      41 B8 08 00 00 00
      41 0F B6 6B 1E
      48 8D 35 ?? ?? ?? ??
      45 0F B6 53 1D
      48 8D 3D ?? ?? ?? ??
      41 0F B6 53 1C
    }

    $sig_stage_decrypt_wrapper = {
      41 B8 00 30 00 00
      41 B9 04 00 00 00
      FF 15 ?? ?? ?? ??
      31 D2 48 85 C0 48 89 06 74 ??
      48 8D 7C 24 20
      4C 8D 05 ?? ?? ?? ??
      48 8D 15 ?? ?? ?? ??
      E8 ?? ?? ?? ??
      48 8B 16 41 89 D8 48 89 F9 E8 ?? ?? ?? ??
      48 8B 16 8D 43 FF 0F B6 04 02
    }

    $patch_amsi = { B8 57 00 07 80 C3 }
    $patch_etw1 = { 31 C0 C3 }

  condition:
    uint16(0) == 0x5A4D and
    pe.machine == pe.MACHINE_AMD64 and
    4 of ($api*) and
    2 of ($anti*) and
    ($sig_kexp or $sig_stage_decrypt_wrapper) and
    ($patch_amsi or $patch_etw1)
}


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


rule VIDAR_LIKE_22_STAGE2_Variant_Heuristic
{
  meta:
    author = "taogoldi"
    date = "2026-02-24"
    description = "Variant-oriented stage2 heuristic from this cluster"
    confidence = "medium"

  strings:
    $s1 = "ChromeBuildTools" ascii wide
    $s2 = "\\Network\\Cookies" ascii wide
    $s3 = "%DOWNLOADS%" ascii wide

  condition:
    uint16(0) == 0x5A4D and
    pe.machine == pe.MACHINE_AMD64 and
    pe.imports("USER32.dll", "CreateDesktopA") and
    pe.imports("USER32.dll", "OpenDesktopA") and
    pe.imports("ADVAPI32.dll", "GetCurrentHwProfileA") and
    2 of ($s*)
}
