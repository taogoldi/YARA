import "pe"

rule VIDAR_LIKE_22_STAGE1_Variant_Heuristic
{
  meta:
    author = "taogoldi"
    date = "2026-02-24"
    description = "Variant-oriented stage1 heuristic for this cluster (less strict than high-fidelity)"
    version = 1
    sha256 = "0cb5a2e3c8aa7c80c8bbfb3a5f737c75807aa0e689dd4ad0a0466d113d8a6b9d"
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
    4 of ($api*) and
    2 of ($anti*) and
    ($sig_kexp or $sig_stage_decrypt_wrapper) and
    ($patch_amsi or $patch_etw1)
}
