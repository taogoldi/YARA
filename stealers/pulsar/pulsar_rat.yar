/*
    Pulsar RAT Detection Rules
    Family: Pulsar RAT (QuasarRAT fork)
    Version: 2.4.5.0

    Reference sample:
        SHA256: 8f31c06c8e7ea9eb451bf26666ac4a958bb485b2a8b71feace1981633b116c92
        File:   RMnsgES.exe

    author = "Tao Goldi"
    Date:   2026-04
*/

rule PulsarRAT_Costura_Bundle
{
    meta:
        description = "Detects Pulsar RAT with Fody/Costura embedded dependencies"
        severity = "critical"
        family = "PulsarRAT"
        mitre_attack = "T1055,T1113,T1555,T1056.001,T1562.001"

    strings:
        // Costura resource names (high-confidence family indicator)
        $costura_core = "costura.pulsar.common.dll.compressed" ascii wide nocase
        $costura_mp = "costura.messagepack.dll.compressed" ascii wide nocase

        // Pulsar namespaces
        $ns1 = "Pulsar.Common.UAC" ascii wide
        $ns2 = "Pulsar.Common.Messages" ascii wide
        $ns3 = "Pulsar.Common.Messages.ClientManagement" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $costura_core or
            ($costura_mp and 1 of ($ns*)) or
            all of ($ns*)
        )
}

rule PulsarRAT_Browser_Stealer
{
    meta:
        description = "Detects Pulsar RAT browser credential harvesting module"
        severity = "critical"
        family = "PulsarRAT"
        mitre_attack = "T1555,T1539"

    strings:
        // Async browser harvester methods
        $chrome = "StartChromeAsync" ascii wide
        $firefox = "StartFirefoxAsync" ascii wide
        $opera = "StartOperaAsync" ascii wide
        $brave = "StartBraveAsync" ascii wide
        $patch_opera = "PatchOperaAsync" ascii wide
        $clone = "CloneBrowserProfileAsync" ascii wide

        // DPAPI decryption
        $dpapi = "DecryptBlob" ascii wide
        $dpapi2 = "encrypt data using DPAPI" ascii wide

        // Key browser data targets
        $login_data = "Login Data" ascii wide
        $logins_json = "logins.json" ascii wide
        $cookies = "Cookies" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (3 of ($chrome, $firefox, $opera, $brave)) or
            ($clone and 1 of ($chrome, $firefox, $opera, $brave)) or
            ($patch_opera and $opera) or
            (2 of ($chrome, $firefox, $opera, $brave) and $dpapi and 1 of ($login_data, $logins_json))
        )
}

rule PulsarRAT_AntiAnalysis
{
    meta:
        description = "Detects Pulsar RAT anti-analysis and evasion routines"
        severity = "high"
        family = "PulsarRAT"
        mitre_attack = "T1497,T1562.001"

    strings:
        // Custom syscall wrappers (obfuscated API names)
        $sys1 = "SysNtQuerySystemInformation" ascii wide
        $sys2 = "SysNtQueryInformationProcess" ascii wide

        // Debug detection
        $dbg1 = "ProcessDebugPort" ascii wide
        $dbg2 = "ProcessDebugFlags" ascii wide
        $dbg3 = "CheckRemoteDebuggerPresent" ascii wide

        // UAC bypass
        $uac1 = "DoDisableUAC" ascii wide
        $uac2 = "DoEnableUAC" ascii wide

        // Registry-based defense disabling
        $reg_disable = "disable system features via registry" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            ($sys1 and $sys2) or
            (all of ($dbg*)) or
            (all of ($uac*)) or
            ($sys1 and 1 of ($uac*) and 1 of ($dbg*))
        )
}

rule PulsarRAT_Keylogger_Screenshot
{
    meta:
        description = "Detects Pulsar RAT collection capabilities (keylogger + screenshot)"
        severity = "high"
        family = "PulsarRAT"
        mitre_attack = "T1056.001,T1113,T1115"

    strings:
        // Keylogger indicators
        $keylog1 = "log keystrokes via application hook" ascii wide
        $keylog2 = "SetWindowsHookEx" ascii wide
        $keylog3 = "WH_KEYBOARD" ascii wide
        $keylog4 = "GetAsyncKeyState" ascii wide

        // Screenshot
        $screen1 = "capture screenshot" ascii wide
        $screen2 = "CreateCompatibleDC" ascii wide
        $screen3 = "CreateDC" ascii wide

        // Clipboard
        $clip1 = "check clipboard data" ascii wide

        // Pulsar-specific context
        $pulsar_ctx = "Pulsar" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        $pulsar_ctx and
        (
            (2 of ($keylog*) and 1 of ($screen*)) or
            (2 of ($screen*) and $clip1) or
            (1 of ($keylog*) and 1 of ($screen*) and $clip1)
        )
}

rule PulsarRAT_Generic
{
    meta:
        description = "Generic detection for Pulsar RAT family based on combined indicators"
        severity = "critical"
        family = "PulsarRAT"

    strings:
        $s1 = "Pulsar" ascii wide
        $s2 = "costura." ascii wide
        $s3 = "MessagePack" ascii wide
        $s4 = "AES" ascii wide
        $s5 = "StartChromeAsync" ascii wide
        $s6 = "DoDisableUAC" ascii wide
        $s7 = "SysNtQuery" ascii wide
        $s8 = "CloneBrowserProfile" ascii wide
        $s9 = "capture screenshot" ascii wide
        $s10 = "log keystrokes" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        5 of ($s*)
}
