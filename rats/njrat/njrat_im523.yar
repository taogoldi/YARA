import "pe"

rule njRAT_im523_HacKed_Campaign
{
    meta:
        description = "Detects njRAT v0.7d im523 variant with 'HacKed' campaign tag"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        sha256 = "ff87cd932e25b024cd10042c186f252fdabdac2c4d4cbc67f89e457697ebbc71"
        severity = "critical"
        family = "njRAT"
        variant = "im523"
        mitre_attack = "T1056.001,T1113,T1547.001,T1059.003,T1071.001,T1497,T1562.001"

    strings:
        // njRAT version and separator
        $ver = "im523" ascii wide
        $sep = "|'|'|" ascii wide

        // Campaign tag (Base64 of "HacKed")
        $tag = "SGFjS2Vk" ascii wide

        // C2 domain
        $c2 = "phishing.multimilliontoken.org" ascii wide

        // Mutex
        $mutex = "411e31664bdd9d96369d0a44d5111aef" ascii wide

        // Command strings unique to njRAT
        $cmd_shutdown = "shutdowncomputer" ascii wide
        $cmd_restart = "restartcomputer" ascii wide
        $cmd_disablekm = "DisableKM" ascii wide
        $cmd_enablekm = "EnableKM" ascii wide
        $cmd_disablecmd = "DisableCMD" ascii wide
        $cmd_disablereg = "DisableRegistry" ascii wide
        $cmd_disabletm = "DisableTaskManager" ascii wide
        $cmd_opencd = "OpenCD" ascii wide
        $cmd_closecd = "CloseCD" ascii wide
        $cmd_reversemouse = "ReverseMouse" ascii wide
        $cmd_cursorhide = "CursorHide" ascii wide
        $cmd_monitor = "TurnOffMonitor" ascii wide

        // Self-delete pattern
        $selfdel = "cmd.exe /k ping 0 & del" ascii wide

        // USB spread
        $usb = "autorun.inf" ascii wide
        $usb2 = "shellexecute=" ascii wide

        // Credential theft
        $cred = "Pass.exe" ascii wide

        // Analysis tool detection
        $tool1 = "processhacker" ascii wide
        $tool2 = "processviewer" ascii wide
        $tool3 = "process explorer" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 100KB and
        (
            ($ver and $sep) or
            ($c2 and $mutex) or
            ($tag and $sep and 3 of ($cmd_*)) or
            (5 of ($cmd_*) and $sep and ($usb or $selfdel))
        )
}

rule njRAT_Generic_v07d
{
    meta:
        description = "Generic njRAT v0.7d family detection"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        severity = "high"
        family = "njRAT"

    strings:
        $sep = "|'|'|" ascii wide
        $s1 = "shutdowncomputer" ascii wide
        $s2 = "restartcomputer" ascii wide
        $s3 = "DisableKM" ascii wide
        $s4 = "EnableKM" ascii wide
        $s5 = "DisableTaskManager" ascii wide
        $s6 = "OpenCD" ascii wide
        $s7 = "TurnOffMonitor" ascii wide
        $s8 = "ReverseMouse" ascii wide
        $s9 = "CursorHide" ascii wide
        $s10 = "DisableCMD" ascii wide
        $s11 = "cmd.exe /k ping 0 & del" ascii wide
        $s12 = "autorun.inf" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        pe.imports("mscoree.dll") and
        $sep and 5 of ($s*)
}
