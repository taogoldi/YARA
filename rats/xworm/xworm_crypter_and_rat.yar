rule XWorm_NET_Crypter_PBKDF2
{
    meta:
        description = "Detects .NET crypter using PBKDF2/AES-128-CBC with embedded encrypted payloads"
        author = "Tao Goldi"
        date = "2026-04"
        sha256 = "27a2505cfd32ca1fda31e58c1d2ddee7e4726b8305fda10b779851e259a2ef9d"
        severity = "critical"
        family = "XWorm Crypter"

    strings:
        $pbkdf2 = "Rfc2898DeriveBytes" ascii wide
        $crypto = "CreateDecryptor" ascii wide
        $stream = "CryptoStream" ascii wide
        $b64 = "FromBase64String" ascii wide
        $res = "ResourceManager" ascii wide
        $asm = "GetExecutingAssembly" ascii wide
        $net = "mscoree.dll" ascii

        // Specific to this crypter variant
        $salt = "erytiqjdxdutsqckdapnnhprdujedlpd" ascii wide
        $iv = "xbginlypryzblkfy" ascii wide

    condition:
        uint16(0) == 0x5A4D and $net and
        (
            ($salt and $iv) or
            ($pbkdf2 and $crypto and $stream and $b64 and $res and $asm)
        )
}

rule XWorm_RAT_v1_LEB128
{
    meta:
        description = "Detects XWorm RAT with LEB128 protocol, D/Invoke, and AMSI/ETW bypass"
        author = "Tao Goldi"
        date = "2026-04"
        severity = "critical"
        family = "XWorm"
        mitre_attack = "T1055,T1547,T1562.001,T1059.001,T1548.002"

    strings:
        // LEB128 protocol (XWorm signature)
        $leb1 = "LEB128" ascii wide
        $leb2 = "ReadLebString" ascii wide
        $leb3 = "ReadLebBool" ascii wide
        $leb4 = "WriteLebString" ascii wide

        // D/Invoke core
        $dinv1 = "DInvokeCore" ascii wide
        $dinv2 = "DynamicAPIInvoke" ascii wide
        $dinv3 = "GetExportAddress" ascii wide

        // AMSI/ETW bypass
        $amsi1 = "AmsiScanBuffer" ascii wide
        $amsi2 = "EtwEventWrite" ascii wide
        $amsi3 = "AsmiAndETW" ascii wide

        // XWorm-specific class names
        $cls1 = "AntiVirtual" ascii wide
        $cls2 = "PluginLoader" ascii wide
        $cls3 = "HwidGenerator" ascii wide
        $cls4 = "SecrityHidden" ascii wide
        $cls5 = "SetRegistry" ascii wide
        $cls6 = "PingChecker" ascii wide

        // Config patterns
        $cfg1 = "SaveInvoke" ascii wide
        $cfg2 = "GetDLL" ascii wide
        $cfg3 = "Pong" ascii wide

        $net = "mscoree.dll" ascii

    condition:
        uint16(0) == 0x5A4D and $net and
        (
            (2 of ($leb*) and 2 of ($cls*)) or
            ($amsi3 and 2 of ($dinv*)) or
            (3 of ($cls*) and 2 of ($cfg*)) or
            ($leb1 and $dinv1 and $amsi3)
        )
}

rule XWorm_RAT_AdvancedBootkit
{
    meta:
        description = "Detects XWorm variant with UEFI bootkit, rootkit, and driver infection capabilities"
        author = "Tao Goldi"
        date = "2026-04"
        severity = "critical"
        family = "XWorm"
        mitre_attack = "T1542.003,T1014,T1068"

    strings:
        $boot1 = "AdvancedBootkit" ascii wide
        $boot2 = "BlackLotusDbxBypass" ascii wide
        $boot3 = "LogoFAILStyle" ascii wide
        $boot4 = "InstallGPTUEFIStager" ascii wide
        $boot5 = "bootmgfw.efi" ascii wide
        $boot6 = "InstallLegacyMbrBootkit" ascii wide

        $root1 = "r77-x86.dll" ascii wide
        $root2 = "r77-x64.dll" ascii wide
        $root3 = "$77config" ascii wide
        $root4 = "InjectHookDll" ascii wide

        $drv1 = "DriverInfector" ascii wide
        $drv2 = "InfectAndReplace" ascii wide

        $net = "mscoree.dll" ascii

    condition:
        uint16(0) == 0x5A4D and $net and
        (
            2 of ($boot*) or
            2 of ($root*) or
            (1 of ($boot*) and 1 of ($root*) and 1 of ($drv*))
        )
}

rule XWorm_RAT_Config_Superiority
{
    meta:
        description = "Detects this specific XWorm build with 'Superiority' campaign tag"
        author = "Tao Goldi"
        date = "2026-04"
        sha256_payload = "710e3226b214aa6d3ab65bb3d8899ea533bdfc6da28602328c5912567c9bcf0c"
        severity = "critical"
        family = "XWorm"

    strings:
        $c2 = "195.10.205.179" ascii wide
        $port = "25565" ascii wide
        $mutex = "yp07tia%jr+2" ascii wide
        $key = "cky9r4ytydhcwji3z3dizpj" ascii wide
        $group = "Superiority" ascii wide
        $task = "Windows Perfoment Host" ascii wide
        $reg = "gogoduck" ascii wide
        $amd = "AMD drivers/software" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            ($c2 and $port) or
            ($mutex and $key) or
            ($group and $task) or
            ($c2 and $group and $reg)
        )
}
