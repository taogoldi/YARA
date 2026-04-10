rule Factory_v3_Go_Implant_NuclearDecoy
{
    meta:
        description = "Detects Factory-v3 builder Go implant with nuclear reactor themed decoy types and CJK obfuscated function names"
        author = "Tao Goldi"
        date = "2026-04"
        sha256 = "072533c1d31d83b056a1a9f4174a23763c53597df1c89ad9c545df2c3bb35f5e"
        severity = "critical"
        family = "Factory-v3"
        mitre_attack = "T1027.010,T1106,T1055,T1059"

    strings:
        // Builder framework path
        $builder = "Factory-v3/builder/temp/" ascii

        // Nuclear reactor decoy type names (unique to this framework)
        $nuke1 = "BeamEnvelope" ascii
        $nuke2 = "ControlDrum" ascii
        $nuke3 = "FuelRodBundle" ascii
        $nuke4 = "XenonTransientTable" ascii
        $nuke5 = "MagnetFlavor" ascii
        $nuke6 = "LatticeCell" ascii
        $nuke7 = "reactivityWorthCurve" ascii
        $nuke8 = "xenonConcentrationPpm" ascii
        $nuke9 = "dopplerCoefficientNeg" ascii
        $nuke10 = "claddingIntegrityScore" ascii

        // CJK obfuscated function names (garble-style Chinese word salad)
        $cjk1 = { E5 8A A8 E4 BD 9C E5 85 AB E6 9C 88 E9 B8 9F }  // 动作八月鸟
        $cjk2 = { E5 81 87 E8 AE BE E5 8E 9F E5 AD 90 E8 A1 80 E6 B6 B2 }  // 假设原子血液
        $cjk3 = { E7 AE 80 E7 9F AD E5 B9 B3 E8 A1 A1 E6 88 98 E6 96 97 }  // 简短平衡战斗
        $cjk4 = { E8 B4 A6 E6 88 B7 E7 94 B7 E5 AD A9 E9 85 92 E5 90 A7 }  // 账户男孩酒吧

        // Go build ID pattern
        $gobuild = "Go build ID:" ascii

        // Dynamic API resolution via LazyDLL
        $lazy1 = "syscall.modkernel32" ascii
        $lazy2 = "syscall.modadvapi32" ascii

        // Go version string
        $gover = "go1.24" ascii

    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and
        (
            ($builder) or
            ($builder and 3 of ($nuke*)) or
            (4 of ($nuke*) and 2 of ($cjk*)) or
            (2 of ($cjk*) and $gobuild and 3 of ($nuke*))
        )
}

rule Factory_v3_Go_Implant_Generic
{
    meta:
        description = "Generic detection for Factory-v3 Go implant framework based on nuclear decoy naming convention"
        author = "Tao Goldi"
        date = "2026-04"
        severity = "high"
        family = "Factory-v3"

    strings:
        // Any 5 of the nuclear-themed type names together is highly suspicious
        $n1 = "BeamEnvelope" ascii
        $n2 = "ControlDrum" ascii
        $n3 = "FuelRodBundle" ascii
        $n4 = "XenonTransientTable" ascii
        $n5 = "MagnetFlavor" ascii
        $n6 = "LatticeCell" ascii
        $n7 = "GridRef" ascii
        $n8 = "reactivityWorthCurve" ascii
        $n9 = "dopplerCoefficientNeg" ascii
        $n10 = "claddingIntegrityScore" ascii
        $n11 = "xenonConcentrationPpm" ascii
        $n12 = "rotationAngleDegrees" ascii

        // Must also have Go binary indicators
        $go1 = "Go build" ascii
        $go2 = "runtime.main" ascii

    condition:
        uint16(0) == 0x5A4D and
        5 of ($n*) and
        1 of ($go*)
}
