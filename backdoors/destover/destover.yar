import "pe"

rule Destover_Lazarus_Backdoor_2014
{
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "Detects the 2014 Destover/Wiper backdoor (Lazarus/DarkSeoul) signed with the stolen Sony Pictures Entertainment certificate"
        sha256      = "4c2efe2f1253b94f16a1cab032f36c7883e4f6c8d9fc17d0ee553b5afb16330c"
        reference   = "https://taogoldi.github.io/reverse-engineer/"

    strings:
        // Hard-coded C2 IPs as wide strings (sockaddr_in init source)
        $c2_us = "208.105.226.235" wide
        $c2_th = "203.131.222.102" wide

        // The "default" placeholder used to seed the 10-entry server table.
        // Single occurrence in .rdata, copied across slots 2..9 at runtime.
        $c2_default = "0.0.0.0" wide

        // OS-detection table fragments - distinctive of this build
        $os1 = "WaitRecv End" wide
        $os2 = "Server2003(R2) " wide
        $os3 = "Datacenter(Itanium) " wide
        $os4 = "SP%d.%d " wide

        // cmd.exe shell-exec format (split with %s placeholders so a literal
        // search for "cmd.exe /c" misses it - this is the way it appears in mem)
        $shell = "%sd.e%sc \"%s > %s\" 2>&1" wide

        // Obfuscated API-name strings: real names interleaved with junk dots
        // and spaces, decoded at runtime before GetProcAddress
        $obf1 = "Vir . tualFr. ee"
        $obf2 = "Writ. eProce . ssMem.ory"
        $obf3 = "G. etDr i. .veTy..peW"
        $obf4 = "Cre..ate Th re.. ad"
        $obf5 = "Ope..nSCMan. agerW"
        $obf6 = "Cr.eate...Ser..v iceW"
        $obf7 = "..W .in..Ex...ec"

        // Custom base32-ish alphabet used by the encoder
        $alphabet = "abcdefghijklmnopqrstuvwxyz012345"

        // Connectivity sentinel hosts
        $probe1 = "www.google.com" ascii
        $probe2 = "www.amazon.com" ascii

        // Masquerade: VS_VERSION_INFO claims to be Intel graphics persistence
        $masq1 = "igfxstartup Module" wide
        $masq2 = "igfxtpers.exe" wide

        // End-of-run banner printed to stdout
        $banner = "---------------End--------------!"

    condition:
        uint16(0) == 0x5A4D
        and pe.is_32bit()
        and filesize < 200KB
        and (
            // Network plus shell plus obfuscation core
            (any of ($c2_us, $c2_th) and $shell and 3 of ($obf*))
            // Or the masquerade plus the OS table plus obfuscation
            or (all of ($masq*) and 2 of ($os*) and 2 of ($obf*))
            // Or the standalone obfuscated-API table fingerprint
            or (5 of ($obf*) and ($alphabet or $banner))
            // Or default placeholder + probe hosts + obfuscation
            or ($c2_default and all of ($probe*) and 3 of ($obf*))
        )
}

rule Destover_Stolen_Sony_Certificate
{
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "Detects PE files signed with the stolen Sony Pictures Entertainment Authenticode certificate (revoked Dec 2014). Any modern hit on this rule is malicious by definition."
        reference   = "https://taogoldi.github.io/reverse-engineer/"

    strings:
        // Subject CN / O fields baked into the embedded PKCS#7 blob
        $cn1 = "Sony Pictures Entertainment Inc." ascii
        $cn2 = "CULVER CITY"
        $issuer = "DigiCert Assured ID Code Signing CA-1"

    condition:
        uint16(0) == 0x5A4D
        and pe.number_of_signatures > 0
        and all of ($cn*)
        and $issuer
}
