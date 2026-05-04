import "pe"

/*
    Amadey_cred64 — credential-harvesting x64 DLL stealer
    Targets: Chromium browsers, Firefox/Tor/Thunderbird, crypto wallets, Telegram, IM clients, WiFi
    C2: 91.92.242.236:80 HTTP POST /oPvjr94jfe/index.php
    String obfuscation: Vigenère (key=a42cf94a609810d038dd0ca0d030ffef) + Base64
    PDB: D:\Mktmp\StealerDLL\Release.x64\STEALERDLL.pdb
    First seen: 2026-03-08
    Reference SHA256: 3bdcb32460e5a613c35b14205e4a98ad50a03a1d7d17f4c30f2935c6f6d5db69
*/

rule Amadey_cred64_PDB {
    meta:
        author      = "Tao Goldi"
        description = "Amadey_cred64 — matches PDB path embedded in x64 DLL"
        version     = 1
        date        = "2026-04-27"
        hash        = "3bdcb32460e5a613c35b14205e4a98ad50a03a1d7d17f4c30f2935c6f6d5db69"
        tlp         = "TLP:WHITE"

    strings:
        $pdb = "D:\\Mktmp\\StealerDLL\\Release.x64\\STEALERDLL.pdb" ascii

    condition:
        uint16(0) == 0x5A4D and $pdb
}

rule Amadey_cred64_ObfuscationKey {
    meta:
        author      = "Tao Goldi"
        description = "Amadey_cred64 — Vigenère string-obfuscation key embedded in .rdata"
        version     = 1
        date        = "2026-04-27"
        hash        = "3bdcb32460e5a613c35b14205e4a98ad50a03a1d7d17f4c30f2935c6f6d5db69"
        tlp         = "TLP:WHITE"

    strings:
        // 32-byte Vigenère key stored as ASCII in .rdata
        $vig_key = "a42cf94a609810d038dd0ca0d030ffef" ascii

    condition:
        uint16(0) == 0x5A4D and $vig_key
}

rule Amadey_cred64_EncryptedConfig {
    meta:
        author      = "Tao Goldi"
        description = "Amadey_cred64 — encrypted C2 address, path, and SQL query in static data region"
        version     = 1
        date        = "2026-04-27"
        hash        = "3bdcb32460e5a613c35b14205e4a98ad50a03a1d7d17f4c30f2935c6f6d5db69"
        tlp         = "TLP:WHITE"

    strings:
        // Vigenère+B64 ciphertext of "91.92.242.236"
        $enc_c2_ip   = "OMvwTRBuH9OvB9LoFd==" ascii
        // Vigenère+B64 ciphertext of "/oPvjr94jfe/index.php" (space at position 27 is Vigenère pass-through)
        $enc_c2_path = "LV0SikiyJIPnPbXk3T8nOZgjfv l" ascii
        // Vigenère+B64 ciphertext of "SELECT origin_url, username_value, password_value FROM logins"
        $enc_sql     = "UTMOWSGUDv7v1Lge4ib42owhLwNo42NzYPSn21Sh7wTiBrElQUQC349n2u1R31B6ZLsIZi2NDvvsPRoj5t==" ascii

    condition:
        uint16(0) == 0x5A4D and 2 of ($enc_*)
}

rule Amadey_cred64_Exports {
    meta:
        author      = "Tao Goldi"
        description = "Amadey_cred64 — characteristic export pair: Main (stealer entry) and Save (stub)"
        version     = 1
        date        = "2026-04-27"
        hash        = "3bdcb32460e5a613c35b14205e4a98ad50a03a1d7d17f4c30f2935c6f6d5db69"
        tlp         = "TLP:WHITE"

    condition:
        uint16(0) == 0x5A4D
        and pe.is_dll()
        and pe.machine == pe.MACHINE_AMD64
        and pe.exports("Main")
        and pe.exports("Save")
        and pe.number_of_exports == 2
}

rule Amadey_cred64_ImportProfile {
    meta:
        author      = "Tao Goldi"
        description = "Amadey_cred64 — import combination: DPAPI + BCrypt AES + NSS3 ref + WinINet C2"
        version     = 1
        date        = "2026-04-27"
        hash        = "3bdcb32460e5a613c35b14205e4a98ad50a03a1d7d17f4c30f2935c6f6d5db69"
        tlp         = "TLP:WHITE"

    strings:
        // Dynamic NSS3 load for Firefox decryption
        $nss3       = "nss3.dll" ascii nocase
        // Vigenère+B64 encrypted Taskkill commands (all share common 14-char prefix encoding "Taskkill /IM ")
        $kill_ltc   = "VzwBf0mp7vudBPoCADAs3IV9eRdjQ2J5LfM64QtvM6==" ascii
        $kill_atm   = "VzwBf0mp7vudBPoCAzME3I9idLE607JxbzM2QkO4UHGdBP1=" ascii
        $kill_arm   = "VzwBf0mp7vudBPoCABIB1Y9nhKxPQrZ9ZLrxWe==" ascii
        $kill_dash  = "VzwBf0mp7vudBPoCADUk24gifMIj42lqIv0I" ascii

    condition:
        uint16(0) == 0x5A4D
        and pe.imports("Crypt32.dll", "CryptUnprotectData")
        and pe.imports("Bcrypt.dll", "BCryptDecrypt")
        and pe.imports("Wininet.dll", "InternetConnectA")
        and $nss3
        and 2 of ($kill_*)
}

rule Amadey_cred64_WifiExfil {
    meta:
        author      = "Tao Goldi"
        description = "Amadey_cred64 — WiFi credential theft via netsh"
        version     = 1
        date        = "2026-04-27"
        hash        = "3bdcb32460e5a613c35b14205e4a98ad50a03a1d7d17f4c30f2935c6f6d5db69"
        tlp         = "TLP:WHITE"

    strings:
        // Plaintext profile enumeration command (appears unobfuscated in binary)
        $netsh_show   = "netsh wlan show profiles" ascii
        // Vigenère+B64 ciphertext of "netsh wlan export profile name=" (spaces are pass-through)
        $netsh_export = "bfM2h0 g9Rve28Ea7EEy2pQ6fwBk4rpxZLsw3UUlKF==" ascii

    condition:
        uint16(0) == 0x5A4D and any of ($netsh_*)
}

rule Amadey_cred64_Full {
    meta:
        author      = "Tao Goldi"
        description = "Amadey_cred64 — high-confidence composite rule (PDB + obf key + exports + imports)"
        version     = 1
        date        = "2026-04-27"
        hash        = "3bdcb32460e5a613c35b14205e4a98ad50a03a1d7d17f4c30f2935c6f6d5db69"
        tlp         = "TLP:WHITE"
        confidence  = "HIGH"

    strings:
        $pdb     = "D:\\Mktmp\\StealerDLL\\Release.x64\\STEALERDLL.pdb" ascii
        $vig_key = "a42cf94a609810d038dd0ca0d030ffef" ascii
        $nss3    = "nss3.dll" ascii nocase

    condition:
        uint16(0) == 0x5A4D
        and pe.is_dll()
        and pe.machine == pe.MACHINE_AMD64
        and pe.exports("Main")
        and pe.exports("Save")
        and pe.imports("Crypt32.dll", "CryptUnprotectData")
        and pe.imports("Bcrypt.dll", "BCryptDecrypt")
        and pe.imports("Wininet.dll", "InternetConnectA")
        and $pdb
        and $vig_key
        and $nss3
}
