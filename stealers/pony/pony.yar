import "pe"

rule Pony_Stealer_Credential_Harvester
{
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "Detects Pony/Fareit credential stealer based on static indicators"
        sha256      = "805b1dbf373986fb98f346b491cea9ce75c44ea7cc55339260c344606773e236"
        reference   = "https://taogoldi.github.io/reverse-engineer/"

    strings:
        // C2 response token
        $s1 = "STATUS-IMPORT-OK" ascii

        // Machine fingerprint label
        $s2 = "Client Hash" ascii

        // HWID generation format string
        $s3 = "HWID" ascii

        // Self-delete batch artifact
        $s4 = "abcd.bat" ascii

        // Legacy IE user-agent used in HTTP exfil
        $s5 = "Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)" ascii

        // HTTP exfil content-type header
        $s6 = "Content-Encoding: binary" ascii

        // NSS API imports for Firefox password decryption
        $s7 = "NSS_Init" ascii
        $s8 = "PK11SDR_Decrypt" ascii

        // SQLite symbols used for browser credential extraction
        $s9  = "sqlite3_open" ascii
        $s10 = "moz_logins" ascii

        // Download-and-execute format string
        $s11 = "%d.exe" ascii

        // Forum-based payload URL pattern
        $s12 = "forum/viewtopic.php" ascii

    condition:
        uint16(0) == 0x5A4D
        and pe.is_32bit()
        and filesize < 300KB
        and (
            ($s1 and $s2 and $s4 and $s5)
            or ($s7 and $s8 and ($s9 or $s10) and $s6)
            or ($s1 and $s11 and $s12)
        )
        and 6 of ($s*)
}

rule Pony_Stealer_HTTP_Protocol
{
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "Detects Pony/Fareit binary exfiltration HTTP fingerprint"

    strings:
        $http_post = "Content-Type: application/octet-stream" ascii
        $encoding  = "Content-Encoding: binary" ascii
        $ua        = "MSIE 5.0; Windows 98" ascii
        $ok        = "STATUS-IMPORT-OK" ascii

    condition:
        uint16(0) == 0x5A4D
        and all of them
}
