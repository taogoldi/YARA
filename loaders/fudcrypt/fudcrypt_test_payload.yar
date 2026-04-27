import "pe"

rule FudCrypt_Test_Payload_Stage2
{
    meta:
        author      = "Tao Goldi"
        description = "FUD Crypt builder QA test payload (TestPayload.Program). Catches operator smoke-tests left exposed on Dropbox / Catbox / any FUD Crypt staging path."
        reference   = "decrypted from https://files.catbox.moe/v5fllr.bin (loader sha256 c73947cf...)"
        family      = "FUD Crypt"
        stage       = "QA test payload"
        date        = "2026-04-26"
        version     = 1
        tlp         = "white"

    strings:
        // The QA fingerprints baked into the test payload's UTF-16LE string heap
        $s1 = "FudCrypt .NET Build Test - " wide
        $s2 = "Test payload executed!" wide
        $s3 = "FudCrypt Test" wide
        $s4 = "dotnet_test_success.txt" wide

        // Class identifiers in the .NET #Strings heap (ASCII)
        $a1 = "TestPayload" ascii
        $a2 = "test_dotnet_payload" ascii

    condition:
        // Note on imphash: deliberately not used here; every .NET PE imports only
        // mscoree!_CorExeMain, so imphash on a managed assembly is meaningless.
        uint16(0) == 0x5A4D and
        pe.is_pe and
        pe.machine == pe.MACHINE_I386 and
        pe.imports("mscoree.dll", "_CorExeMain") and
        (
            2 of ($s*) or
            (1 of ($s*) and 1 of ($a*))
        )
}
