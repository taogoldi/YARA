import "pe"
import "dotnet"

rule IRoveroll_Stealer {
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "IRoveroll infostealer (Inqusitor Prod) - Telegram-exfiltrating .NET stealer masquerading as svchost.exe"
        sha256      = "e7fcb6ab49296e69d1aa94091bb639a8ab3f69823ada857ab7fd5b3457a41867"
        date        = "2026-04-23"
        tlp         = "WHITE"
        reference   = "https://taogoldi.github.io/reverse-engineer/"

    strings:
        // Distinctive mutex name
        $mutex          = "IMSEXYGIRL" ascii wide

        // Internal namespace / PDB artefact
        $ns_iroveroll   = "IRoveroll" ascii wide

        // Telegram exfil strings
        $tg_api         = "api.telegram.org" ascii wide
        $tg_send        = "sendDocument" ascii wide
        $tg_caption     = "LOG - " ascii wide

        // Anti-VM WMI queries
        $wmi_cache      = "Win32_CacheMemory" ascii wide
        $wmi_cim        = "CIM_Memory" ascii wide

        // Self-delete command
        $autodel        = "rmdir /s /q" ascii wide

        // Sandbox username blocklist (distinctive set)
        $sandbox_ua     = "utilityaccount" ascii wide
        $sandbox_wdag   = "wdag" ascii wide

        // Version info planted strings
        $ver_company    = "Alsu Software" ascii wide
        $ver_product    = "Inqusitor Prod" ascii wide
        $ver_comment    = "Disable defender and antivirus softwares" ascii wide

        // Discord token encryption marker
        $discord_regex  = "dQw4w9WgXcQ:" ascii wide

        // Yandex-specific targets (CIS origin signal)
        $ya_passman     = "Ya Passman Data" ascii wide
        $ya_cards       = "Ya Credit Cards" ascii wide

        // Chrome v20 App-Bound Encryption key lookup
        $cng_key        = "Google Chromekey1" ascii wide

        // Russian-language error string (attribution)
        $cyrillic_err   = "Процесс winlogon.exe не найден" ascii wide

        // Obfuscated Stealer class name (survives compilation)
        $cls_stealer    = "S__T___e___aaa___ll_er" ascii wide

        // External IP endpoint (distinct from ip-api.com)
        $icanhazip      = "icanhazip.com" ascii wide

        // Seed phrase hunter extension set (all 9 together is a strong signal)
        $seedext        = ".seedphrase" ascii wide
        $seedext2       = ".mnemonic" ascii wide

        // Information.txt schema markers
        $info_user      = "[User Info]" ascii wide
        $info_hwid      = "Hwid: " ascii wide
        $info_clip      = "Clipboard: " ascii wide

        // Telegram Desktop file grabber target
        $tgdesk_path    = "Downloads\\Telegram Desktop" ascii wide

        // Steam mobile authenticator target (unusual extension)
        $mafile_ext     = ".mafile" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and pe.is_pe
        and dotnet.is_dotnet
        and pe.characteristics & pe.EXECUTABLE_IMAGE
        and (
            $mutex
            or $cls_stealer
            or ($ns_iroveroll and $tg_api and $autodel)
            or ($ver_product and $ver_comment)
            or ($cyrillic_err and $cng_key)
            or (4 of ($tg_api, $tg_send, $tg_caption, $wmi_cache, $wmi_cim,
                      $sandbox_ua, $sandbox_wdag, $discord_regex, $ya_passman, $ya_cards, $ver_company))
            or (3 of ($info_user, $info_hwid, $info_clip))                // Information.txt schema
            or ($seedext and $seedext2 and $icanhazip)                    // Grabber + network fingerprint
            or ($tgdesk_path and $mafile_ext)                              // Telegram-Downloads + Steam 2FA targets
        )
}

rule IRoveroll_Config_Embedded {
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "IRoveroll Telegram bot config - base64-split chat ID markers"
        date        = "2026-04-23"

    strings:
        // Config helpers
        $mutex          = "IMSEXYGIRL" ascii wide
        $tg_token_kw    = "BOT_TOKEN" ascii wide
        $config_chat    = "CHAT_ID" ascii wide

        // First base64 char of chat ID prefix ('-' encoded) -- low-specificity on its own
        $chatid_prefix  = "LQ==" ascii

        // The obfuscated Stealer class
        $cls_stealer    = "S__T___e___aaa___ll_er" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and $mutex
        and $tg_token_kw
        and $config_chat
        and ($chatid_prefix or $cls_stealer)
}
