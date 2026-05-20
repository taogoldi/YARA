// StudioSecGhost hVNC + browser-piggyback agent
// Author: taogoldi
// Date:   2026-05-19
// TLP:    TLP:CLEAR
// Hash:   5940c41ab003399680a04d726587eed242e4ad8969abe4b5617d712ff190a852

import "pe"

rule StudioSecGhost_HVNC_Agent
{
    meta:
        author      = "taogoldi"
        version     = 1
        date        = "2026-05-19"
        hash        = "5940c41ab003399680a04d726587eed242e4ad8969abe4b5617d712ff190a852"
        tlp         = "TLP:CLEAR"
        family      = "StudioSecGhost"
        description = "Native x64 hidden-VNC agent that piggybacks on real Chrome/Edge/Firefox and cloaks a sibling ghost window. Internal builder marker StudioSecGhost is left in the bounce HTML title."

    strings:
        // Internal builder marker (binary's own self-identifier)
        $bid_title          = "<html><head><title>StudioSecGhost</title></head><body>" ascii
        $bid_search         = "StudioSecGhost" wide
        $bid_banner_class   = "StudioSecVNC_Banner" wide
        $bid_banner_title   = "StudioSecVNC Banner" wide
        $bid_anchor_a       = "GSystem" wide
        $bid_anchor_b       = ".SecAnchor" wide

        // Distinctive log-format prefixes (composite signature)
        $log_chrome_pigg    = "[CHROME] Chrome already running. Piggybacking immediately." ascii
        $log_chrome_ghost   = "[CHROME] Found ghost among hidden windows: HWND=%p" ascii
        $log_chrome_prefs   = "[CHROME] Firefox prefs.js patched: crash recovery disabled." ascii
        $log_chrome_bounce  = "[CHROME] Failed to resolve bounce path." ascii
        $log_vnc_stream     = "[VNC] StreamThread started (%dx%d)%s." ascii
        $log_vnc_capture    = "[VNC] WindowCapturer: init OK (%dx%d), HWND=%p." ascii
        $log_net_auth       = "[NET] AUTH_LOGIN sent: '%ls' (browsers: %d, active: %d)" ascii
        $log_net_target     = "[NET] AgentNetwork started. Target: %ls:%u" ascii
        $log_init_replica   = "[INIT] Replica deployed: slot %d" ascii
        $log_init_watchdog  = "[INIT] Watchdog restored replica slot %d" ascii

        // Filesystem and persistence artifacts (drop names)
        $art_bounce_a       = "studiosec_bounce.html" wide
        $art_bounce_b       = "chrome_update_manifest.html" wide
        $art_task_xml       = "chrome_task_%u.xml" wide
        $art_cleanup        = "ssv_cleanup.bat" wide

        // Victim-facing lockout banner
        $banner_text        = "  WARNING!  SECURITY AUDIT IN PROGRESS.  " wide

        // Browser launch arguments (Chromium piggyback profile)
        $browser_args       = "--hide-crash-restore-bubble --disable-backgrounding-occluded-windows --disable-renderer-backgrounding --disable-occlusion-tracking" wide

    condition:
        uint16(0) == 0x5a4d
        and pe.machine == pe.MACHINE_AMD64
        and pe.imports("mscoree.dll") == 0
        and pe.imports("gdiplus.dll", "GdipSaveImageToStream")
        and pe.imports("WS2_32.dll", "send")
        and (
            $bid_search
            or $bid_title
            or $bid_banner_class
        )
        and 3 of ($log_*)
        and any of ($art_*)
}

rule StudioSecGhost_Bounce_HTML
{
    meta:
        author      = "taogoldi"
        version     = 1
        date        = "2026-05-19"
        tlp         = "TLP:CLEAR"
        family      = "StudioSecGhost"
        description = "Dropped bounce HTML used to seed the ghost window title. Lives at %TEMP%\\studiosec_bounce.html or %TEMP%\\chrome_update_manifest.html."

    strings:
        $a = "<html><head><title>StudioSecGhost</title></head><body>" ascii
        $b = "window.location.replace(" ascii
        $c = "setTimeout(function(){" ascii

    condition:
        filesize < 4KB and all of them
}
