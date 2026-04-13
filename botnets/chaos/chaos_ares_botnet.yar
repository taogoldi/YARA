import "elf"

rule Chaos_Ares_DDoS_Botnet
{
    meta:
        description = "Detects Chaos/Kaiji botnet Ares variant with DDoS attack modules and DNS-based C2"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        sha256 = "a2ce4bfd8411324b10576d228b04cb8036e61b998ae9162e6f81ab65cf7416bd"
        severity = "critical"
        family = "Chaos/Kaiji"
        variant = "Ares"
        mitre_attack = "T1498,T1090,T1059.004,T1053.003,T1543.002"

    strings:
        // Ares-branded attack functions (Go symbol names in pclntab)
        $ares1 = "Ares_Plain_Udp" ascii
        $ares2 = "Ares_L3_Raw" ascii
        $ares3 = "Ares_ipspoof" ascii
        $ares4 = "Ares_Tcp" ascii
        $ares5 = "Ares_L3_Udp" ascii
        $ares6 = "Ares_Tcp_Keep" ascii
        $ares7 = "Ares_send" ascii

        // Chaos protocol functions
        $chaos1 = "chaos_readfromreader" ascii
        $chaos2 = "chaos_checkMsg" ascii

        // DNS-based C2
        $dns1 = "Dns_Url" ascii
        $dns2 = "Dns_Key" ascii

        // Persistence paths
        $persist1 = "/boot/System.mod" ascii
        $persist2 = "quotaoff.service" ascii
        $persist3 = "/lib/system-mark" ascii
        $persist4 = "ifconfig.cfg" ascii

        // Source path leak
        $src = "C:/src/client/linux/" ascii

    condition:
        elf.machine == elf.EM_X86_64 and
        (
            (3 of ($ares*)) or
            ($chaos1 and $chaos2) or
            ($dns1 and $dns2 and 2 of ($ares*)) or
            ($src and 2 of ($ares*)) or
            (2 of ($persist*) and 1 of ($ares*))
        )
}

rule Chaos_Kaiji_Generic
{
    meta:
        description = "Generic detection for Chaos/Kaiji Go botnet family across architectures"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        severity = "high"
        family = "Chaos/Kaiji"

    strings:
        // Chaos protocol markers
        $chaos1 = "chaos_readfromreader" ascii
        $chaos2 = "chaos_checkMsg" ascii
        $chaos3 = "chaos_grow" ascii

        // Attack module patterns
        $atk1 = "Ares_Plain_Udp" ascii
        $atk2 = "Ares_L3_Raw" ascii
        $atk3 = "Ares_ipspoof" ascii
        $atk4 = "Ares_Tcp_Keep" ascii
        $atk5 = "Ares_L3_Udp" ascii

        // Kill/watchdog
        $kill1 = "Killcpu" ascii
        $kill2 = "Killsh" ascii
        $watch = "Watchdog" ascii

        // SOCKS proxy
        $socks1 = "Socks5Auth" ascii
        $socks2 = "Socks5Connect" ascii
        $proxy = "StartProxy" ascii

        // Terminal
        $term1 = "terminalrun" ascii
        $term2 = "terminalclose" ascii

        // Crypto
        $crypt1 = "DecryptCFB" ascii
        $crypt2 = "DecryptCBC" ascii
        $crypt3 = "DecryptECB" ascii

    condition:
        filesize < 10MB and
        (
            (2 of ($chaos*)) or
            (3 of ($atk*) and 1 of ($chaos*)) or
            (1 of ($chaos*) and 1 of ($kill*) and ($socks1 or $socks2) and 1 of ($term*)) or
            (3 of ($atk*) and 2 of ($crypt*) and $watch)
        )
}

rule Chaos_Ares_Persistence_Scripts
{
    meta:
        description = "Detects Chaos/Ares persistence via embedded init scripts and SELinux bypass"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        severity = "critical"
        family = "Chaos/Kaiji"

    strings:
        $rc = "/etc/rc.d/rc.local" ascii
        $initd = "/etc/init.d/boot.local" ascii
        $profile1 = "/etc/profile.d/bash_cfg" ascii
        $profile2 = "/etc/profile.d/gateway.sh" ascii
        $systemd = "quotaoff.service" ascii
        $boot = "/boot/System.mod" ascii
        $marker = "/lib/system-mark" ascii
        $cron = "/.mod" ascii
        $selinux = "audit2allow" ascii
        $chkconfig = "chkconfig: 2345" ascii

    condition:
        filesize < 10MB and
        (
            (3 of ($rc, $initd, $profile1, $profile2, $systemd, $boot)) or
            ($selinux and $boot) or
            ($chkconfig and $boot and $marker) or
            ($cron and $boot and 1 of ($profile1, $profile2))
        )
}
