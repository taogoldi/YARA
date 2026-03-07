import "elf"

rule Linux_KaijiLike_Persist_C2_0a70 {
  meta:
    author = "taogoldi"
    family = "kaiji-like"
    version = "1"
    sha256 = "0a70d7699c8e0629597dcc03b1aef0beebec03ae0580f2c070fb2bfd2fd89a71"
    scope = "file"
    description = "Kaiji-like Go ELF with embedded base64 C2 token and quotaoff persistence"

  strings:
    $b64_c2 = "YWlyLnhlbS5sYXQ6MjUxOTR8KG9kaykvKi0=" ascii
    $persist_service = "/usr/lib/systemd/system/quotaoff.service" ascii
    $persist_cron = "echo \"*/1 * * * * root /.mod \" >> /etc/crontab" ascii
    $persist_exec = "ExecStart=/boot/System.mod" ascii
    $drop_path = "/usr/sbin/ifconfig.cfg" ascii
    $module_tag = "[a=r=e=s]]" ascii

  condition:
    elf.type == elf.ET_EXEC and
    filesize < 5MB and
    4 of ($b64_c2, $persist_service, $persist_cron, $persist_exec, $drop_path, $module_tag)
}

rule Linux_KaijiLike_AresModuleSet_0a70 {
  meta:
    author = "taogoldi"
    family = "kaiji-like"
    version = "1"
    sha256 = "0a70d7699c8e0629597dcc03b1aef0beebec03ae0580f2c070fb2bfd2fd89a71"
    scope = "file"
    description = "Kaiji/Ares attack module namespace and source path indicators"

  strings:
    $fn1 = "main.Ares_ipspoof" ascii
    $fn2 = "main.Ares_L3_Udp" ascii
    $fn3 = "main.Ares_Tcp_Keep" ascii
    $fn4 = "main.Killcpu" ascii
    $src1 = "C:/src/client/linux/ares_tcp.go" ascii
    $src2 = "C:/src/client/linux/ares_udp.go" ascii
    $src3 = "C:/src/client/linux/ares_spoof.go" ascii
    $src4 = "C:/src/client/linux/killcpu.go" ascii

  condition:
    elf.type == elf.ET_EXEC and
    filesize < 5MB and
    6 of them
}
