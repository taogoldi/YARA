/*
   shc-compiled shell scripts (any build)
   Author: Tao Goldi
   TLP:WHITE

   shc (https://github.com/neurobin/shc) turns a shell script into an ELF: the script, the shell path and the
   check strings are RC4-encrypted in .data, and a small C runtime decrypts them and re-executes the shell with
   the script. The runtime's own strings stay in clear in every build: its argv[0] error message and the two
   formats it uses to pass state to the re-executed copy through the environment. They survive stripping,
   -O0/-O2/static builds and architecture changes. The expiry message ("has expired!") is encrypted with the
   script, so it is not a usable string.

   This identifies the wrapper, not what the script does: miners, SSH brute-force kits and droppers ship this way,
   and so do ordinary admin scripts. The shc compiler embeds the runtime as C source text and is excluded. Recover
   the script (any shc decoder) to judge the sample.
*/

rule Linux_SHC_Compiled_Script_Generic
{
    meta:
        description  = "ELF built by shc (shell script compiler): the shc runtime's argv[0] error message and environment state formats; identifies the wrapper only, recover the script to judge it"
        author       = "Tao Goldi"
        reference    = "https://github.com/neurobin/shc"
        date         = "2026-11-04"
        version      = 1
        tool         = "shc"
        severity     = "medium"
        mitre_attack = "T1027.002, T1059.004"
        scope        = "file"
        sha256       = "f6371d8b3bcc784017d4fbb544550873281cdc4aa4167ffac91526126d3b4e01"

    strings:
        $rt1 = "E: neither argv[0] nor $_ works." ascii
        $rt2 = "=%lu %d" ascii
        $rt3 = "%lu %d%c" ascii
        $rt4 = "x%lx" ascii
        $compiler1 = "Script Compiler" ascii
        $compiler2 = "/* rtc.c */" ascii

    condition:
        uint32(0) == 0x464c457f and all of ($rt*) and not any of ($compiler*)
}
