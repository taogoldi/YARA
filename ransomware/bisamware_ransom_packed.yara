import "pe"
rule bisamware_ransomware_packed {
    meta:
        description = "Detect packed variants of Bisamware Ransomware"
        author = "Jake Goldi @ubersec"
        date = "2022-09-29"
        packed_hash1 = "3758900465a0bbb5ce4eab1a5c981a7c35b8334427f606ab722223e2b2dacc73"
        version="1.0"
        phase = "experimental"
        url = "https://twitter.com/h2jazi/status/1570246177756413953"
        malware = "Win64.Ransom.Packed.Bisam"
    strings:
        $s1 = "Bisamware"
        /*
            4A 8D 54 04 20                          lea     rdx, [rsp+r8+138h+LibFileName]
            F5                                      cmc
            41 8B C8                                mov     ecx, r8d
            48 0F B7 C3                             movzx   rax, bx
            66 41 0F B6 C6                          movzx   ax, r14b
            B8 ?? ?? ?? ??                          mov     eax, <int>
            F5                                      cmc
            D3 C0                                   rol     eax, cl
            41 02 C0                                add     al, r8b
            41 32 04 11                             xor     al, [r9+rdx]
            E9 00 00 00 00                          jmp     $+5
        */

        $op1 = {4A 8D 54 04 20 F5 41 8B C8 48 0F B7 C3 66 41 0F B6 C6 B8 ?? ?? ?? ?? F5 D3 C0 41 02 C0 41 32 04 11 E9 00 00 00 00}

        /*
            48 8D 4C 24 20                          lea     rcx, [rsp+138h+LibFileName] ; lpLibFileName
            40 8A C5                                mov     al, bpl
            41 0F BF C1                             movsx   eax, r9w
            48 0F BF C5                             movsx   rax, bp
            48 8B 05 4E B1 F5 FF                    mov     rax, cs:LoadLibraryA
            FF D0                                   call    rax ; LoadLibraryA
            48 81 C4 ?? ?? ?? ??                    add     rsp, <int>
            E9 00 00 00 00                          jmp     $+5
        */

        $op2 = {48 8D 4C 24 20 40 8A C5 41 0F BF C1 48 0F BF C5 48 8B 05 4E B1 F5 FF FF D0 48 81 C4 ?? ?? ?? ?? E9}
    condition:
        uint16(0) == 0x5a4d and (
            (pe.imphash() == "ff82513c4fa00b7d17d53d76a64daf90" or pe.exports("DotNetRuntimeDebugHeader")) and
            for any i in ( 0..pe.number_of_sections -1 ) : 
                (pe.sections[i].name contains "bmw") 
            or
            ((all of ($s*))
            and 
            (all of ($op*)))
    )
}