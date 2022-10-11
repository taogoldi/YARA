import "pe"
rule dagon_locker_ransomware {
  meta:
    description = "Detect Dagon Locker Ransomware"
    author = "Jake Goldi @ubersec"
    date = "2022-10-09"
    hash1 = "a0fef8b9c275d11c2922db9f0bf0d696f4a8598de488c26d62313540eb22b470"
    hash2 = "c70aa87fbbcc8e6e5d9c8272c4783d35ba607b07cc5e93e12dc4d0132bd84ef0"
    version="1.0"
    phase = "experimental"
    url = "https://twitter.com/siri_urz/status/1575828753975910400"
    malware = "Win32.Ransom.Dagon.Locker"
strings:
    $s1 = "sc.exe" wide ascii nocase
    $s2 = "CoLoadLibrary" wide ascii nocase
    /*

        Hash 1: a0fef8b9c275d11c2922db9f0bf0d696f4a8598de488c26d62313540eb22b470
        48 8D 0D 07 EB 04 00                    lea     rcx, a6         ; "6"
        48 8B 05 BE 70 05 00                    mov     rax, cs:__imp__wtoi
        FF D0                                   call    rax ; __imp__wtoi
        89 C6                                   mov     esi, eax
        48 8D 0D FB EA 04 00                    lea     rcx, a4096      ; "4096"
        48 8B 05 AC 70 05 00                    mov     rax, cs:__imp__wtoi
        FF D0                                   call    rax ; __imp__wtoi
        89 C3                                   mov     ebx, eax
        48 8D 0D F3 EA 04 00                    lea     rcx, a8         ; "8"
        48 8B 05 9A 70 05 00                    mov     rax, cs:__imp__wtoi
        FF D0                                   call    rax ; __imp__wtoi
        09 D8                                   or      eax, ebx
        89 C2                                   mov     edx, eax

        8B 45 28                                mov     eax, dword ptr [rbp+dwSize]
        41 89 F1                                mov     r9d, esi        ; flProtect
        41 89 D0                                mov     r8d, edx        ; flAllocationType
        48 89 C2                                mov     rdx, rax        ; dwSize
        B9 00 00 00 00                          mov     ecx, 0          ; lpAddress
        48 8B 05 A4 6F 05 00                    mov     rax, cs:__imp_VirtualAlloc
        FF D0                                   call    rax ; __imp_VirtualAlloc
        48 89 45 F0                             mov     [rbp+var_10], rax
        48 83 7D F0 00                          cmp     [rbp+var_10], 0
        75 07                                   jnz     short loc_401578
        B8 00 00 00 00                          mov     eax, 0
        EB 70 

        Hash 2: c70aa87fbbcc8e6e5d9c8272c4783d35ba607b07cc5e93e12dc4d0132bd84ef0 
        48 8D 0D 79 BA 02 00                    lea     rcx, a64        ; "64"
        48 8B 05 1A 40 03 00                    mov     rax, cs:_wtoi
        FF D0                                   call    rax ; _wtoi
        89 C6                                   mov     esi, eax
        48 8D 0D 6D BA 02 00                    lea     rcx, a4         ; "4"
        48 8B 05 08 40 03 00                    mov     rax, cs:_wtoi
        FF D0                                   call    rax ; _wtoi
        89 C3                                   mov     ebx, eax
        48 8D 0D 65 BA 02 00                    lea     rcx, a8192      ; "8192"
        48 8B 05 F6 3F 03 00                    mov     rax, cs:_wtoi
        FF D0                                   call    rax ; _wtoi
        09 D8                                   or      eax, ebx
        89 C2                                   mov     edx, eax

        8B 45 28                                mov     eax, dword ptr [rbp+dwSize]
        41 89 F1                                mov     r9d, esi        ; flProtect
        41 89 D0                                mov     r8d, edx        ; flAllocationType
        48 89 C2                                mov     rdx, rax        ; dwSize
        B9 00 00 00 00                          mov     ecx, 0          ; lpAddress
        48 8B 05 00 3F 03 00                    mov     rax, cs:VirtualAlloc
        FF D0                                   call    rax ; VirtualAlloc
        48 89 45 F0                             mov     [rbp+var_10], rax
        48 83 7D F0 00                          cmp     [rbp+var_10], 0
        75 07                                   jnz     short loc_40161C
        B8 00 00 00 00                          mov     eax, 0
        EB 6A                                   jmp     short loc_401686
    */
    
    $op1 = {8b45284189f14189d04889c2b900000000488b05???f0?00ffd0488945f048837df0007507b800000000eb}

condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and 
    (
        (
            pe.imphash() == "8976a2145c27db94c55480b99c25f1af" and (1 of ($s*))
        ) 
        or 
        (all of ($op*))
    )
}