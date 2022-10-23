import "pe"
rule dagon_locker_ransomware_packed {
  meta:
    description = "Detect Packed Dagon Locker Ransomware"
    author = "Jake Goldi @ubersec"
    date = "2022-11-09"
    packed_hash1 = "a0fef8b9c275d11c2922db9f0bf0d696f4a8598de488c26d62313540eb22b470"
    packed_hash2 = "c70aa87fbbcc8e6e5d9c8272c4783d35ba607b07cc5e93e12dc4d0132bd84ef0"
    version="1.0"
    phase = "experimental"
    url = "https://twitter.com/siri_urz/status/1575828753975910400"
    malware = "Win64.Packed.Ransom.Dagon.Locker"
strings:
    $s1 = "sc.exe" wide ascii nocase
    $s2 = "CoLoadLibrary" wide ascii nocase
    /*

        packed_hash1: a0fef8b9c275d11c2922db9f0bf0d696f4a8598de488c26d62313540eb22b470
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

        packed_hash2: c70aa87fbbcc8e6e5d9c8272c4783d35ba607b07cc5e93e12dc4d0132bd84ef0 
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

    /*
        packed_hash1: a0fef8b9c275d11c2922db9f0bf0d696f4a8598de488c26d62313540eb22b470
        48 C7 45 A0 00 00 00 00                 mov     [rbp+0A10h+var_A70], 0
        C7 45 A8 01 00 00 00                    mov     [rbp+0A10h+var_A68], 1
        8B 85 F8 09 00 00                       mov     eax, [rbp+0A10h+var_18]
        89 C2                                   mov     edx, eax        ; unsigned int
        48 8D 0D 46 49 01 00                    lea     rcx, _data      ; unsigned __int8 *
        E8 11 FE FF FF                          call    mw_mem_buff_allocation_key_xor
        48 89 45 B0                             mov     [rbp+0A10h+var_A60], rax
        8B 95 FC 09 00 00                       mov     edx, [rbp+0A10h+buff_size] ; unsigned int
        48 8D 45 C0                             lea     rax, [rbp+0A10h+array_buff]
        48 89 C1                                mov     rcx, rax        ; unsigned __int8 *
        E8 FB FD FF FF                          call    mw_mem_buff_allocation_key_xor
        48 89 85 F0 09 00 00                    mov     [rbp+0A10h+var_20], rax
        48 8B 85 F0 09 00 00                    mov     rax, [rbp+0A10h+var_20]
        48 8D 55 A0                             lea     rdx, [rbp+0A10h+var_A70]
        48 89 D1                                mov     rcx, rdx
        FF D0                                   call    rax

        packed_hash2: c70aa87fbbcc8e6e5d9c8272c4783d35ba607b07cc5e93e12dc4d0132bd84ef0 
        48 C7 45 A0 00 00 00 00                 mov     [rbp+0A10h+var_A70], 0
        C7 45 A8 01 00 00 00                    mov     [rbp+0A10h+var_A68], 1
        8B 85 F8 09 00 00                       mov     eax, [rbp+0A10h+var_18]
        89 C2                                   mov     edx, eax
        48 8D 0D A8 48 01 00                    lea     rcx, unk_416020
        E8 73 FD FF FF                          call    sub_4014F0
        48 89 45 B0                             mov     [rbp+0A10h+var_A60], rax
        8B 95 FC 09 00 00                       mov     edx, [rbp+0A10h+var_14]
        48 8D 45 C0                             lea     rax, [rbp+0A10h+var_A50]
        48 89 C1                                mov     rcx, rax
        E8 5D FD FF FF                          call    sub_4014F0
        48 89 85 F0 09 00 00                    mov     [rbp+0A10h+var_20], rax
        48 8B 85 F0 09 00 00                    mov     rax, [rbp+0A10h+var_20]
        48 8D 55 A0                             lea     rdx, [rbp+0A10h+var_A70]
        48 89 D1                                mov     rcx, rdx
        FF D0                                   call    rax
        B8 00 00 00 00                          mov     eax, 0
        EB 08                                   jmp     short loc_4017B9

    */
    $op2 = {48c745a000000000c745a8010000008b85f809000089c2488d0d??4?0100e8????ffff488945b08b95fc090000488d45c04889c1e8??fdffff488985f0090000488b85f0090000488d55a04889d1ffd0}

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