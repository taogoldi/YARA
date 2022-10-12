import "pe"
rule dagon_locker_ransomware_unpacked {
  meta:
    description = "Detect unpacked Dagon Locker Ransomware"
    author = "Jake Goldi @ubersec"
    date = "2022-11-09"
    packed_hash1 = "a0fef8b9c275d11c2922db9f0bf0d696f4a8598de488c26d62313540eb22b470"
    packed_hash2 = "c70aa87fbbcc8e6e5d9c8272c4783d35ba607b07cc5e93e12dc4d0132bd84ef0"
    unpacked_hash = "8955db80bf0b9e71069ef8085f116c56e9525a8ffc64b665e0f7ecd9edcfac5f"
    version="1.0"
    phase = "experimental"
    url = "https://twitter.com/siri_urz/status/1575828753975910400"
    malware = "Win32.Unpacked.Ransom.Dagon.Locker"
strings:
    /*
        E8 B7 93 FF FF                          call    memset
        48 8D 15 CF 90 01 00                    lea     rdx, unk_140022ED0
        48 8D 8C 24 20 02 00 00                 lea     rcx, [rsp+728h+var_508]
        E8 92 E8 FF FF                          call    mw_API_hash_load
        48 8D 15 DB 29 01 00                    lea     rdx, unk_14001C7F0
        48 8D 8C 24 20 02 00 00                 lea     rcx, [rsp+728h+var_508]
        E8 7E E8 FF FF                          call    mw_API_hash_load
        48 8D 15 77 79 01 00                    lea     rdx, unk_1400217A0
        48 8D 8C 24 20 02 00 00                 lea     rcx, [rsp+728h+var_508]
        E8 6A E8 FF FF
    */
    $op1 = {e8 b7 93 ff ff 48 8d 15 ?? ?? 01 00 48 8d 8c 24 20 02 00 00 e8 ?? e8 ff ff 48 8d 15 ?? ?? 01 00 48 8d 8c 24 20 02 00 00 e8 ?? e8 ff ff 48 8d 15 ?? ?? 01 00 48 8d 8c 24 20 02 00 00 e8 ?? e8 ff ff }
condition:
    uint16(0) == 0x5a4d and filesize < 500KB and 
    (
        (
            pe.imphash() == "f0457f592cb6623fae51f7d4ebd0268f" and
            pe.number_of_sections > 4
        )
    ) or 
        (all of ($op*))
}