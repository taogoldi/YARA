rule Android_GbcBot_ENS_ChaCha_C2_Resolver
{
    meta:
        description = "GbcBot (name assigned by the author, no public family name): native Android TV bot shipped as libgbc.so in the APK com.android.shop. Reads a ChaCha20-encrypted address list from an ENS text record; the key is keccak256 of the label ens_ips_v1 and a constant in the build. Strings sit in an RC4 table"
        author = "Tao Goldi"
        date = "2026-11-05"
        version = "1.0"
        family = "GbcBot"
        sha256 = "78b84e2f2f9cd28afda5d5687b91e63b68b8252311c19104b4c79f646f2ab19e"
        sha256_2 = "1ea03e6f674a0d870a3a15b7dae589266436cff7bd900049d34fa58cacf48370"
    strings:
        $call = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"0x" ascii
        $label = "ens_ips_v1" ascii
        $p1 = "android-tv-sysboot" ascii
        $p2 = "android-tv-preboot" ascii
        $p3 = "android-tv-posts" ascii
        $p4 = "android-tv-emu" ascii
        $svc = "com.android.shop/.SDKService" ascii
        // RC4 table entries under the key 6e 79 76 66 65 25 a9 76 39 77 7d 2d 7f 30 31 77
        $name_enc = { 9a 3f ea 3a e0 3b 96 92 48 18 00 06 4f 1c 8e }                                    // libservice.eth
        $key_enc = { 85 24 fe 2e e4 24 85 fb }                                                          // srvgame
        $oom_enc = { d9 26 fa 26 e6 66 93 9e 47 1b 01 0c 54 19 d1 cf d6 85 68 93 2b ad 91 c9 f2 }       // /proc/self/oom_score_adj
    condition:
        uint32(0) == 0x464c457f and filesize < 2MB and $call and $label
        and (2 of ($p*) or $svc or $name_enc or ($key_enc and $oom_enc))
}
