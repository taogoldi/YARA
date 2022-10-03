import "pe"
rule crytox_ransomware_packed {
  meta:
    description = "Detect packed variants of Crytox Ransomware"
    author = "Jake Goldi @ubersec"
    date = "2022-09-29"
    packed_hash1 = "32eef267a1192a9a739ccaaae0266bc66707bb64768a764541ecb039a50cba67"
    version="1.0"
    phase = "experimental"
    url = "https://www.zscaler.com/blogs/security-research/technical-analysis-crytox-ransomware"
    malware = "Win64.Ransom.Packed.Crytox"
  condition:
    uint16(0) == 0x5a4d and filesize < 1500KB and filesize > 1000KB and (pe.imphash() == "365b1d12b684a96b167a74679ec9e4e3" and 
        (pe.sections[0].name contains "UPX0" and pe.sections[1].name contains "UPX1") )
}
    