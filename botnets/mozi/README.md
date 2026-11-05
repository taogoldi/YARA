# Mozi: the P2P IoT bot and its tampered UPX packing

`mozi.yar` (2026-11-04), two rules.

Mozi builds its peer network on the BitTorrent DHT, takes over routers through their TR-069 management settings,
and closes the ports it came in through with iptables. Almost every copy is a 32-bit MIPS or ARM ELF packed with UPX
and then damaged on purpose. The three `p_info` fields after UPX's `l_info` header are zeroed and the trailing
PackHeader is wiped, so `upx -d` refuses the file ("header corrupted"). The compressed blocks are intact (NRV2B), so
a short block decoder recovers the bot. In this corpus most copies were also truncated, but the decoder still
recovers the part that is present.

| Rule | Matches |
|---|---|
| `Linux_Mozi_Payload` | The bot: 3 of its configuration closing tags (`[/cnc]`, `[/atk]`, `[/dip]`, `[/ver]`, `[/cpu]`, `[/count]`), plus 2 DHT bootstrap nodes or one of its own paths and router settings (`/usr/networks`, `"acsMozi"`, `/etc/init.d/S95baby.sh`, `ConnectionRequestUsername notitms`) |
| `Linux_Mozi_UPX_Tampered` | The packed form: an ELF32 UPX file with all three `p_info` fields zero and no PackHeader. A packer trait, not content |

The packed rule says nothing about what is inside. In the corpus below, every file it matched that decoded far
enough to read was Mozi, but another family adopting the same trick would match too. Decode and run the payload rule
when the identification matters.

## Measured (2026-11-04)

| Set | Result |
|---|---|
| Mozi-labelled copies (170 ELF) | 149 matched by `Linux_Mozi_UPX_Tampered`. The other 21: 11 are not UPX-packed, 10 keep their PackHeader |
| Same copies, decoded (158) | 72 matched by `Linux_Mozi_Payload`, of the 74 that hold any Mozi string. The other 2 end three tags into the configuration (truncated copies); the rest were truncated before it |
| Malware corpus, 193,816 local ELF | `Linux_Mozi_UPX_Tampered`: 771 (labels: 149 Mozi, 121 Mirai, 81 Dakkatoni, 415 none). Decoded, 404 matched the payload rule, and all 339 that decoded to 300 or more strings were Mozi |
| Same corpus | `Linux_Mozi_Payload`: 266 unpacked files, labelled Mirai (252) or Gafgyt (14). All carry `acsMozi`, `S95baby.sh` or `/usr/networks` and the literal `Mozi`: Mozi bots under a Mirai or Gafgyt label |
| Clean ELF: a benign software set (14,698) and a Debian system image (1,603) | 0 matched |

Reference samples:

- Packed (tampered UPX, MIPS): `05d459c9f944cbc3586ceac0c277268e5c611fb9962bab9744dc2893b23ee248`
- Unpacked bot (labelled Mirai): `003d54ad5c9f8105ec03c0e6e52b9bcd414fde4a7812ff7335ad1394b5ea1fc5`
