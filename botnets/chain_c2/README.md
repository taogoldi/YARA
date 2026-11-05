# Linux bots that keep their C2 on a blockchain

Twelve rules (2026-11-05) for Linux bots that do not carry a usable C2 address. Each one asks a public JSON-RPC
endpoint for a value its operator can change at will: a smart contract's storage on Polygon, or a record of an
Ethereum Name Service (ENS) name. Taking down a server does not help, because the operator writes a new address to
the chain and every bot picks it up. A sandbox with no route out never sees the C2 either; it only sees the lookups.

All of these build the `eth_call` request by hand, with a format string or by concatenation, which is what the rules key on.

| Rule | File | What it matches |
|---|---|---|
| `Linux_Boatnet_Polygon_C2_Resolver` | `boatnet_polygon_c2.yar` | Boatnet: `get()` (`0x6d4ce63c`) on a Polygon contract, value is an AES-128 encrypted line list (CBC in 1.0.x, GCM from 1.2.x) |
| `Linux_Mirai_Akuma_Polygon_C2_Resolver` | `mirai_akuma_polygon_c2.yar` | Mirai fork with bot ids `akuma.*`: contract, selector and port hidden as XOR shares; the contract returns a fake `2001:db8::` IPv6 string that decodes to an IPv4 |
| `Linux_Mirai_ENS_Ouroboros_C2_Resolver` | `mirai_ens_c2_resolvers.yar` | ENS text record `ouroboros`: `::ffff:x:x:x`, six bytes XOR `0xDE` = IPv4 and port |
| `Linux_Mirai_ENS_Rc4_TextRecord_C2_Resolver` | `mirai_ens_c2_resolvers.yar` | ENS text record `your_public_ip`: a dotted quad that is RC4-encrypted with the key `GET/dlr.`; names in an RC4 string table. A later form asks the ENS universal resolver |
| `Linux_Bot_ENS_ProxyIps_C2_Resolver` | `mirai_ens_c2_resolvers.yar` | ENS text record `proxy.ips` of a hard-coded node: a plain comma-separated IPv4 list |
| `Linux_Mirai_ENS_IpRecords_C2_Resolver` | `mirai_ens_c2_resolvers.yar` | DVR bot: ENS text records `ip`, `ip2` .. `ip14`, IPv4 with the two halves swapped; name and keys in a ChaCha20 string table |
| `Linux_Mirai_ENS_DvrBot_March_C2_Resolver` | `mirai_ens_c2_resolvers.yar` | The same DVR bot, March to July 2026: asks the ENS public resolver directly; text record `2001:db8:AABB:CCDD::1`, bytes XOR `0xA5` |
| `Linux_Mirai_ENS_DvrBot_July_C2_Resolver` | `mirai_ens_c2_resolvers.yar` | The same DVR bot, July to August 2026: ENS text records `ipv4` and `telnet`, plain; also resolves Solana names |
| `Linux_Mirai_ENS_Drunkasfk_C2_Resolver` | `mirai_ens_c2_resolvers.yar` | Build marker `drunkasfk`: request built by concatenation, ENS text record `woah` |
| `Linux_Kimwolf_ENS_Addr_C2_Resolver` | `kimwolf_ens_c2.yar` | Kimwolf: ENS address record, last four bytes XOR `93 14 17 15` = IPv4; strings in a per-entry xorshift table |
| `SUSP_ELF_ENS_Registry_Lookup` | `mirai_ens_c2_resolvers.yar` | Heuristic: small ELF with an `eth_call` request and either the ENS registry address plus the `resolver(bytes32)` selector, or the ENS public resolver address |
| `SUSP_ELF_EthCall_C2_Resolver` | `susp_elf_eth_call_c2.yar` | Heuristic: any ELF under 10 MB with a hand-built `eth_call` request |

The two `SUSP_` rules say how a file finds its server, not which family it is. Wallet tools and node software
would match them if they were built the same way; none did in the sets below.

## How each build decodes its value

The DVR bot appears four times below. Its March, July, August and September builds share their path lists and
differ in the name, the record and the string protection. The two older builds keep their strings in a reworked
RC4: a 16-byte key read as four words in the file's byte order, a key schedule mixed with an LCG, and an LFSR
folded into every output byte. Each table entry restarts the stream, so the table reads by sliding the stream
over the constants; the key sits right after the table.

| Build | Chain | Where | Decoding |
|---|---|---|---|
| Boatnet 1.0.x | Polygon | contract `get()` | IV (16) + AES-128-CBC, key in the binary as 32 hex characters |
| Boatnet 1.2.x and later | Polygon | contract `get()` | nonce (12) + AES-128-GCM + tag (16); line list: C2 `host:port`, miner pool and wallet from 2026-10-24 |
| Akuma | Polygon | contract, selector `0xc5a56599` | last 12 bytes of the fake IPv6 text, `ror8(b - 13*i, 3) ^ table[(7*i) & 31]`, the IPv4 three times |
| Ouroboros | Ethereum | `text(node, "ouroboros")` | hextets a:b:c, bytes XOR `0xDE`, 4 bytes IPv4 + 2 bytes port |
| RC4 text record | Ethereum | `text(node, "your_public_ip")` | 4 bytes RC4 with `GET/dlr.` (the string table uses RC4 with an XOR swap, which zeroes a cell when i equals j) |
| proxy.ips | Ethereum | `text(node, "proxy.ips")` | none; the same node also holds `proxy.port`, `bin.base` and `gen` |
| ip records | Ethereum | `text(node, "ip")` .. `"ip14"` | the two halves of the dotted quad are swapped: record `C.D.A.B` is host `A.B.C.D`. The bot does the same to the A records of its fallback domains |
| Kimwolf | Ethereum | `addr(node)` | last 4 bytes XOR `93 14 17 15` |
| DVR bot, March | Ethereum | `text(node, "k1er4n")`, asked of the public resolver | `2001:db8:AABB:CCDD::1`, the four bytes XOR `0xA5` |
| DVR bot, July | Ethereum, Solana | `text(node, "ipv4")`, `text(node, "telnet")`; `.sol` names through an SNS proxy | none; addresses separated by a vertical bar |
| Drunkasfk | Ethereum | `text(node, "woah")` | `[a:b:c:d::e:f|...]:port`, a list of IPv6-looking entries whose last 32 bits carry the address; the transform was not recovered |
| Vibenet (one sample, covered by the heuristics only) | Ethereum | `text(node, "description")`, `"meow"` | base64 of a comma-separated IPv4 list |

## Indicators (read 2026-11-05, defanged)

| Build | On chain | Value history |
|---|---|---|
| Boatnet 1.0.x | Polygon `0xCb53AE835855AfA955580EA781dF78bF82B1f2dC` | `213[.]111[.]144[.]211:443`, set once 2026-03-16 |
| Boatnet 1.2.x+ | Polygon `0x5D5abC33a4e5C602a002815d93806b204324D1a1` | 21 updates 2026-09-15 to 2026-11-03; current `80[.]87[.]206[.]91`, `.95`, `.86` on 443, `85[.]137[.]54[.]178:443` |
| Akuma | Polygon `0x084a379b1E18c153212015bCCD60295C948EaAe2` | `191[.]217[.]203[.]232:25565` |
| Ouroboros | `bossmen[.]eth` | 2026-09-21 `176[.]65[.]139[.]158:45678`; from 2026-09-22 `201[.]7[.]16[.]231:11121` (54887 for 18 minutes) |
| RC4 text record | `chinkon[.]eth` (C2), `infectedchink[.]eth` (scan ranges and loader, port 80) | 2026-10-10 `176[.]65[.]139[.]40`; 2026-10-15 the loader record decoded to `45[.]90[.]163[.]37` for two minutes and then to `202[.]42[.]45[.]124` for 20 hours (the two are each other's RC4 image, so one was written unencrypted); from 2026-10-16 `185[.]228[.]72[.]128` (C2) and `130[.]12[.]46[.]145` (loader) |
| proxy.ips | node `0xdaa10029263ba2403b2e3a338719ec43cc30a2ce3ed3842207890c2d0d0eecf0` | 2026-10-23 `185[.]95[.]231[.]143`, `91[.]92[.]46[.]91`, `83[.]171[.]227[.]116`, `135[.]136[.]27[.]193`, port 443; `bin.base` `hxxp://elliotsdog[.]ru/bins/` |
| ip records | `catswithhatslolksjhakf[.]eth` (September builds), `dumbfuckerslol[.]eth` (August builds); fallback hosts under `botlesscucks[.]st`, `potassium[.]st`, `leandro[.]st` | `catswithhatslolksjhakf`: record `49.6.172.233` since 2026-09-11, which is host `172[.]233[.]49[.]6`. `dumbfuckerslol`: twelve records, hosts `89[.]185[.]82[.]69`, `91[.]92[.]242[.]19`, `45[.]95[.]232[.]146`, `45[.]142[.]31[.]186`, `87[.]251[.]69[.]139`, `31[.]56[.]19[.]70` to `.75` and `.111` |
| DVR bot, March | `m3rnbvs5d[.]eth`; `kieron[.]androiddebugbridge[.]su` in the binary | retired: the record now reads `one two seven . zero . zero . one` |
| DVR bot, July | `meower[.]eth`; Solana names `roanoke[.]sol`, `telnet[.]sol`; loader `deformed[.]su:9018`, `nvms9000[.]online` in the binary | 2026-07-17 `172[.]233[.]124[.]230`, `45[.]154[.]98[.]115`, telnet record `205[.]237[.]110[.]232`; since 2026-07-24 the records read `I took it down now im sorry` and `no more botnet` |
| Drunkasfk | `2busydrinkingcodeine[.]eth` (plain in the August builds, hidden later) | registered 2026-07-29; 157 updates 2026-07-30 to 2026-10-26; resolver cleared and the name transferred on 2026-10-27, so these bots no longer resolve |
| Kimwolf | `pawsatyou[.]eth`; in the binary `176[.]65[.]139[.]210`, `65[.]109[.]18[.]44`, `report[.]kimwolf[.]net` | the address record holds the owner's own wallet, which decodes to no real server |
| Vibenet | `fuckmepls[.]eth` | 2026-08-24 `201[.]7[.]23[.]8`, `.9`; 2026-09-01 adds `.254`, `.255`; 2026-09-15 `217[.]60[.]242[.]252`, `.253`; 2026-10-03 adds `.79`, `.80` |

All live names resolve through the ENS public resolver `0xF29100983E058b709F3D539b0c765937B804AC15`.

## Measured (2026-11-05)

| Set | Result |
|---|---|
| Malware corpus, text search for `"method":"eth_call"` over 457,428 files: 413 ELF | Named by a family rule: 357 (Boatnet 67, Akuma 28, Ouroboros 72, RC4 text record 17, proxy.ips 9, ip records 12, DVR bot March 32, DVR bot July 62, Drunkasfk 47, Kimwolf 11). All 413 matched `SUSP_ELF_EthCall_C2_Resolver`; 202 matched `SUSP_ELF_ENS_Registry_Lookup` |
| Same search, the 56 ELF matched by the heuristics only | 25 further files of the DVR bot's March cluster, most of them a later revision whose strings were not recovered; Rust bots (24); Vibenet (1); six others |
| Benign software set (49,633 files) | 0 matched, all twelve rules |
| Clean ELF: a benign software set (14,698) and a Debian system image (1,603) | 0 matched, all twelve rules |

Bazaar labels most of these samples Mirai, including Boatnet. UPX-packed copies match after unpacking only.

Reference samples:

- Boatnet: `de1733fa9e993bd7cd54e0e1998ef2024f593592cb6be7a370120ba6d625c796`
- Akuma: `15d10a6db45fd36d394efa01528a05706afb9021fcf7d5f97e1af205acd65199`
- Ouroboros: `6b4b3724c21b93a773823853c561d4da1b2d216879f30d40c20965cbef66f50e`
- RC4 text record: `15466df1a1f5d04f6e3b3a7628c2ddea263266acc7d28cb6c6217b595c2e42e4`, universal resolver form `9387db1c3801abb24e49d8a1cc7878dffb09588017d957be29a35720137c29ab`
- proxy.ips: `80faa91681af2522632deab56bb2200ec51f795f0b8d8d0506014d724a54b040`
- ip records: `3461b097ea026c9161113f0f590e75c47908cebd3d6a30de3b821c10a85ea9fc`
- DVR bot, March: `d6b7bb3baba4a7a97d0fab24faa2165ca4f658a87447761321c77b8cda841a97`
- DVR bot, July: `1de6220fc4c3502a55fa5cc220b9a91cead25fc34bc7d3610edf1914f83bc379`
- Drunkasfk: `369194a0cfbe5f3524dbe1f3f9726547cbe6bc62a266e8c07e3f14409c78a621`
- Kimwolf: `25418594755f57298e0f0c81a91205c28c0af91709af755e919d4b896ccce212`
- Vibenet: `5002282edb86e86fd7d7eedd8b3bd2444390eec0d18e93641d23c89cdba1f9ef`
