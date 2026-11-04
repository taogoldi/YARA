# Diicot (Mexals): shc-compiled installers and their scripts

`diicot_shc.yar` (2026-11-03), three rules.

Diicot, a Romanian cryptojacking group, ship their bash installers as shc-compiled x86-64 ELF files. shc keeps the
script RC4-encrypted in the binary, so the ELF rule and the script rules see different things:

| Rule | Matches |
|---|---|
| `Linux_Diicot_SHC_Wrapper` | The compiled ELF: shc runtime strings plus the RC4 key schedule as Diicot's build toolchain inlines it (static, -O2, `.comment` stripped) |
| `Linux_Diicot_Miner_Installer_Script` | The decrypted miner installer: fetches `.report_system` from a `/.puscarie/` path into `/var/tmp/.rcu_gp`, writes the `diicot` watchdog and cron persistence |
| `Linux_Diicot_SSH_Brute_Launcher_Script` | The decrypted SSH scan-and-brute launcher: `./ps <class> 22`, then `./brute ... bios.txt pass`, Romanian usage and error messages |

The wrapper rule is a build-cluster rule. It keys on how the shc runtime was compiled, not on the script, so an
unrelated shc build made with the same toolchain and options would also match. Recover the script with any shc
decoder to confirm. Other shc builds do not match: dynamic builds, static Ubuntu GCC 9.4 and Red Hat GCC 4.8 builds,
and a fresh Debian GCC 12 static -O2 build.

## Measured (2026-11-03)

| Set | Result |
|---|---|
| Diicot shc ELF builds | 7 of 7 matched by the wrapper rule |
| Decrypted Diicot scripts | 6 of 6 installers, 1 of 1 brute launcher |
| Other shc-compiled ELF files (19, other operators and benign tools) | 0 matched |
| Malware corpus: 185,984 ELF, 61,183 scripts, 35,176 unidentified files | 0 matched outside the samples above |
| Clean files: a 208 GB benign software set, 43,547 files of a Debian system image, a macOS host | 0 matched |

Indicators seen in the decrypted installers (defanged): `hxxp://66.63.187[.]200/.puscarie/.report_system`,
`hxxp://xkobeimparatu[.]net/.puscarie/.report_system`.

Reference samples:

- Wrapper (miner installer): `f6371d8b3bcc784017d4fbb544550873281cdc4aa4167ffac91526126d3b4e01`
- Wrapper (brute launcher): `90dc177f5b126f428c9b77c6187dc49ee1968a76988fb62191c80f1c0ee4d125`
- Decrypted installer: `2130bc318632f761c9d503b9731f2ed93690e7940462d1903bd88789a3222d0f`
- Decrypted brute launcher: `5d53373e8dcf5ab6f9ae2976b02c7d6907f07849507cd41e6db296a25c132882`
