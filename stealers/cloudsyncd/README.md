# CloudSyncD

Detection rules for CloudSyncD (Microsoft: CloudSyncD, Sophos: CldSync, ESET: OSX/PSW.Agent.KO), a macOS
password stealer and stager distributed as fake installers for Zoom, StreamYard and Snair.

The installer is a universal (x86_64 + arm64) Mach-O that shows its own "wants to make changes" password dialog
(`AuthDialog`), checks the password with `dscl -authonly`, saves it under `~/.config/<app>/`, strips the
quarantine and provenance attributes, and runs the stager it carries in `__TEXT,__const` without writing it to
disk (`/dev/fd`, then `sudo -S`, then an unlinked temporary file). The stager (`cloudsyncd`, signing identifier
`cshelper`) installs under `~/.local/share/cloudsync`, fingerprints the host and pulls ChaCha20-Poly1305
encrypted tasks, either a Mach-O or a `package.tar.gz`, from its server.

Both binaries hide their configuration and most strings with the `cloudsync_impl::sobf` obfuscator:

    out[i] = ct[i] ^ K[i & 31] ^ K[salt & 31] ^ ((salt * 0x83 + 0x11 * i) & 0xff)

## Rules

| Rule | Signal | Fidelity |
|---|---|---|
| `CloudSyncD_Sobf_Reveal` | The `sobf::reveal` decoder loop, x86_64 or arm64 instruction encodings. Does not depend on symbols | High |
| `CloudSyncD_Installer` | Universal binary with two decoders (its own and the embedded stager's), or the dialog classes plus the namespace | High |
| `CloudSyncD_Config_Symbols` | The `sobf` namespace plus the `_ct_APP_*` config constant names. Evaded by a stripped build | High |

## Validation (2026-11-01)

- All seven CloudSyncD files seen hit the rules: three installers and their three embedded stagers, plus a separately
  distributed stager. All three rules fire on every installer, and `Sobf_Reveal` and `Config_Symbols` fire on
  every stager.
- `Sobf_Reveal` still hits after the stager is run through `strip`.
- Zero hits on 2,588 other macOS malware samples (AMOS and its forks, Poseidon, and others).
- Zero hits on 776,126 benign files, and on 457,017 files from a macOS 26 system (`/usr`, `/System`,
  `/Applications`, Homebrew).

## IOCs

C2 servers decoded from the builds seen. They are encrypted in the binaries, so they are not YARA strings.

| Lure | C2 |
|---|---|
| StreamYard | `hxxps://bjzhishang[.]com/macos/jquery.js` |
| Snair | `hxxps://clampacks[.]com/macos/jquery.js` |
| Zoom | developer build, private address only |

| SHA-256 | Role |
|---|---|
| `524a7bcc8edcadc6f4381459f79769e1ec534aa78f66e5c38a6678bd55cf2572` | installer, Zoom lure |
| `cc54d90920a73cc5e176664f61c6f601c95d693e431e79ae1148cb91e83c9235` | installer, StreamYard lure |
| `8d13fb2cd4942e7757a3c409ff0efc9e299a1440d3953f8e2f3791c25879c9fd` | installer, Snair lure |
| `18f071ee32fa5210aaca10ff5310e8747152e3f842d70631b5233eeb7c62da8d` | stager (`cshelper`), Snair campaign |
