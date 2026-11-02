# AnimateClipper and the Moonshine loader

Detection rules for the loader first analysed as the AnimateClipper stage 1,
and for the AnimateClipper Go dropper.

**The loader is Moonshine, a crypter, not part of AnimateClipper.** Its builds
name it: the PDB path `F:\Projects\Moonshine-Csharp\out\native\aethsync.pdb`,
the stub `MoonshineStub.exe` and the module `Moonshine.Core.dll`. The same
loader carries AnimateClipper, XWorm, PhantomStealer, Formbook and
NeedleStealer, so in November 2026 its rules were renamed from
`AnimateClipper_*` to `Moonshine_Loader_*`. A match names the loader, not the
payload inside it.

The loader is a .NET NativeAOT binary: C# compiled ahead of time to native
x86-64, with no CLR header and no IL, so managed decompilers and CLR-header-gated
.NET detectors report nothing on it. It encrypts its API name table with a
hand-rolled keystream cipher, bypasses UAC through the CMSTPLUA elevation
moniker, copies itself into Startup, and hollows a signed Microsoft binary with
a payload carried inside the file.

Full analysis: <https://taogoldi.github.io/reverse-engineer/blog/animateclipper-nativeaot-loader/>

## Rules

| File | Rule | Signal | Fidelity |
|---|---|---|---|
| `animateclipper.yar` | `Moonshine_Loader_StringDecryptor_Constants` (was `AnimateClipper_StringDecryptor_Constants`) | Full instruction encodings of the keystream key schedule | Medium |
| `animateclipper.yar` | `Moonshine_Loader_GfxSection` (was `AnimateClipper_Loader_GfxSection`) | A high-entropy `.gfx` section plus NativeAOT markers, or the `aethsync` module name, or the `Moonshine-Csharp` build path | Medium |
| `animateclipper.yar` | `Moonshine_Loader_Composite` (was `AnimateClipper_Composite`) | Constants gated on NativeAOT markers and the `aethsync` / `Moonshine.Core` identity, x64 only | High |
| `animateclipper.yar` | `Moonshine_Loader_PayloadContainer` (was `AnimateClipper_PayloadContainer`) | Overlay stage-2 container: magic plus a self-consistent length plus high entropy | Medium |
| `animateclipper.yar` | `XorRamp_Overlay_Inflation` | Whole megabytes of one repeating 4-byte pattern `x, x^1, x^2, x^3` appended to the file | Medium |
| `animateclipper_dropper.yar` | `AnimateClipper_GoDropper_SIRDCU` | The dropper's unpublished Go module name inside its buildinfo blob | High |

## Operational guidance

Hunt with the constants rule, block with the composite.

Two of the three cipher constants are common. Across 2,000 unrelated PE files
`0x9E3779B9` (golden ratio, used by TEA, XXTEA and `boost::hash_combine`)
appears in 9.65%, and `0x6C078965` (the MT19937 init multiplier, present in any
binary statically linking `std::mt19937`) in 4.95%. All three together appear in
0.20%, and one of those four files is a genuine false positive. The rules match
full instruction encodings rather than bare four-byte values to cut that down,
and `AnimateClipper_Composite` gates the constants on NativeAOT markers, which
rejects the confirmed false positive outright.

Across 2,977 unrelated corpus samples, 900 of them Go binaries chosen to attack
the dropper rule, the whole set produced no false positives. With no events in
2,977 trials the one-sided 95% upper bound on the rate is about 0.10%.

`AnimateClipper_PayloadContainer` exists because builds from April and May 2026
append the encrypted stage 2 to the file instead of parking it in a `.gfx`
section, so the section-based rule structurally cannot see them. A four-byte
magic is far too short to match on alone, so the rule requires the length field
to describe exactly the bytes remaining in the file.

## Coverage

November 2026 review, against a platform corpus of about 66,000 labelled and
random samples:

- 17 of 18 known builds match at least one rule. The keystream builds (11)
  match the constants and composite rules. Three later `.gfx` builds carry no
  keystream constants and no NativeAOT metadata, only `aethsync.exe` and in one
  case the `Moonshine-Csharp` PDB path; `Moonshine_Loader_GfxSection` v2 now
  takes those.
- `XorRamp_Overlay_Inflation` covers five of the Moonshine builds and three NativeAOT
  builds filed as AnimateClipper that carry no Moonshine identity at all. The
  overlay is the only thing they share with the Moonshine builds, so the rule
  names the inflation step, not a family.
- The one AnimateClipper sample nothing matches is the clipboard hijacker
  itself (it imports `GetClipboardData` / `SetClipboardData`); there is no
  payload rule yet.

The original coverage note, from the August analysis:

Nine of nine known loader builds match, including three earlier builds recovered
from an internal collection where they were filed as AgentTesla, SnakeKeylogger
and Formbook. The Go dropper matches only its own rule, correctly: it shares no
code with the loader.

`aethsync` is not invariant across builds; `Moonshine.Core` is present in all
nine. The composite rule requires `1 of` the two, which is the only reason it
catches the earliest build.

## Verify

```bash
yara -w animateclipper.yar /path/to/sample
yara -w -r . /path/to/corpus/
```
