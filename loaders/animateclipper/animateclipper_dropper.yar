/*
   AnimateClipper delivery stage: 32-bit Go dropper
   Author: taogoldi
   TLP:WHITE

   The stage-1 loader rules in animateclipper.yar key on x86-64 instruction
   encodings that this dropper does not contain: it is a 32-bit Go binary and
   shares no code with the NativeAOT loader it delivers. It therefore needs
   its own coverage.
*/

import "pe"

rule AnimateClipper_GoDropper_SIRDCU
{
    meta:
        author      = "taogoldi"
        reference   = "https://taogoldi.github.io/reverse-engineer/blog/animateclipper-nativeaot-loader/"
        license     = "Apache-2.0"
        date        = "2026-08-28"
        version     = 1
        description = "AnimateClipper Go dropper, keyed on its unpublished module name"
        hash        = "43edee1eabae3c4ebd3bb2d21f6c24d0984b38f51dbeb74b425ccd53f2a71399"
        tlp         = "TLP:WHITE"
        fidelity    = "high"

    strings:
        // Go embeds the module path verbatim in the buildinfo blob. "SIRDCU"
        // is not a published module -- it exists only in this actor's source
        // tree -- and it survives a rebuild, unlike the randomised symbols.
        $mod_path  = "path\tSIRDCU"
        $mod_devel = "mod\tSIRDCU\t(devel)"
        // Anchors the match to the buildinfo structure rather than a chance
        // occurrence of the six letters elsewhere in the file.
        $buildinf  = "\xff Go buildinf:"

    condition:
        uint16(0) == 0x5A4D and
        $buildinf and
        any of ($mod_path, $mod_devel)
}

/*
   A second rule keyed on the dropper's garbled main-package symbols was
   written and rejected. Requiring eight or more long all-lowercase `main.*`
   symbols alongside GOARCH=386 / GOOS=windows / -trimpath, it matched the
   dropper -- and also 38 of 1,486 corpus samples (2.6%), nearly all of them
   lummastealer, acrstealer and amadey builds.

   That is not a tuning problem. Name mangling is a property of the build
   toolchain, which these families share, so the rule identifies the packer
   rather than the actor. Shipping it under an AnimateClipper name would
   attribute every garbled 32-bit Go stealer to this campaign.
*/
