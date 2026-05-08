// poolparty.yar, cross-variant detection for PoolParty thread-pool
// process injection. Covers SafeBreach's eight variants
// (TP_WORK, TP_TIMER, TP_WAIT, TP_IO, TP_ALPC, TP_JOB, TP_DIRECT, plus
//  worker-factory start-routine overwrite).
//
// Companion to docs/poolparty_blog_draft.md. See that post for the
// reverse-engineering work that motivates each detection path.
//
// Apache-2.0 licensed; PRs welcome at the parent repository.

rule PoolParty_ThreadPool_Injection
{
    meta:
        description    = "Detects SafeBreach-derived PoolParty thread-pool process injection patterns"
        author         = "tao-threatintel"
        date           = "2026-05-07"
        license        = "Apache-2.0"
        reference1     = "https://safebreach.com/blog/process-injection-using-windows-thread-pools/"
        reference2     = "https://i.blackhat.com/EU-23/Presentations/EU-23-Leviev-The-Pool-Party-You-Will-Never-Forget.pdf"
        reference3     = "https://github.com/SafeBreach-Labs/PoolParty"
        sample_a_sha256 = "24c141656d4a9f75513d167f0a4664a8bfe63ecd93e27b5e5b150b0e89b0e8b7"
        sample_b_sha256 = "4cfc8ee7f76a8c7aca96fa783a8d90e915fc1f720062a8241f0c2a0247a382c5"
        sample_c_sha256 = "849e64db81b5bebe1d0b6fb82dd66a1fd8bb4094a016beff6e501bcbbf36e72c"

    strings:
        // Path 1: documentary log strings (unstripped SafeBreach builds).
        $log_craft_direct  = "Crafted TP_DIRECT structure"                ascii wide
        $log_alloc_direct  = "Allocated TP_DIRECT memory in the target"   ascii wide
        $log_written_direct= "Written the TP_DIRECT structure"            ascii wide
        $log_queued_direct = "Queued a packet to the IO completion port"  ascii wide
        $log_craft_work    = "Crafted TP_WORK structure"                  ascii wide
        $log_alloc_work    = "Allocated TP_WORK memory in the target"     ascii wide
        $log_craft_alpc    = "Crafted TP_ALPC structure"                  ascii wide
        $log_craft_job     = "Crafted TP_JOB structure"                   ascii wide
        $log_worker_factory= "worker factory of the target process"       ascii wide

        // Path 2: API-name strings used in dynamic resolution.
        $api_zwsetio       = "ZwSetIoCompletion"               ascii fullword
        $api_zwawcp        = "ZwAssociateWaitCompletionPacket" ascii fullword
        $api_tpaac         = "TpAllocAlpcCompletion"           ascii fullword
        $api_tpajn         = "TpAllocJobNotification"          ascii fullword
        $api_ntsiwf        = "NtSetInformationWorkerFactory"   ascii fullword
        $api_ntqiwf        = "NtQueryInformationWorkerFactory" ascii fullword

        // Path 3: explicit self-name (catches Sample A and similar small droppers).
        $self_poolparty    = "PoolParty" ascii nocase

        // Path 4: structural, strlen+lea std::string construction pattern.
        //         mov r8d, IMM (= strlen) + lea rdx, [rip+OFF].
        $strlen_lea_zwsetio   = { 41 B8 11 00 00 00 48 8D 15 ?? ?? ?? ?? }
        $strlen_lea_tpaac     = { 41 B8 15 00 00 00 48 8D 15 ?? ?? ?? ?? }
        $strlen_lea_tpajn     = { 41 B8 16 00 00 00 48 8D 15 ?? ?? ?? ?? }
        $strlen_lea_zwawcp    = { 41 B8 1F 00 00 00 48 8D 15 ?? ?? ?? ?? }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 16MB
        and (
            2 of ($log_*) or

            ($api_zwsetio and 2 of ($api_zwawcp, $api_tpaac, $api_tpajn,
                                    $api_ntsiwf, $api_ntqiwf)) or

            ($self_poolparty and 1 of ($api_zwsetio, $api_zwawcp, $api_tpaac,
                                       $api_tpajn, $api_ntsiwf, $api_ntqiwf)) or

            2 of ($strlen_lea_*)
        )
}
