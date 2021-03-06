rule win_dircrypt_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-06-10"
        version = "1"
        description = "Detects win.dircrypt."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dircrypt"
        malpedia_rule_date = "20210604"
        malpedia_hash = "be09d5d71e77373c0f538068be31a2ad4c69cfbd"
        malpedia_version = "20210616"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 05d7070000 50 6a01 6a02 }
            // n = 4, score = 800
            //   05d7070000           | add                 eax, 0x7d7
            //   50                   | push                eax
            //   6a01                 | push                1
            //   6a02                 | push                2

        $sequence_1 = { 8bec 51 ff15???????? 8945fc 8b450c 2b4508 }
            // n = 6, score = 800
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   2b4508               | sub                 eax, dword ptr [ebp + 8]

        $sequence_2 = { 8d45dc 50 e8???????? 6a00 e8???????? }
            // n = 5, score = 800
            //   8d45dc               | lea                 eax, dword ptr [ebp - 0x24]
            //   50                   | push                eax
            //   e8????????           |                     
            //   6a00                 | push                0
            //   e8????????           |                     

        $sequence_3 = { c705????????01000000 e8???????? e8???????? e8???????? 833d????????00 7514 68???????? }
            // n = 7, score = 800
            //   c705????????01000000     |     
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   833d????????00       |                     
            //   7514                 | jne                 0x16
            //   68????????           |                     

        $sequence_4 = { e8???????? 05d5070000 50 6a01 6a02 }
            // n = 5, score = 800
            //   e8????????           |                     
            //   05d5070000           | add                 eax, 0x7d5
            //   50                   | push                eax
            //   6a01                 | push                1
            //   6a02                 | push                2

        $sequence_5 = { 68???????? e8???????? 05d2070000 50 e8???????? a3???????? }
            // n = 6, score = 800
            //   68????????           |                     
            //   e8????????           |                     
            //   05d2070000           | add                 eax, 0x7d2
            //   50                   | push                eax
            //   e8????????           |                     
            //   a3????????           |                     

        $sequence_6 = { c705????????01000000 e8???????? e8???????? e8???????? 833d????????00 7514 }
            // n = 6, score = 800
            //   c705????????01000000     |     
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   833d????????00       |                     
            //   7514                 | jne                 0x16

        $sequence_7 = { 833d????????00 7528 c705????????01000000 e8???????? e8???????? }
            // n = 5, score = 800
            //   833d????????00       |                     
            //   7528                 | jne                 0x2a
            //   c705????????01000000     |     
            //   e8????????           |                     
            //   e8????????           |                     

        $sequence_8 = { 68???????? ff15???????? 833d????????00 751a 68???????? e8???????? }
            // n = 6, score = 800
            //   68????????           |                     
            //   ff15????????         |                     
            //   833d????????00       |                     
            //   751a                 | jne                 0x1c
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_9 = { 7528 c705????????01000000 e8???????? e8???????? e8???????? e8???????? }
            // n = 6, score = 800
            //   7528                 | jne                 0x2a
            //   c705????????01000000     |     
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     

    condition:
        7 of them and filesize < 671744
}