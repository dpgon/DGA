rule win_dnschanger_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-06-10"
        version = "1"
        description = "Detects win.dnschanger."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dnschanger"
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
        $sequence_0 = { c3 56 57 8b7c240c 85ff 741e }
            // n = 6, score = 100
            //   c3                   | ret                 
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7c240c             | mov                 edi, dword ptr [esp + 0xc]
            //   85ff                 | test                edi, edi
            //   741e                 | je                  0x20

        $sequence_1 = { 84c0 5f 750e e8???????? }
            // n = 4, score = 100
            //   84c0                 | test                al, al
            //   5f                   | pop                 edi
            //   750e                 | jne                 0x10
            //   e8????????           |                     

        $sequence_2 = { 8b7c2414 85db 7e21 8bf7 8d8604010000 }
            // n = 5, score = 100
            //   8b7c2414             | mov                 edi, dword ptr [esp + 0x14]
            //   85db                 | test                ebx, ebx
            //   7e21                 | jle                 0x23
            //   8bf7                 | mov                 esi, edi
            //   8d8604010000         | lea                 eax, dword ptr [esi + 0x104]

        $sequence_3 = { ffd6 8b4c2410 8d842414010000 57 }
            // n = 4, score = 100
            //   ffd6                 | call                esi
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   8d842414010000       | lea                 eax, dword ptr [esp + 0x114]
            //   57                   | push                edi

        $sequence_4 = { 53 55 8b2d???????? 56 57 6800020000 6a08 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   55                   | push                ebp
            //   8b2d????????         |                     
            //   56                   | push                esi
            //   57                   | push                edi
            //   6800020000           | push                0x200
            //   6a08                 | push                8

        $sequence_5 = { 6a30 50 57 ff15???????? 8bf0 85f6 750f }
            // n = 7, score = 100
            //   6a30                 | push                0x30
            //   50                   | push                eax
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   750f                 | jne                 0x11

        $sequence_6 = { c744241000000000 f3ab 8d442410 50 55 ff15???????? 85c0 }
            // n = 7, score = 100
            //   c744241000000000     | mov                 dword ptr [esp + 0x10], 0
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8d442410             | lea                 eax, dword ptr [esp + 0x10]
            //   50                   | push                eax
            //   55                   | push                ebp
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_7 = { aa 8d8594feffff 6800010000 50 }
            // n = 4, score = 100
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8d8594feffff         | lea                 eax, dword ptr [ebp - 0x16c]
            //   6800010000           | push                0x100
            //   50                   | push                eax

        $sequence_8 = { 83f86f 7521 85f6 740b 56 53 }
            // n = 6, score = 100
            //   83f86f               | cmp                 eax, 0x6f
            //   7521                 | jne                 0x23
            //   85f6                 | test                esi, esi
            //   740b                 | je                  0xd
            //   56                   | push                esi
            //   53                   | push                ebx

        $sequence_9 = { c3 8b44240c 8bc8 48 85c9 7429 }
            // n = 6, score = 100
            //   c3                   | ret                 
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   8bc8                 | mov                 ecx, eax
            //   48                   | dec                 eax
            //   85c9                 | test                ecx, ecx
            //   7429                 | je                  0x2b

    condition:
        7 of them and filesize < 49152
}