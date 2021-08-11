rule win_gozi_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-06-10"
        version = "1"
        description = "Detects win.gozi."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gozi"
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
        $sequence_0 = { ffd6 8945d8 83f8ff 0f8448ffffff c745b801000000 }
            // n = 5, score = 100
            //   ffd6                 | call                esi
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   83f8ff               | cmp                 eax, -1
            //   0f8448ffffff         | je                  0xffffff4e
            //   c745b801000000       | mov                 dword ptr [ebp - 0x48], 1

        $sequence_1 = { ff75f4 e8???????? ff75e0 e8???????? ff75f4 }
            // n = 5, score = 100
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   ff75e0               | push                dword ptr [ebp - 0x20]
            //   e8????????           |                     
            //   ff75f4               | push                dword ptr [ebp - 0xc]

        $sequence_2 = { 96 3b5375 60 d3e0 90 48 9e }
            // n = 7, score = 100
            //   96                   | xchg                eax, esi
            //   3b5375               | cmp                 edx, dword ptr [ebx + 0x75]
            //   60                   | pushal              
            //   d3e0                 | shl                 eax, cl
            //   90                   | nop                 
            //   48                   | dec                 eax
            //   9e                   | sahf                

        $sequence_3 = { f4 16 ee 7f7b }
            // n = 4, score = 100
            //   f4                   | hlt                 
            //   16                   | push                ss
            //   ee                   | out                 dx, al
            //   7f7b                 | jg                  0x7d

        $sequence_4 = { 92 6a00 8d45ec 50 52 68???????? }
            // n = 6, score = 100
            //   92                   | xchg                eax, edx
            //   6a00                 | push                0
            //   8d45ec               | lea                 eax, dword ptr [ebp - 0x14]
            //   50                   | push                eax
            //   52                   | push                edx
            //   68????????           |                     

        $sequence_5 = { e022 3a56b9 036890 2b02 9a102a6715fb53 31db b0a6 }
            // n = 7, score = 100
            //   e022                 | loopne              0x24
            //   3a56b9               | cmp                 dl, byte ptr [esi - 0x47]
            //   036890               | add                 ebp, dword ptr [eax - 0x70]
            //   2b02                 | sub                 eax, dword ptr [edx]
            //   9a102a6715fb53       | lcall               0x53fb:0x15672a10
            //   31db                 | xor                 ebx, ebx
            //   b0a6                 | mov                 al, 0xa6

        $sequence_6 = { 53 8d9f42050000 8903 5b e8???????? }
            // n = 5, score = 100
            //   53                   | push                ebx
            //   8d9f42050000         | lea                 ebx, dword ptr [edi + 0x542]
            //   8903                 | mov                 dword ptr [ebx], eax
            //   5b                   | pop                 ebx
            //   e8????????           |                     

        $sequence_7 = { d6 b6c6 e8???????? 6af4 dbe9 68912b4384 }
            // n = 6, score = 100
            //   d6                   | salc                
            //   b6c6                 | mov                 dh, 0xc6
            //   e8????????           |                     
            //   6af4                 | push                -0xc
            //   dbe9                 | fucomi              st(1)
            //   68912b4384           | push                0x84432b91

        $sequence_8 = { 68912b4384 2383e08985e4 0572b6e2f4 fd 4e 128b42926614 }
            // n = 6, score = 100
            //   68912b4384           | push                0x84432b91
            //   2383e08985e4         | and                 eax, dword ptr [ebx - 0x1b7a7620]
            //   0572b6e2f4           | add                 eax, 0xf4e2b672
            //   fd                   | std                 
            //   4e                   | dec                 esi
            //   128b42926614         | adc                 cl, byte ptr [ebx + 0x14669242]

        $sequence_9 = { 751d 399d40f4ffff 750d ff15???????? 3de5030000 74a8 }
            // n = 6, score = 100
            //   751d                 | jne                 0x1f
            //   399d40f4ffff         | cmp                 dword ptr [ebp - 0xbc0], ebx
            //   750d                 | jne                 0xf
            //   ff15????????         |                     
            //   3de5030000           | cmp                 eax, 0x3e5
            //   74a8                 | je                  0xffffffaa

        $sequence_10 = { 7415 57 57 53 8b7dfc e8???????? }
            // n = 6, score = 100
            //   7415                 | je                  0x17
            //   57                   | push                edi
            //   57                   | push                edi
            //   53                   | push                ebx
            //   8b7dfc               | mov                 edi, dword ptr [ebp - 4]
            //   e8????????           |                     

        $sequence_11 = { 74f5 55 68???????? e8???????? }
            // n = 4, score = 100
            //   74f5                 | je                  0xfffffff7
            //   55                   | push                ebp
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_12 = { ff7508 e8???????? c745f400100000 8d45f4 50 }
            // n = 5, score = 100
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   c745f400100000       | mov                 dword ptr [ebp - 0xc], 0x1000
            //   8d45f4               | lea                 eax, dword ptr [ebp - 0xc]
            //   50                   | push                eax

        $sequence_13 = { 83c4f4 8d45fc 50 6a01 6a00 }
            // n = 5, score = 100
            //   83c4f4               | add                 esp, -0xc
            //   8d45fc               | lea                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax
            //   6a01                 | push                1
            //   6a00                 | push                0

        $sequence_14 = { 8d8570ffffff 50 e8???????? 898574ffffff 57 8bbd70ffffff 57 }
            // n = 7, score = 100
            //   8d8570ffffff         | lea                 eax, dword ptr [ebp - 0x90]
            //   50                   | push                eax
            //   e8????????           |                     
            //   898574ffffff         | mov                 dword ptr [ebp - 0x8c], eax
            //   57                   | push                edi
            //   8bbd70ffffff         | mov                 edi, dword ptr [ebp - 0x90]
            //   57                   | push                edi

        $sequence_15 = { 741e 8d85b8fcffff 50 e8???????? }
            // n = 4, score = 100
            //   741e                 | je                  0x20
            //   8d85b8fcffff         | lea                 eax, dword ptr [ebp - 0x348]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_16 = { 0c73 0e 96 3b5375 }
            // n = 4, score = 100
            //   0c73                 | or                  al, 0x73
            //   0e                   | push                cs
            //   96                   | xchg                eax, esi
            //   3b5375               | cmp                 edx, dword ptr [ebx + 0x75]

        $sequence_17 = { 57 8911 7e25 8b7508 8a06 3c0a 7414 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   8911                 | mov                 dword ptr [ecx], edx
            //   7e25                 | jle                 0x27
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8a06                 | mov                 al, byte ptr [esi]
            //   3c0a                 | cmp                 al, 0xa
            //   7414                 | je                  0x16

        $sequence_18 = { 57 e8???????? c70728000000 56 e8???????? }
            // n = 5, score = 100
            //   57                   | push                edi
            //   e8????????           |                     
            //   c70728000000         | mov                 dword ptr [edi], 0x28
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_19 = { e8???????? 83c40c 8975fc 8d85bcfdffff 50 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   8d85bcfdffff         | lea                 eax, dword ptr [ebp - 0x244]
            //   50                   | push                eax

        $sequence_20 = { 6878330000 6a00 ff33 8d8746020000 }
            // n = 4, score = 100
            //   6878330000           | push                0x3378
            //   6a00                 | push                0
            //   ff33                 | push                dword ptr [ebx]
            //   8d8746020000         | lea                 eax, dword ptr [edi + 0x246]

        $sequence_21 = { 4a 51 d2b8c512294e 8c8873cd58c8 17 }
            // n = 5, score = 100
            //   4a                   | dec                 edx
            //   51                   | push                ecx
            //   d2b8c512294e         | sar                 byte ptr [eax + 0x4e2912c5], cl
            //   8c8873cd58c8         | mov                 word ptr [eax - 0x37a7328d], cs
            //   17                   | pop                 ss

        $sequence_22 = { 7524 ff7518 ff7514 8d45f8 50 6a00 }
            // n = 6, score = 100
            //   7524                 | jne                 0x26
            //   ff7518               | push                dword ptr [ebp + 0x18]
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   8d45f8               | lea                 eax, dword ptr [ebp - 8]
            //   50                   | push                eax
            //   6a00                 | push                0

        $sequence_23 = { f79bfe7ca80d a7 ad b710 2dc7ce5bbb d6 }
            // n = 6, score = 100
            //   f79bfe7ca80d         | neg                 dword ptr [ebx + 0xda87cfe]
            //   a7                   | cmpsd               dword ptr [esi], dword ptr es:[edi]
            //   ad                   | lodsd               eax, dword ptr [esi]
            //   b710                 | mov                 bh, 0x10
            //   2dc7ce5bbb           | sub                 eax, 0xbb5bcec7
            //   d6                   | salc                

    condition:
        7 of them and filesize < 237568
}