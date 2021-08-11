rule win_zloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-06-10"
        version = "1"
        description = "Detects win.zloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zloader"
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
        $sequence_0 = { 56 ff7510 ff750c ff7508 e8???????? 83c414 89f1 }
            // n = 7, score = 1800
            //   56                   | push                esi
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   89f1                 | mov                 ecx, esi

        $sequence_1 = { 31db 89d8 83c40c 5e 5b }
            // n = 5, score = 1800
            //   31db                 | xor                 ebx, ebx
            //   89d8                 | mov                 eax, ebx
            //   83c40c               | add                 esp, 0xc
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_2 = { 57 e8???????? 83c408 47 a801 }
            // n = 5, score = 1800
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   47                   | inc                 edi
            //   a801                 | test                al, 1

        $sequence_3 = { 0fb7c0 57 50 53 e8???????? 83c40c 89f1 }
            // n = 7, score = 1800
            //   0fb7c0               | movzx               eax, ax
            //   57                   | push                edi
            //   50                   | push                eax
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   89f1                 | mov                 ecx, esi

        $sequence_4 = { 53 57 56 e8???????? 81c410010000 5e 5f }
            // n = 7, score = 1800
            //   53                   | push                ebx
            //   57                   | push                edi
            //   56                   | push                esi
            //   e8????????           |                     
            //   81c410010000         | add                 esp, 0x110
            //   5e                   | pop                 esi
            //   5f                   | pop                 edi

        $sequence_5 = { 0fb7450c 8d9df0feffff 53 50 ff7508 }
            // n = 5, score = 1800
            //   0fb7450c             | movzx               eax, word ptr [ebp + 0xc]
            //   8d9df0feffff         | lea                 ebx, dword ptr [ebp - 0x110]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_6 = { 56 e8???????? 83c404 8d4de8 68???????? }
            // n = 5, score = 1800
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8d4de8               | lea                 ecx, dword ptr [ebp - 0x18]
            //   68????????           |                     

        $sequence_7 = { 31db 8d8df0feffff e8???????? 89d8 }
            // n = 4, score = 1800
            //   31db                 | xor                 ebx, ebx
            //   8d8df0feffff         | lea                 ecx, dword ptr [ebp - 0x110]
            //   e8????????           |                     
            //   89d8                 | mov                 eax, ebx

        $sequence_8 = { 56 50 a1???????? 89c1 }
            // n = 4, score = 1300
            //   56                   | push                esi
            //   50                   | push                eax
            //   a1????????           |                     
            //   89c1                 | mov                 ecx, eax

        $sequence_9 = { 53 57 56 50 8b4510 31db }
            // n = 6, score = 700
            //   53                   | push                ebx
            //   57                   | push                edi
            //   56                   | push                esi
            //   50                   | push                eax
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   31db                 | xor                 ebx, ebx

        $sequence_10 = { 7432 68???????? ff742408 e8???????? 59 59 84c0 }
            // n = 7, score = 600
            //   7432                 | je                  0x34
            //   68????????           |                     
            //   ff742408             | push                dword ptr [esp + 8]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   84c0                 | test                al, al

        $sequence_11 = { 8bc3 5b c3 8b44240c 83f8ff 750a ff742408 }
            // n = 7, score = 600
            //   8bc3                 | mov                 eax, ebx
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   83f8ff               | cmp                 eax, -1
            //   750a                 | jne                 0xc
            //   ff742408             | push                dword ptr [esp + 8]

        $sequence_12 = { c6043000 5e c3 56 57 8b7c2414 83ffff }
            // n = 7, score = 600
            //   c6043000             | mov                 byte ptr [eax + esi], 0
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7c2414             | mov                 edi, dword ptr [esp + 0x14]
            //   83ffff               | cmp                 edi, -1

        $sequence_13 = { 50 56 56 56 ff7514 }
            // n = 5, score = 600
            //   50                   | push                eax
            //   56                   | push                esi
            //   56                   | push                esi
            //   56                   | push                esi
            //   ff7514               | push                dword ptr [ebp + 0x14]

        $sequence_14 = { ff742404 e8???????? 59 84c0 7432 68???????? ff742408 }
            // n = 7, score = 600
            //   ff742404             | push                dword ptr [esp + 4]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   84c0                 | test                al, al
            //   7432                 | je                  0x34
            //   68????????           |                     
            //   ff742408             | push                dword ptr [esp + 8]

        $sequence_15 = { 6aff 50 e8???????? 8d857cffffff 50 }
            // n = 5, score = 500
            //   6aff                 | push                -1
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d857cffffff         | lea                 eax, dword ptr [ebp - 0x84]
            //   50                   | push                eax

        $sequence_16 = { 50 89542444 e8???????? 03c0 }
            // n = 4, score = 500
            //   50                   | push                eax
            //   89542444             | mov                 dword ptr [esp + 0x44], edx
            //   e8????????           |                     
            //   03c0                 | add                 eax, eax

        $sequence_17 = { 83c408 5e 5d c3 55 89e5 57 }
            // n = 7, score = 500
            //   83c408               | add                 esp, 8
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   57                   | push                edi

        $sequence_18 = { 55 89e5 53 57 56 81eca8020000 }
            // n = 6, score = 500
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   53                   | push                ebx
            //   57                   | push                edi
            //   56                   | push                esi
            //   81eca8020000         | sub                 esp, 0x2a8

        $sequence_19 = { c7462401000000 c7462800004001 e8???????? 89460c }
            // n = 4, score = 500
            //   c7462401000000       | mov                 dword ptr [esi + 0x24], 1
            //   c7462800004001       | mov                 dword ptr [esi + 0x28], 0x1400000
            //   e8????????           |                     
            //   89460c               | mov                 dword ptr [esi + 0xc], eax

        $sequence_20 = { e8???????? 03c0 6689442438 8b442438 83c002 }
            // n = 5, score = 500
            //   e8????????           |                     
            //   03c0                 | add                 eax, eax
            //   6689442438           | mov                 word ptr [esp + 0x38], ax
            //   8b442438             | mov                 eax, dword ptr [esp + 0x38]
            //   83c002               | add                 eax, 2

        $sequence_21 = { 81c4a8020000 5e 5f 5b }
            // n = 4, score = 500
            //   81c4a8020000         | add                 esp, 0x2a8
            //   5e                   | pop                 esi
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx

        $sequence_22 = { 52 50 8d44243c 99 52 50 }
            // n = 6, score = 500
            //   52                   | push                edx
            //   50                   | push                eax
            //   8d44243c             | lea                 eax, dword ptr [esp + 0x3c]
            //   99                   | cdq                 
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_23 = { e8???????? 83c414 c3 56 ff742410 }
            // n = 5, score = 500
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   c3                   | ret                 
            //   56                   | push                esi
            //   ff742410             | push                dword ptr [esp + 0x10]

        $sequence_24 = { 0bc5 0f848c000000 8d442418 99 }
            // n = 4, score = 400
            //   0bc5                 | or                  eax, ebp
            //   0f848c000000         | je                  0x92
            //   8d442418             | lea                 eax, dword ptr [esp + 0x18]
            //   99                   | cdq                 

        $sequence_25 = { 0bc3 a3???????? e8???????? 8bc8 eb06 8b0d???????? 85c9 }
            // n = 7, score = 400
            //   0bc3                 | or                  eax, ebx
            //   a3????????           |                     
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax
            //   eb06                 | jmp                 8
            //   8b0d????????         |                     
            //   85c9                 | test                ecx, ecx

        $sequence_26 = { 5d c3 51 64a130000000 }
            // n = 4, score = 400
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   51                   | push                ecx
            //   64a130000000         | mov                 eax, dword ptr fs:[0x30]

        $sequence_27 = { 56 83ec18 89d6 89cf }
            // n = 4, score = 400
            //   56                   | push                esi
            //   83ec18               | sub                 esp, 0x18
            //   89d6                 | mov                 esi, edx
            //   89cf                 | mov                 edi, ecx

        $sequence_28 = { 8b842430010000 8b842430010000 890424 c74424041c010000 e8???????? c74424101c010000 893424 }
            // n = 7, score = 400
            //   8b842430010000       | mov                 eax, dword ptr [esp + 0x130]
            //   8b842430010000       | mov                 eax, dword ptr [esp + 0x130]
            //   890424               | mov                 dword ptr [esp], eax
            //   c74424041c010000     | mov                 dword ptr [esp + 4], 0x11c
            //   e8????????           |                     
            //   c74424101c010000     | mov                 dword ptr [esp + 0x10], 0x11c
            //   893424               | mov                 dword ptr [esp], esi

        $sequence_29 = { 50 6a72 e8???????? 59 }
            // n = 4, score = 300
            //   50                   | push                eax
            //   6a72                 | push                0x72
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_30 = { 5b c3 8bc2 ebf7 8d442410 50 }
            // n = 6, score = 300
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   8bc2                 | mov                 eax, edx
            //   ebf7                 | jmp                 0xfffffff9
            //   8d442410             | lea                 eax, dword ptr [esp + 0x10]
            //   50                   | push                eax

        $sequence_31 = { 56 8b742408 6804010000 68???????? }
            // n = 4, score = 300
            //   56                   | push                esi
            //   8b742408             | mov                 esi, dword ptr [esp + 8]
            //   6804010000           | push                0x104
            //   68????????           |                     

        $sequence_32 = { 56 68???????? ff742410 e8???????? 6823af2930 56 ff742410 }
            // n = 7, score = 300
            //   56                   | push                esi
            //   68????????           |                     
            //   ff742410             | push                dword ptr [esp + 0x10]
            //   e8????????           |                     
            //   6823af2930           | push                0x3029af23
            //   56                   | push                esi
            //   ff742410             | push                dword ptr [esp + 0x10]

        $sequence_33 = { ebf7 8d442410 50 ff742410 ff742410 ff742410 }
            // n = 6, score = 300
            //   ebf7                 | jmp                 0xfffffff9
            //   8d442410             | lea                 eax, dword ptr [esp + 0x10]
            //   50                   | push                eax
            //   ff742410             | push                dword ptr [esp + 0x10]
            //   ff742410             | push                dword ptr [esp + 0x10]
            //   ff742410             | push                dword ptr [esp + 0x10]

        $sequence_34 = { c3 8bc2 ebf8 53 }
            // n = 4, score = 300
            //   c3                   | ret                 
            //   8bc2                 | mov                 eax, edx
            //   ebf8                 | jmp                 0xfffffffa
            //   53                   | push                ebx

        $sequence_35 = { 8d8578fdffff 50 68???????? 6804010000 }
            // n = 4, score = 300
            //   8d8578fdffff         | lea                 eax, dword ptr [ebp - 0x288]
            //   50                   | push                eax
            //   68????????           |                     
            //   6804010000           | push                0x104

        $sequence_36 = { ebf8 53 8b5c240c 55 33ed }
            // n = 5, score = 300
            //   ebf8                 | jmp                 0xfffffffa
            //   53                   | push                ebx
            //   8b5c240c             | mov                 ebx, dword ptr [esp + 0xc]
            //   55                   | push                ebp
            //   33ed                 | xor                 ebp, ebp

        $sequence_37 = { 33f6 e8???????? ff7508 8d85f0fdffff 68???????? 6804010000 }
            // n = 6, score = 300
            //   33f6                 | xor                 esi, esi
            //   e8????????           |                     
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8d85f0fdffff         | lea                 eax, dword ptr [ebp - 0x210]
            //   68????????           |                     
            //   6804010000           | push                0x104

        $sequence_38 = { 56 57 ff750c 33db 68???????? }
            // n = 5, score = 300
            //   56                   | push                esi
            //   57                   | push                edi
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   33db                 | xor                 ebx, ebx
            //   68????????           |                     

        $sequence_39 = { 50 e8???????? 68???????? 56 e8???????? 8bf0 59 }
            // n = 7, score = 300
            //   50                   | push                eax
            //   e8????????           |                     
            //   68????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   59                   | pop                 ecx

    condition:
        7 of them and filesize < 1105920
}