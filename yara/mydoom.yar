rule win_mydoom_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-06-10"
        version = "1"
        description = "Detects win.mydoom."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mydoom"
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
        $sequence_0 = { 8945ec 0fb705???????? 668945f0 0fb605???????? 8845f2 }
            // n = 5, score = 100
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   0fb705????????       |                     
            //   668945f0             | mov                 word ptr [ebp - 0x10], ax
            //   0fb605????????       |                     
            //   8845f2               | mov                 byte ptr [ebp - 0xe], al

        $sequence_1 = { ba00000000 85c0 0f8434020000 803b05 }
            // n = 4, score = 100
            //   ba00000000           | mov                 edx, 0
            //   85c0                 | test                eax, eax
            //   0f8434020000         | je                  0x23a
            //   803b05               | cmp                 byte ptr [ebx], 5

        $sequence_2 = { 01c0 29c6 0fb6442eb8 884707 e8???????? 89c6 }
            // n = 6, score = 100
            //   01c0                 | add                 eax, eax
            //   29c6                 | sub                 esi, eax
            //   0fb6442eb8           | movzx               eax, byte ptr [esi + ebp - 0x48]
            //   884707               | mov                 byte ptr [edi + 7], al
            //   e8????????           |                     
            //   89c6                 | mov                 esi, eax

        $sequence_3 = { 891c24 e8???????? c744240c14000000 c7442408???????? c7442404???????? 891c24 e8???????? }
            // n = 7, score = 100
            //   891c24               | mov                 dword ptr [esp], ebx
            //   e8????????           |                     
            //   c744240c14000000     | mov                 dword ptr [esp + 0xc], 0x14
            //   c7442408????????     |                     
            //   c7442404????????     |                     
            //   891c24               | mov                 dword ptr [esp], ebx
            //   e8????????           |                     

        $sequence_4 = { 8d85e0feffff 8944240c 8d85dffeffff 89442408 89742404 891c24 e8???????? }
            // n = 7, score = 100
            //   8d85e0feffff         | lea                 eax, dword ptr [ebp - 0x120]
            //   8944240c             | mov                 dword ptr [esp + 0xc], eax
            //   8d85dffeffff         | lea                 eax, dword ptr [ebp - 0x121]
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   89742404             | mov                 dword ptr [esp + 4], esi
            //   891c24               | mov                 dword ptr [esp], ebx
            //   e8????????           |                     

        $sequence_5 = { 890424 e8???????? 8d9d38feffff 8db5b8feffff c7042400530700 e8???????? }
            // n = 6, score = 100
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   8d9d38feffff         | lea                 ebx, dword ptr [ebp - 0x1c8]
            //   8db5b8feffff         | lea                 esi, dword ptr [ebp - 0x148]
            //   c7042400530700       | mov                 dword ptr [esp], 0x75300
            //   e8????????           |                     

        $sequence_6 = { e8???????? 83ec0c 83f8ff 7535 8d45e6 89442410 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83ec0c               | sub                 esp, 0xc
            //   83f8ff               | cmp                 eax, -1
            //   7535                 | jne                 0x37
            //   8d45e6               | lea                 eax, dword ptr [ebp - 0x1a]
            //   89442410             | mov                 dword ptr [esp + 0x10], eax

        $sequence_7 = { e8???????? 8806 46 803b00 75ec }
            // n = 5, score = 100
            //   e8????????           |                     
            //   8806                 | mov                 byte ptr [esi], al
            //   46                   | inc                 esi
            //   803b00               | cmp                 byte ptr [ebx], 0
            //   75ec                 | jne                 0xffffffee

        $sequence_8 = { 83ec08 ba00000000 85c0 0f85a1010000 c744240800000000 c744240401000000 c7042402000000 }
            // n = 7, score = 100
            //   83ec08               | sub                 esp, 8
            //   ba00000000           | mov                 edx, 0
            //   85c0                 | test                eax, eax
            //   0f85a1010000         | jne                 0x1a7
            //   c744240800000000     | mov                 dword ptr [esp + 8], 0
            //   c744240401000000     | mov                 dword ptr [esp + 4], 1
            //   c7042402000000       | mov                 dword ptr [esp], 2

        $sequence_9 = { 85d0 7547 85f6 750c 8b0d???????? 85c9 7546 }
            // n = 7, score = 100
            //   85d0                 | test                eax, edx
            //   7547                 | jne                 0x49
            //   85f6                 | test                esi, esi
            //   750c                 | jne                 0xe
            //   8b0d????????         |                     
            //   85c9                 | test                ecx, ecx
            //   7546                 | jne                 0x48

    condition:
        7 of them and filesize < 114688
}