rule win_chinad_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-06-10"
        version = "1"
        description = "Detects win.chinad."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chinad"
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
        $sequence_0 = { 0bd0 c1e91c 8b8514fdffff 0bf1 8b8d38fdffff 89b530fdffff 8bf1 }
            // n = 7, score = 200
            //   0bd0                 | or                  edx, eax
            //   c1e91c               | shr                 ecx, 0x1c
            //   8b8514fdffff         | mov                 eax, dword ptr [ebp - 0x2ec]
            //   0bf1                 | or                  esi, ecx
            //   8b8d38fdffff         | mov                 ecx, dword ptr [ebp - 0x2c8]
            //   89b530fdffff         | mov                 dword ptr [ebp - 0x2d0], esi
            //   8bf1                 | mov                 esi, ecx

        $sequence_1 = { 894dc8 8b8d00fdffff 8bd9 0fa4c117 c1eb09 0bf9 c1e017 }
            // n = 7, score = 200
            //   894dc8               | mov                 dword ptr [ebp - 0x38], ecx
            //   8b8d00fdffff         | mov                 ecx, dword ptr [ebp - 0x300]
            //   8bd9                 | mov                 ebx, ecx
            //   0fa4c117             | shld                ecx, eax, 0x17
            //   c1eb09               | shr                 ebx, 9
            //   0bf9                 | or                  edi, ecx
            //   c1e017               | shl                 eax, 0x17

        $sequence_2 = { 33ff 898d2cfdffff 33d2 8b8d38fdffff 8bd9 0fa4c117 c1eb09 }
            // n = 7, score = 200
            //   33ff                 | xor                 edi, edi
            //   898d2cfdffff         | mov                 dword ptr [ebp - 0x2d4], ecx
            //   33d2                 | xor                 edx, edx
            //   8b8d38fdffff         | mov                 ecx, dword ptr [ebp - 0x2c8]
            //   8bd9                 | mov                 ebx, ecx
            //   0fa4c117             | shld                ecx, eax, 0x17
            //   c1eb09               | shr                 ebx, 9

        $sequence_3 = { e8???????? 83c404 e9???????? c745d4dc284300 b804000000 6bc800 8b55fc }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   e9????????           |                     
            //   c745d4dc284300       | mov                 dword ptr [ebp - 0x2c], 0x4328dc
            //   b804000000           | mov                 eax, 4
            //   6bc800               | imul                ecx, eax, 0
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_4 = { 8bf1 238d08fdffff 0bb508fdffff 8b9528fdffff 0b952cfdffff 23b510fdffff 239534fdffff }
            // n = 7, score = 200
            //   8bf1                 | mov                 esi, ecx
            //   238d08fdffff         | and                 ecx, dword ptr [ebp - 0x2f8]
            //   0bb508fdffff         | or                  esi, dword ptr [ebp - 0x2f8]
            //   8b9528fdffff         | mov                 edx, dword ptr [ebp - 0x2d8]
            //   0b952cfdffff         | or                  edx, dword ptr [ebp - 0x2d4]
            //   23b510fdffff         | and                 esi, dword ptr [ebp - 0x2f0]
            //   239534fdffff         | and                 edx, dword ptr [ebp - 0x2cc]

        $sequence_5 = { 83458801 807d9600 75ee 8b4d88 2b8d34ffffff 898d38ffffff 8b9538ffffff }
            // n = 7, score = 200
            //   83458801             | add                 dword ptr [ebp - 0x78], 1
            //   807d9600             | cmp                 byte ptr [ebp - 0x6a], 0
            //   75ee                 | jne                 0xfffffff0
            //   8b4d88               | mov                 ecx, dword ptr [ebp - 0x78]
            //   2b8d34ffffff         | sub                 ecx, dword ptr [ebp - 0xcc]
            //   898d38ffffff         | mov                 dword ptr [ebp - 0xc8], ecx
            //   8b9538ffffff         | mov                 edx, dword ptr [ebp - 0xc8]

        $sequence_6 = { 23de 8bf3 0bf0 8bc7 03f1 c1c007 8bcf }
            // n = 7, score = 200
            //   23de                 | and                 ebx, esi
            //   8bf3                 | mov                 esi, ebx
            //   0bf0                 | or                  esi, eax
            //   8bc7                 | mov                 eax, edi
            //   03f1                 | add                 esi, ecx
            //   c1c007               | rol                 eax, 7
            //   8bcf                 | mov                 ecx, edi

        $sequence_7 = { 8b85c0feffff 8bc8 c1c00a c1c90d 33c8 899dd4feffff 8b85c0feffff }
            // n = 7, score = 200
            //   8b85c0feffff         | mov                 eax, dword ptr [ebp - 0x140]
            //   8bc8                 | mov                 ecx, eax
            //   c1c00a               | rol                 eax, 0xa
            //   c1c90d               | ror                 ecx, 0xd
            //   33c8                 | xor                 ecx, eax
            //   899dd4feffff         | mov                 dword ptr [ebp - 0x12c], ebx
            //   8b85c0feffff         | mov                 eax, dword ptr [ebp - 0x140]

        $sequence_8 = { e8???????? ff75ec 0145f0 ff75f8 11550c ff7588 ff7580 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   0145f0               | add                 dword ptr [ebp - 0x10], eax
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   11550c               | adc                 dword ptr [ebp + 0xc], edx
            //   ff7588               | push                dword ptr [ebp - 0x78]
            //   ff7580               | push                dword ptr [ebp - 0x80]

        $sequence_9 = { 6a00 6800000080 e8???????? 50 ff15???????? 8945f4 }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   6800000080           | push                0x80000000
            //   e8????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax

    condition:
        7 of them and filesize < 598016
}