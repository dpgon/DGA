class DGA:
    shortname = "ramnit"
    yara = "ramnit.yar"
    name = "Ramnit malware"
    ref = ["https://johannesbader.ch/blog/the-dga-of-ramnit/",
           "https://nao-sec.org/2018/01/analyzing-ramnit-used-in-seamless.html",
           "https://blogs.akamai.com/2019/02/ramnit-in-the-uk.html"]
    desc = "Ramnit is a Zeus-like malware from 2010 used to spy on infected users."
    samples = 0
    lcg = "x = 16807*(x % 127773) - 2836*(x // 127773) & 0xFFFFFFFF"
    use_date = False
    use_seed = "A string with an hexadecimal number (16647BB4 by default)"
    configs = ['16647BB4', 'E7392D18', 'C129388E', 'E706B455', 'DC485593',
               'EF214BBF', '28488EEA', '4BFCBC6A', '79159C10', '92F4BE35',
               '4302C04A', '52278648', '9753029A', 'A6EAB21A', '46CF1B28',
               '1CCEC41C', '0C5787AE2', '0FCFFD9E9', '75EA95C2', '8A0AEC7D',
               '1DF640A8', '14DF29DD', '8222270B', '55536A85', '5C39E467',
               'D2B3C361', 'F318D47D', '231D9480', '13317EAC', '89547381',
               '6C36D41D']
    variation = "The entire domain except one of two TLDs."
    regex = "[a-y]{8,19}"
    ends = ['.com', '.eu']

    def __init__(self, date=None, seed='16647BB4'):
        self.seed = int(seed, 16)
        if self.seed == 0x4302C04A or self.seed == 0x9753029A:
            self.tlds = [".eu"]
        else:
            self.tlds = [".com"]
        self.domain = None
        self.nr = 0

    def rand_int_modulus(self, modulus):
        ix = self.seed
        ix = 16807 * (ix % 127773) - 2836 * (ix // 127773) & 0xFFFFFFFF
        self.seed = ix
        return ix % modulus

    def _dga(self):
        seed_a = self.seed
        domain_len = self.rand_int_modulus(12) + 8
        seed_b = self.seed
        self.domain = ""
        for j in range(domain_len):
            char = chr(ord('a') + self.rand_int_modulus(25))
            self.domain += char
        tld = self.tlds[self.nr % len(self.tlds)]
        self.domain += '.' if tld[0] != '.' else ''
        self.domain += tld
        m = seed_a * seed_b
        self.seed = (m + m // (2 ** 32)) % 2 ** 32
        self.nr += 1

    def get_domain(self):
        self._dga()
        return self.domain
