class DGA:
    shortname = "dircrypt"
    yara = "dircrypt.yar"
    name = "DirCrypt ransomware"
    ref = ["http://johannesbader.ch/2015/03/the-dga-of-dircrypt/"]
    desc = "DirCrypt is an inactive Ransomware that uses a Domain Generation Algorithm (DGA) for its callback call."
    samples = 30
    lcg = "Similar to a LCG: n = 16807 * (n%127773) - 2836 * (n//127773) & 0xFFFFFFFF"
    use_date = False
    use_seed = "Integer hex number in text format (F2113C2A by default)"
    configs = [None]
    variation = "The entire domain except the TLD."
    regex = "[a-z]{8,20}"
    ends = ['.com']

    def __init__(self, date=None, seed="F2113C2A"):
        self.seed = int(seed, 16)
        self.nr = 30
        self.domain = None
        self.generator = None

    def rand_int_modulus(self, modulus):
        ix = self.seed
        ix = 16807 * (ix % 127773) - 2836 * (ix // 127773) & 0xFFFFFFFF
        self.seed = ix
        return ix % modulus

    def _dga(self):
        for i in range(self.nr):
            domain_len = self.rand_int_modulus(12 + 1) + 8
            self.domain = ""
            for i in range(domain_len):
                char = chr(ord('a') + self.rand_int_modulus(25 + 1))
                self.domain += char
            self.domain += ".com"
            yield self.domain

    def get_domain(self):
        if self.generator:
            next(self.generator)
        else:
            self.generator = self._dga()
            next(self.generator)
        return self.domain
