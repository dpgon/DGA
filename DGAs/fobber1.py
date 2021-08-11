class DGA:
    shortname = "fobber1"
    yara = "fobber.yar"
    name = "Fobber v1 banking trojan"
    ref = ["https://www.govcert.ch/blog/analysing-a-new-ebanking-trojan-called-fobber/",
           "https://blog.wizche.ch/fobber/malware/analysis/2015/08/10/fobber-encryption.html"]
    desc = "An e-banking focussed malware that seems to be a Tinba spinoff."
    samples = 300
    lcg = "n = (321167 * n - 1719405398) & 0xFFFFFFFF"
    use_date = False
    use_seed = False
    configs = [None]
    variation = "The entire domain except the TLD."
    regex = "[a-z]{17}"
    ends = ['.net']

    def __init__(self, date=None, seed=None):
        self.r = 0xC87C8A78
        self.c = -1719405398
        self.l = 17
        self.tld = '.net'
        self.domain = None

    def ror32(self, v, n):
        return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF

    def _dga(self):
        self.domain = ""
        for _ in range(self.l):
            self.r = self.ror32((321167 * self.r + self.c) & 0xFFFFFFFF, 16);
            self.domain += chr((self.r & 0x17FF) % 26 + ord('a'))
        self.domain += self.tld

    def get_domain(self):
        self._dga()
        return self.domain
