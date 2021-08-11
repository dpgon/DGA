from ctypes import c_int


class DGA:
    shortname = "vawtrak3"
    yara = "vawtrak.yar"
    name = "Vawtrak malware"
    ref = ["https://github.com/baderj/domain_generation_algorithms/blob/master/vawtrak/dga3.py",
           "https://www.blueliv.com/downloads/network-insights-into-vawtrak-v2.pdf"]
    desc = "Vawtrak is distributed as part of the payload of various exploit kits, and via spam email campaigns."
    samples = 0
    lcg = "x = (1103515245 * x + 12345) % 2**31"
    use_date = False
    use_seed = "A string with an hexadecimal number (874c49 by default)"
    configs = ['5542b2', '5884c3c4', '874c49', '3cdca1', 'DEADBEEF']
    variation = "The entire domain except the .com TLD."
    regex = "[ac-il-or-uw]{7,12}"
    ends = ['.com']

    def __init__(self, date=None, seed='874C49'):
        self.seed = int(seed, 16)
        self.domain = None
        self.nr = 0
        self.consonants = "cdfghlmnrstw"
        self.vowels = "aeiou"
        self.r = c_int(self.seed)

    def prng(self, r):
        r.value = (1103515245 * r.value + 12345) % 2 ** 31
        return r

    def _dga(self):
        self.r = self.prng(self.r)
        length = self.r.value % 5 + 7
        self.r = self.prng(self.r)
        p = self.r.value % 2
        self.domain = ""
        for _ in range(length):
            self.r.value = (self.r.value + 0x1895120F)
            self.r = self.prng(self.r)
            tmp = self.r.value
            if p:
                wordlist = self.consonants
                p -= 1
            else:
                wordlist = self.vowels
                self.r = self.prng(self.r)
                p = self.r.value % 2 + 1
            self.domain += wordlist[tmp % len(wordlist)]
        self.domain += ".com"

    def get_domain(self):
        self._dga()
        return self.domain
