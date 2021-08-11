class DGA:
    shortname = "ramdo"
    yara = "ramdo.yar"
    name = "Ramdo malware"
    ref = ["https://web.archive.org/web/20160602004352/https://www.damballa.com/behind-ramdo-dga-domain-generation-algorithm/",
           "https://www.secureworks.com/blog/ramdo-click-fraud-malware"]
    desc = "Ramdo is a family of malware that performs fraudulent website ‘clicks’."
    samples = 0
    lcg = False
    use_date = False
    use_seed = "A string with an hexadecimal number (D5FFF by default)"
    configs = ['D5FFF', '2B44C']
    variation = "The entire domain except the .org TLD."
    regex = "[a-z]{16}"
    ends = ['.org']

    def __init__(self, date=None, seed='D5FFF'):
        self.seed = int(seed, 16)
        self.domain = None
        self.nr = 0

    def _dga(self):
        s = (2 * self.seed * (self.nr + 1))
        r = s ^ (26 * self.seed * self.nr)
        self.domain = ""
        for i in range(16):
            r = r & 0xFFFFFFFF
            self.domain += chr(r % 26 + ord('a'))
            r += (r ^ (s * i ** 2 * 26))
        self.domain += ".org"
        self.nr += 1

    def get_domain(self):
        self._dga()
        return self.domain
