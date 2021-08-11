import hashlib


class DGA:
    shortname = "murofet2"
    yara = "murofet.yar"
    name = "Murofet malware DGA v2"
    ref = ["https://johannesbader.ch/blog/three-variants-of-murofets-dga/"]
    desc = "Murofet, also called LICAT, is a member of the ZeuS family."
    samples = 800
    lcg = False
    use_date = 1
    use_seed = "Integer in hex. Known seeds D6D7A4BE, DEADC2DE and D6D7A4B1 (D6D7A4BE by default)"
    configs = ["D6D7A4BE", "DEADC2DE", "D6D7A4B1", None]
    variation = "Different domains and the tld is one of five possibilities."
    regex = "[a-z]{10,16}"
    ends = [".biz", ".info", ".org", ".net", ".com"]

    def __init__(self, date=None, seed=None):
        self.date = date
        if seed:
            self.seed = int(seed, 16)
        else:
            self.seed = None
        self.tlds = [".biz", ".info", ".org", ".net", ".com"]
        self.domain = None
        self.index = 0

    def _dga(self):
        seed = 8 * [0]
        seed[0] = ((self.date.year & 0xFF) + 0x30) & 0xFF
        seed[1] = self.date.month & 0xFF
        seed[2] = self.date.day & 0xFF
        seed[3] = 0
        r = self.index & 0xFFFFFFFE
        for i in range(4):
            seed[4 + i] = r & 0xFF
            r >>= 8

        seed_str = ""
        for i in range(8):
            k = (self.seed >> (8 * (i % 4))) & 0xFF if self.seed else 0
            seed_str += chr((seed[i] ^ k))

        m = hashlib.md5()
        m.update(seed_str.encode('latin1'))
        md5 = m.digest()

        self.domain = ""
        for m in md5:
            tmp = (m & 0xF) + (m >> 4) + ord('a')
            if tmp <= ord('z'):
                self.domain += chr(tmp)

        for i, tld in enumerate(self.tlds):
            m = len(self.tlds) - i
            if not self.index % m:
                self.domain += tld
                break

    def get_domain(self):
        self._dga()
        self.index += 1
        return self.domain
