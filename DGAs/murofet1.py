import hashlib


class DGA:
    shortname = "murofet1"
    yara = "murofet.yar"
    name = "Murofet malware DGA v1"
    ref = ["https://johannesbader.ch/blog/three-variants-of-murofets-dga/"]
    desc = "Murofet, also called LICAT, is a member of the ZeuS family."
    samples = 800
    lcg = False
    use_date = 7
    use_seed = False
    configs = [None]
    variation = "Different domains and the tld is one of six possibilities."
    regex = "[a-z]{15,32}"
    ends = [".ru", ".biz", ".info", ".org", ".net", ".com"]

    def __init__(self, date=None, seed=None):
        self.date = date
        self.tlds = [".ru", ".biz", ".info", ".org", ".net", ".com"]
        self.domain = None
        self.index = 0

    def _dga(self):
        seed = 7 * [0]
        seed[0] = ((self.date.year & 0xFF) + 0x30) & 0xFF
        seed[1] = self.date.month
        seed[2] = (self.date.day // 7) * 7
        r = self.index
        for i in range(4):
            seed[3 + i] = r & 0xFF
            r >>= 8

        seed_str = ""
        for i in range(7):
            seed_str += chr((seed[i]))

        m = hashlib.md5()
        m.update(seed_str.encode('latin1'))
        md5 = m.digest()

        self.domain = ""
        for m in md5:
            # 12 of 255 cases don't add letter to the domain (~5%)
            d = (m & 0x1F) + ord('a')
            c = (m >> 3) + ord('a')
            if d != c:
                if d <= ord('z'):
                    self.domain += chr(d)
                if c <= ord('z'):
                    self.domain += chr(c)

        for i, tld in enumerate(self.tlds):
            m = len(self.tlds) - i
            if not self.index % m:
                self.domain += tld
                break

    def get_domain(self):
        self._dga()
        self.index += 1
        return self.domain
