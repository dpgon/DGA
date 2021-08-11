import hashlib


class DGA:
    shortname = "murofet3"
    yara = "murofet.yar"
    name = "Murofet malware v3"
    ref = ["https://johannesbader.ch/blog/three-variants-of-murofets-dga/"]
    desc = "Murofet, also called LICAT, is a member of the ZeuS family."
    samples = 800
    lcg = False
    use_date = 7
    use_seed = False
    configs = [None]
    variation = "Different domains and the tld is one of six possibilities."
    regex = "(([a-p][q-z])|([a-p][1-6][0-9])){16}"
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

        seed_str = ''.join([chr(s) for s in seed])

        md5 = hashlib.md5(seed_str.encode('latin1')).digest()

        self.domain = ""
        for m in md5:
            """ 
                a:   'a' ... 'p' 
                b:   'q' ... 'z' . '1' ... '6' 
                c:   '0' ... '9' IFF b is a number, else discard
            """
            a = (m & 0xF) + ord('a')
            b = (m >> 4) + ord('q')
            if b > ord('z'):
                b = b - ord('J')
                c = (a % 10) + ord('0')
            else:
                c = None

            self.domain += chr(a)
            self.domain += chr(b)
            if c:
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
