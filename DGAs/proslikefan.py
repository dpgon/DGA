from ctypes import c_int


class DGA:
    shortname = "proslikefan"
    yara = None
    name = "Proslikefan worm"
    ref = ["https://johannesbader.ch/blog/a-javascript-based-dga/"]
    desc = "Proslikefan is a JavaScript worm that spreads by copying itself to removable drives and mapped network shares, as well as via file-sharing applications."
    samples = 100
    lcg = None
    use_date = 1
    use_seed = "Use a word as seed. (prospect by default)"
    configs = [None]
    variation = "Different domains and the tld is one of ten possibilities."
    regex = "[a-z]{6,12}"
    ends = [".eu", ".biz", ".se", ".info", ".com", ".net", ".org", ".ru", ".in", ".name"]

    def __init__(self, date=None, seed="prospect"):
        self.date = date
        self.seed = seed
        self.domain = None
        self.tlds = ["eu", "biz", "se", "info", "com", "net", "org", "ru", "in", "name"]
        self.generator = None

    def hash_string(self, s):
        h = c_int(0)
        for c in s:
            h.value = (h.value << 5) - h.value + ord(c)
        return h.value

    def _dga(self):
        for i in range(10):
            for tld in self.tlds:
                seed_string = '.'.join([str(s) for s in
                                        [self.seed, self.date.month, self.date.day, self.date.year, tld]])
                r = abs(self.hash_string(seed_string)) + i
                self.domain = ""
                k = 0
                while (k < r % 7 + 6):
                    r = abs(self.hash_string(self.domain + str(r)))
                    self.domain += chr(r % 26 + ord('a'))
                    k += 1
                self.domain += '.' + tld
                yield self.domain

    def get_domain(self):
        if self.generator:
            next(self.generator)
        else:
            self.generator = self._dga()
            next(self.generator)
        return self.domain
