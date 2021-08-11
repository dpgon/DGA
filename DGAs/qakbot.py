import binascii
from ctypes import c_uint


class DGA:
    shortname = "qakbot"
    yara = "qakbot.yar"
    name = "Qakbot trojan DGA version"
    ref = ["https://johannesbader.ch/blog/the-dga-of-qakbot/",
           "https://drive.google.com/file/d/1mO2Zb-Q94t39DvdASd4KNTPBD8JdkyC3/view",
           "https://0xthreatintel.medium.com/reversing-qakbot-tlp-white-d1b8b37ad8e7"]
    desc = "Qakbot, Akbot or Qbot is an older banking trojan from 2009 that underwent multiple modifications. Since at least September 2013, Qakbot relies on a domain generation algorithm (DGA) for C&C communication."
    samples = 0
    lcg = False
    use_date = 10
    use_seed = "An integer 0 or 1 (0 by default)"
    configs = ["0", "1"]
    variation = "Domain with one of five tld"
    regex = "[a-z]{8,25}"
    ends = [".net", ".org", ".info", ".com", ".biz"]

    def __init__(self, date=None, seed="0"):
        self.seed = int(seed)
        self.domain = self.seed
        self.date = date
        self.domain = None
        self.generator = None
        self.tlds = ["com", "net", "org", "info", "biz", "org"]

    def date_to_seed(self, date, seed):
        dx = (date.day - 1) // 10
        data = "{}.{}.{}.{:08x}".format(
            dx if dx <= 2 else 2,
            date.strftime("%b").lower(),
            date.year,
            seed)
        crc = c_uint(binascii.crc32(data.encode('ascii')))
        return crc

    def _dga(self):
        seed = self.date_to_seed(self.date, self.seed).value
        mt = MT19937(seed)
        while True:
            tld_nr = mt.rand_int(0, len(self.tlds) - 1)
            length = mt.rand_int(8, 25)
            self.domain = ""
            for l in range(length):
                self.domain += chr(mt.rand_int(0, 25) + ord('a'))
            self.domain += "." + self.tlds[tld_nr]
            yield self.domain

    def get_domain(self):
        if self.generator:
            next(self.generator)
        else:
            self.generator = self._dga()
            next(self.generator)
        return self.domain


class MT19937:
    def __init__(self, seed):
        # Initialize the index to 0
        self.index = 624
        self.mt = [0] * 624
        self.mt[0] = seed  # Initialize the initial state to the seed
        for i in range(1, 624):
            self.mt[i] = self._int32(
                1812433253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)

    def _int32(self, x):
        return int(0xFFFFFFFF & x)

    def extract_number(self):
        if self.index >= 624:
            self.twist()

        y = self.mt[self.index]
        y = y ^ y >> 11
        y = y ^ y << 7 & 2636928640
        y = y ^ y << 15 & 4022730752
        y = y ^ y >> 18

        self.index = self.index + 1
        return self._int32(y)

    def twist(self):
        for i in range(0, 624):
            y = self._int32((self.mt[i] & 0x80000000) +
                       (self.mt[(i + 1) % 624] & 0x7fffffff))
            self.mt[i] = self.mt[(i + 397) % 624] ^ y >> 1

            if y % 2 != 0:
                self.mt[i] = self.mt[i] ^ 0x9908b0df
        self.index = 0

    def rand_int(self, lower, upper):
        r = self.extract_number()
        r &= 0xFFFFFFF
        t = lower + float(r) / (2**28)*(upper - lower + 1)
        t = int(t)
        return t
