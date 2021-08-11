class DGA:
    shortname = "nymaim1"
    yara = "nymaim1.yar"
    name = "Nymain malware"
    ref = ["https://github.com/baderj/domain_generation_algorithms/blob/master/nymaim/dga.py",
           "https://arielkoren.com/blog/2016/11/02/nymaim-deep-technical-dive-adventures-in-evasive-malware/"]
    desc = "Nymaim was discovered in 2013, it was only a dropper, but over time it gained banking capabilities."
    samples = 0
    lcg = None
    use_date = 1
    use_seed = None
    configs = [None]
    variation = "Different domains and the tld is one of five possibilities."
    regex = "[a-z]{6,11}"
    ends = ['.com', '.net', '.org', '.biz', '.info']

    def __init__(self, date=None, seed=None):
        self.date = date
        s = self.date.year + (self.date.month << 16) + (self.date.isoweekday() % 7) \
            + (self.date.day << 16)
        self.r = 4 * [None]
        self.r[0] = (s + 0x52455641) & 0xFFFFFFFF
        self.r[1] = (s + 0x49484F4C)
        self.r[1] = self.r[1] if self.r[1] <= 0xFFFFFFFF else 0
        self.r[2] = (s + 0x59554820) & 0xFFFFFFFF
        self.r[3] = (s + 0x4D415620) & 0xFFFFFFFF
        self.domain = None

    def rand(self, m):
        t = 4 * [None]
        t[0] = ((self.r[0] << 11) ^ self.r[0]) & 0xFFFFFFFF
        t[1] = self.r[1]
        t[2] = self.r[2]
        t[3] = ((self.r[3] >> 19) ^ self.r[3]) ^ t[0]
        t[0] = t[0] >> 8
        t[3] = t[3] ^ t[0]
        c = self.r[2]
        for i in range(3):
            self.r[i] = (self.r[i] + self.r[i + 1]) & 0xFFFFFFFF
        self.r[3] = t[3]
        nr = (((c + t[3]) & 0xFFFFFFFF) // 100) % m
        return nr

    def _dga(self):
        length = self.rand(6) + 6
        self.domain = ""
        for l in range(length):
            self.domain += chr(ord('a') + (self.rand(26) % 26))

        t = ord(self.domain[-2]) - ord('a')
        if t < 9:
            self.domain += '.com'
        elif t < 13:
            self.domain += '.org'
        elif t < 17:
            self.domain += '.biz'
        elif t < 21:
            self.domain += '.net'
        else:
            self.domain += '.info'

    def get_domain(self):
        self._dga()
        return self.domain
