class DGA:
    shortname = "corebot"
    yara = "corebot.yar"
    name = "Corebot banking trojan"
    ref = ["https://johannesbader.ch/2015/09/the-dga-of-corebot/",
           "https://www.crowdstrike.com/blog/ecrime-ecosystem/",
           "https://go.crowdstrike.com/rs/281-OBQ-266/images/Report_BosonSpider.pdf"]
    desc = "A banking trojan and information stealer. The malware’s compiled file was named 'core' by its developer."
    samples = 0
    lcg = "n = (1664525 * n + 1013904223) & 0xFFFFFFFF"
    use_date = 1
    use_seed = "Integer hex number in text format (1DBA8930 by default)"
    configs = ["1DB98930", "1DBA8930"]
    variation = "The entire domain except the TLD."
    regex = "[a-y0-8]{12,23}"
    ends = ['.ddns.net']

    def __init__(self, date=None, seed="1DB98930"):
        self.date = date
        self._init_rand_and_chars(self.date.year, self.date.month, self.date.day, 1, int(seed, 16))
        self.domain = None

    def _init_rand_and_chars(self, year, month, day, nr_b, r):
        self.r = (r + year + ((nr_b << 16) + (month << 8) | day)) & 0xFFFFFFFF
        self.charset = [chr(x) for x in range(ord('a'), ord('z'))] + \
                  [chr(x) for x in range(ord('0'), ord('9'))]

    def _dga(self):
        len_l = 0xC
        len_u = 0x18
        self.r = (1664525 * self.r + 1013904223) & 0xFFFFFFFF
        domain_len = len_l + self.r % (len_u - len_l)
        self.domain = ""
        for i in range(domain_len, 0, -1):
            self.r = ((1664525 * self.r) + 1013904223) & 0xFFFFFFFF
            self.domain += self.charset[self.r % len(self.charset)]
        self.domain += ".ddns.net"

    def get_domain(self):
        self._dga()
        return self.domain
