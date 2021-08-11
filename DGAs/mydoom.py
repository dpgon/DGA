class DGA:
    shortname = "mydoom"
    yara = "mydoom.yar"
    name = "Mydoom malware"
    ref = ["https://johannesbader.ch/blog/the-dga-of-a-monero-miner-downloader/",
           "https://www.giac.org/paper/gcih/568/mydoom-dom-anlysis-mydoom-virus/106069"]
    desc = "Mydoom also known as W32.MyDoom@mm, Novarg, Mimail.R and Shimgapi, is a computer worm affecting Microsoft Windows."
    samples = 0
    lcg = "n = (1664525 * n + 1013904223) & 0xFFFFFFFF"
    use_date = 1
    use_seed = "String with a hex number. (FA8 by default)"
    configs = [None]
    variation = "Different domains and the tld is one of eight possibilities."
    regex = "(a|s|n|h|r|e|q|w|p|m){10}"
    ends = ['.com', '.biz', '.us', '.net', '.org', '.ws', '.info', '.in']

    def __init__(self, date=None, seed="FA8"):
        self.date = date
        self.seed = int(seed, 16)
        temp = self.date.year + self.date.month + self.date.day + self.seed
        self.r = temp
        self.generator = None
        self.domain = None
        self.nr = 1
        self.tlds = ['.com', '.biz', '.us', '.net', '.org', '.ws', '.info']
        self.defaulttld = ".in"
        self.letters = "asnhreqwpm"

    def rand(self):
        self.r = self.r * 1664525
        self.r += 1013904223
        self.r &= 0xFFFFFFFF
        return self.r

    def _dga(self):
        if self.nr == 0x33:
            self.r = self.seed
        v1 = self.rand()
        ra = []
        for i in range(10):
            ra.append(v1 % 10)
            v1 //= 10

        self.domain = ""
        for x in ra:
            self.domain += self.letters[x]

        if ra[0] < len(self.tlds):
            tld = self.tlds[ra[0]]
        else:
            tld = self.defaulttld

        self.domain += tld
        self.nr += 1

    def get_domain(self):
        self._dga()
        return self.domain
