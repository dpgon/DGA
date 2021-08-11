from ctypes import c_int


class DGA:
    shortname = "dnschanger"
    yara = "dnschanger.yar"
    name = "DNSChanger malware"
    ref = ["https://johannesbader.ch/blog/the-dga-in-alureon-dnschanger/"]
    desc = "DNSChanger malware samples use a domain generation algorithm (DGA) to generate five pseudo random domains. In contrast to most other uses of DGAs, the domains are never intended to be actually registered. Instead, by contacting the domains, the rogue name servers are informed immediately of newly infected clients. Failed DNS queries also reveal that the DNS changes did not succeed, or that the queries are blocked."
    samples = 5
    lcg = "n = ((214013 * n + 2531011) >> 16) & 0x7FFF"
    use_date = False
    use_seed = "Integer number. 60000 by default."
    configs = [None]
    variation = "The entire domain except the TLD."
    regex = "[a-bd-ux-z]{10}"
    ends = ['.com']

    def __init__(self, date=None, seed="60000"):
        self.domain = None
        self.r = c_int()
        self.r.value = int(seed)

    def rand(self):
        self.r.value = 214013 * self.r.value + 2531011
        return (self.r.value >> 16) & 0x7FFF

    def randint(self, lower, upper):
        return lower + self.rand() % (upper - lower + 1)

    def _dga(self):
        sld = ''.join([chr(self.randint(ord('a'), ord('z'))) for _ in range(10)])
        self.domain = sld + '.com'

    def get_domain(self):
        self._dga()
        return self.domain
