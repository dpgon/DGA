class DGA:
    shortname = "symmi"
    yara = "symmi.yar"
    name = "Symmi malware"
    ref = ["https://johannesbader.ch/blog/the-dga-of-symmi/"]
    desc = "Symmi, other names for the same or similar malware family are MewsSpy and Graftor."
    samples = 0
    lcg = False
    use_date = 16   # Two variatios per month (1-15 and 16-end)
    use_seed = False
    configs = [None]
    variation = "The entire domain except the .ddns.net TLD."
    regex = "[a-ik-z]{8,15}"
    ends = ['.ddns.net']

    def __init__(self, date=None, seed=None):
        self.domain = None
        self.seed_const = 42
        self.days_period = 16
        self.nr_of_domains = 64
        self.third_lvl_min_len = 8
        self.third_lvl_max_len = 15
        self.date = date
        self.seed = self.create_seed()
        self.tld = ".ddns.net"

    def create_seed(self):
        return 10000 * (self.date.day // self.days_period * 100 + self.date.month) + self.date.year + self.seed_const

    def rand(self):
        self.seed = (self.seed * 214013 + 2531011) & 0xFFFFFFFF
        return (self.seed >> 16) & 0x7FFF

    def next_domain(self, second_and_top_lvl, third_lvl_domain_len):
        letters = ["aeiouy", "bcdfghklmnpqrstvwxz"]
        domain = ""
        for i in range(third_lvl_domain_len):
            if not i % 2:
                offset_1 = 0 if self.rand() & 0x100 == 0 else 1
            s = self.rand()
            offset = (offset_1 + i) % 2
            symbols = letters[offset]
            domain += symbols[s % (len(symbols) - 1)]
        return domain + second_and_top_lvl

    def _dga(self):
        span = self.third_lvl_max_len - self.third_lvl_min_len + 1
        third_lvl_len = self.third_lvl_min_len + self.rand() % span
        self.domain = self.next_domain(self.tld, third_lvl_len)

    def get_domain(self):
        self._dga()
        return self.domain
