from datetime import datetime
from ctypes import c_uint

class DGA:
    shortname = "gozi"
    yara = "gozi.yar"
    name = "Gozi trojan"
    ref = ["https://www.govcert.ch/blog/gozi-isfb-when-a-bug-really-is-a-feature/",
           "https://lokalhost.pl/gozi_tree.txt",
           "https://www.f5.com/labs/articles/education/banking-trojans-a-reference-guide-to-the-malware-family-tree"]
    desc = "Gozi ISFB is an eBanking Trojan launched against financial institutions in Switzerland."
    samples = 12
    lcg = "n = 1664525 * n + 1013904223"
    use_date = 5   # 3 - 5 days. It depends from the chosen seed
    use_seed = "Four posibilities: luther, rfc4343, nasa or gpl (all of them dictionary files, luther by default)"
    configs = ['luther', 'rfc4343', 'nasa', 'gpl']
    variation = "The entire domain except the TLD."
    regex = "[a-z]{12,24}"
    ends = ['.com', '.ru']

    def __init__(self, date=None, seed="luther"):
        self.date = date

        seeds = {
            'luther': {'div': 4, 'tld': '.com', 'nr': 12},
            'rfc4343': {'div': 3, 'tld': '.com', 'nr': 10},
            'nasa': {'div': 5, 'tld': '.com', 'nr': 12},
            'gpl': {'div': 5, 'tld': '.ru', 'nr': 10}
        }
        if seed in seeds:
            self.filename = seed
            self.div = seeds[seed]['div']
            self.tld = seeds[seed]['tld']
            self.nr = seeds[seed]['nr']
        else:
            raise ValueError("unsupported seed {}".format(seed))

        self.words = self.get_words()
        diff = self.date - datetime.strptime("2015-01-01", "%Y-%m-%d")
        days_passed = (diff.days // self.div)
        flag = 1
        seed_rand = (flag << 16) + days_passed - 306607824
        self.r = c_uint(seed_rand)

        self.domain = None
        self.generator = None

    def get_words(self):
        with open("DGAs/wordlist/" + self.filename, 'r') as r:
            return [w.strip() for w in r if w.strip()]

    def rand(self):
        self.r.value = 1664525 * self.r.value + 1013904223
        return self.r.value

    def _dga(self):
        for i in range(12):
            self.rand()
            v = self.rand()
            length = v % 12 + 12
            self.domain = ""
            while len(self.domain) < length:
                v = self.rand() % len(self.words)
                word = self.words[v]
                l = len(word)
                if not self.rand() % 3:
                    l >>= 1
                if len(self.domain) + l <= 24:
                    self.domain += word[:l]
            self.domain += self.tld
            yield self.domain

    def get_domain(self):
        if self.generator:
            next(self.generator)
        else:
            self.generator = self._dga()
            next(self.generator)
        return self.domain
