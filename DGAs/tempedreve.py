import string
from datetime import datetime, timedelta


class DGA:
    shortname = "tempedreve"
    yara = "tempedreve.yar"
    name = "Tempedreve botnet"
    ref = ["https://github.com/baderj/domain_generation_algorithms/tree/master/tempedreve"]
    desc = "Tempedreve is a malware with worm capabilities used to create a botnet."
    samples = 1     # Generate a new sample every day, the rest of domains are one of older days than current
    lcg = "x = (((16843009*x) & 0xFFFFFFFF) + 65805) & 0xFFFFFFFF\n         "\
          "seed = (((1664525 * days) & 0xFFFFFFFF) + 1013904223) & 0xFFFFFFFF"
    use_date = 1
    use_seed = False
    configs = [None]
    variation = "Domain with one of four tld"
    regex = "[a-z]{8}"
    ends = [".net", ".org", ".info", ".com"]

    def __init__(self, date=None, seed=None):
        self.date = date
        self.domain = None
        self.generator = None
        self.tlds = ['.com', '.net', '.org', '.info']

    def rand(self, r):
        r = (16843009 * r) & 0xFFFFFFFF
        r = (r + 65805) & 0xFFFFFFFF
        return r

    def shuffle(self, letters, seed):
        r = seed
        for j in range(len(letters)):
            i = r % len(letters)
            r = self.rand(r)
            letters[j], letters[i] = letters[i], letters[j]
        return letters

    def days_since_unix_epoch(self, dt):
        return (dt - datetime(1970, 1, 1)).days

    def _dga(self):
        enddate = datetime.strptime("2015-03-23", "%Y-%m-%d")
        # Tempedreve generate domains till a date, changed in order to stadisticals calculations
        #while self.date >= enddate:
        while True:
            days = self.days_since_unix_epoch(self.date)
            seed = (((1664525 * days) & 0xFFFFFFFF) + 1013904223) & 0xFFFFFFFF
            letters = list(string.ascii_lowercase)
            letters = self.shuffle(letters, seed)
            length = seed % 5 + 7   # Error in seed always ends in 1 or 6, %5 lefts lenght with 8 always
            self.domain = ""
            r = seed
            for i in range(length):
                self.domain += letters[r % len(letters)]
                r = self.rand(r)
            tld = self.tlds[seed & 3]
            self.domain += tld
            self.date -= timedelta(days=1)
            yield self.domain

    def get_domain(self):
        if self.generator:
            next(self.generator)
        else:
            self.generator = self._dga()
            next(self.generator)
        return self.domain
