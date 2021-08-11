import string
import time


class DGA:
    shortname = "qadars"
    yara = "qadars.yar"
    name = "Qadars trojan"
    ref = ["https://johannesbader.ch/blog/the-dga-of-qadars/",
           "https://securityintelligence.com/an-analysis-of-the-qadars-trojan/",
           "https://www.phishlabs.com/blog/dissecting-the-qadars-banking-trojan/"]
    desc = "Qadars is a sophisticated trojan used for crimeware-related activities including banking fraud and credential theft."
    samples = 200
    lcg = "x = (seed - 1043968403*x) & 0x7FFFFFFF"
    use_date = 7
    use_seed = "Two bytes number in hex format (e08a by default)"
    configs = ["89f5", "4449", "E1F1", "E1F2", "E08A", "E1F5"]
    variation = "Domain with one of three tld"
    regex = "[a-z0-9]{12}"
    ends = [".net", ".org", ".top", ".com"]

    def __init__(self, date=None, seed='e08a'):
        self.seed = int(seed, 16)
        self.domain = self.seed
        self.date = date
        self.domain = None
        self.generator = None

    def rand(self, r, seed):
        return (seed - 1043968403 * r) & 0x7FFFFFFF

    def _dga(self):
        charset = string.ascii_lowercase + string.digits
        if self.seed in [0xE1F2, 0xE1F1, 0xE1F5]:
            tlds = [".com", ".org", ".net"]
        else:
            tlds = [".net", ".org", ".top"]
        unix = int(time.mktime(self.date.timetuple()))
        b = 7 * 24 * 3600
        c = 4 * 24 * 3600
        r = unix - (unix - c) % b
        for i in range(200):
            self.domain = ""
            for _ in range(12):
                r = self.rand(r, self.seed)
                self.domain += charset[r % len(charset)]
            r = self.rand(r, self.seed)
            tld = tlds[r % 3]
            self.domain += tld
            yield self.domain

    def get_domain(self):
        if self.generator:
            next(self.generator)
        else:
            self.generator = self._dga()
            next(self.generator)
        return self.domain
