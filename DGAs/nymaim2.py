import json
import hashlib


class DGA:
    shortname = "nymaim2"
    yara = "nymaim2.yar"
    name = "Nymain malware v2"
    ref = ["https://johannesbader.ch/blog/the-new-domain-generation-algorithm-of-nymaim/"]
    desc = "Nymaim was discovered in 2013, it was only a dropper, but over time it gained banking capabilities."
    samples = 704
    lcg = None
    use_date = 1
    use_seed = None
    configs = [None]
    variation = "Two words from a dictionary joined by a hyphen (optionally) with a tld (68  TLD) from the same dictionary."
    regex = "[a-z]{4,18}(-)?[a-z]{4,15}"
    # There are a combination of two words (2450 - 4387 words) with the TLD
    ends = ['.ac', '.ad', '.am', '.at', '.az', '.be', '.biz', '.bt', '.by', '.cc', '.ch', '.cm', '.cn', '.co', '.com', '.cx', '.cz', '.de', '.dk', '.ec', '.eu', '.gs', '.hn', '.ht', '.id', '.in', '.info', '.it', '.jp', '.ki', '.kr', '.kz', '.la', '.li', '.lk', '.lv', '.me', '.mo', '.mv', '.mx', '.name', '.net', '.nu', '.org', '.ph', '.pk', '.pl', '.pro', '.ps', '.re', '.ru', '.sc', '.sg', '.sh', '.su', '.tel', '.tf', '.tj', '.tk', '.tm', '.top', '.uz', '.vn', '.win', '.ws', '.wtf', '.xyz', '.yt']

    def __init__(self, date=None, seed="3138C81ED54AD5F8E905555A6623C9C9"):
        # Just a known seed
        self.date = date
        self.seed = seed
        self.m = self.md5(seed)
        self.domain = None
        self.generator = None

    @staticmethod
    def md5(s):
        return hashlib.md5(s.encode('ascii')).hexdigest()

    def rand(self, year, yday, offset=0):
        s = "{}{}{}".format(self.m, year, yday + offset)
        self.hashstring = self.md5(s)

    def getval(self):
        v = int(self.hashstring[:8], 16)
        self.hashstring = self.md5(self.hashstring[7:])
        return v

    def _dga(self):
        with open("DGAs/wordlist/words.json", "r") as r:
            wt = json.load(r)
        daydelta = 10
        maxdomainsfortry = 64
        year = self.date.year % 100
        yday = self.date.timetuple().tm_yday - 1

        for dayoffset in range(daydelta + 1):
            self.rand(year, yday - dayoffset)
            for _ in range(maxdomainsfortry):
                self.domain = ""
                for s in ['firstword', 'separator', 'secondword', 'tld']:
                    ss = wt[s]
                    self.domain += ss[self.getval() % len(ss)]
                yield self.domain

    def get_domain(self):
        if self.generator:
            next(self.generator)
        else:
            self.generator = self._dga()
            next(self.generator)
        return self.domain
