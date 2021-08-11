from datetime import datetime
import hashlib


class DGA:
    shortname = "monero"
    yara = "monero.yar"
    name = "Monero downloader"
    ref = ["https://johannesbader.ch/blog/the-dga-of-a-monero-miner-downloader/",
           "https://www.welivesecurity.com/2017/09/28/monero-money-mining-malware/"]
    desc = "Monero Miner Downloader (aka Crackonosh) is a cryptocurrency-mining malware distributed along with cracked copies of popular software and is also able to disable antivirus software."
    samples = 2500
    lcg = False
    use_date = 1
    use_seed = False
    configs = [None]
    variation = "Different domains and the tld is one of five possibilities. (first 5 domains are always the same)"
    regex = "(31b4bd31fg1x2|[0-9a-f]{13})"
    ends = ['.org', '.tickets', '.blackfriday', '.hosting', '.feedback']

    def __init__(self, date=None, seed=None):
        self.date = date
        self.generator = None
        self.domain = None
        self.tlds = [
            ".org",
            ".tickets",
            ".blackfriday",
            ".hosting",
            ".feedback",
        ]
        self.magic = "jkhhksugrhtijys78g46"
        self.special = "31b4bd31fg1x2"

    def _dga(self):
        epoch = datetime(1970, 1, 1)
        days_since_epoch = (self.date - epoch).days
        days = days_since_epoch
        for nr in range(500):
            for tld in self.tlds:
                seed = "{}-{}-{}".format(self.magic, days, nr)
                m = hashlib.md5(seed.encode('ascii')).hexdigest()
                mc = m[:13]
                if nr == 0:
                    sld = self.special
                else:
                    sld = mc
                self.domain = "{}{}".format(sld, tld)
                yield self.domain

    def get_domain(self):
        if self.generator:
            next(self.generator)
        else:
            self.generator = self._dga()
            next(self.generator)
        return self.domain
