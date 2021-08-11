class DGA:
    shortname = "fosniw"
    yara = None
    name = "Fosniw downloader"
    ref = ["https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/FOSNIW/"]
    desc = "This malware family of Trojans is used to download other malware on the affected systems thus further compromising its security."
    samples = 101
    lcg = False
    use_date = False
    use_seed = "Two known seeds: appx.koreasys{}.com and app2.winsoft{}.com (koreasys by default)"
    configs = ["appx.koreasys{}.com", "app2.winsoft{}.com"]
    variation = "The number before the TLD. The rest of the domain doesn't change."
    regex = "(appx.koreasys[0-9]{1,3}|app2.winsoft[0-9]{1,3})"
    ends = ['.com']

    def __init__(self, date=None, seed="appx.koreasys{}.com"):
        self.seed = seed
        self.domain = None
        self.generator = None

    def _dga(self):
        if "{}" not in self.seed:
            raise ValueError("unsupported seed {}".format(self.seed))
        for i in range(101):
            self.domain = self.seed.format(i)
            yield self.domain

    def get_domain(self):
        if self.generator:
            next(self.generator)
        else:
            self.generator = self._dga()
            next(self.generator)
        return self.domain
