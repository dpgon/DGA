from time import mktime


class DGA:
    shortname = "pykspa2"
    yara = "pykspa.yar"
    name = "Pykspa worm v2"
    ref = ["http://johannesbader.ch/2015/07/pykspas-inferior-dga-version/",
           "https://blogs.akamai.com/sitr/2019/07/pykspa-v2-dga-updated-to-become-selective.html"]
    desc = "Pykspa, also known as Pykse, Skyper or SkypeBot, is a worm that spreads via Skype."
    samples = 0
    lcg = None
    use_date = 2
    use_seed = None
    configs = [None]
    variation = "Different domains and the tld is one of five possibilities."
    regex = "[a-z]{6,12}"
    ends = ['.com', '.net', '.org', '.info', '.cc']

    def __init__(self, date=None, seed=None):
        self.date = date
        unix_timestamp = mktime(self.date.timetuple())
        self.seed = int(unix_timestamp // (2 * 24 * 3600))
        self.nr = 0
        self.domain = None
        self.generator = None
        self.tlds = ["biz", "com", "net", "org", "info", "cc"]

    def get_sld(self, sld_len, r):
        a = sld_len ** 2
        sld = ""
        for i in range(sld_len):
            x = i * (r % 4567 + r % 19) & 0xFFFFFFFF
            y = r % 123456
            z = r % 5
            p = (r * (z + y + x)) & 0xFFFFFFFF
            ind = (a + p) & 0xFFFFFFFF
            sld += chr(ord('a') + ind % 26)
            r = (r + i) & 0xFFFFFFFF
            r = r >> (((i ** 2) & 0xFF) & 31)
            a += sld_len
            a &= 0xFFFFFFFF
        return sld

    def _dga(self):
        r = self.seed
        while True:
            r = int(r ** 2) & 0xFFFFFFFF
            r += self.nr
            r &= 0xFFFFFFFF
            domain_length = (r % 10) + 6
            sld = self.get_sld(domain_length, r)
            tld = self.tlds[r % 6]
            self.domain = "{}.{}".format(sld, tld)
            self.nr += 1
            yield self.domain

    def get_domain(self):
        if self.generator:
            next(self.generator)
        else:
            self.generator = self._dga()
            next(self.generator)
        return self.domain
