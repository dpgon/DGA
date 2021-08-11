import hashlib


class DGA:
    shortname = "padcrypt"
    yara = "padcrypt.yar"
    name = "PadCrypt ransomware"
    ref = ["https://johannesbader.ch/blog/the-dga-of-padcrypt/",
           "https://www.bleepingcomputer.com/news/security/padcrypt-the-first-ransomware-with-live-support-chat-and-an-uninstaller/"]
    desc = "PadCrypt is a ransomware that offers for the first time a live support chat feature and an uninstaller for its victims."
    samples = 24
    # 24 samples in the 2.2.86.1 config
    lcg = None
    use_date = 1
    use_seed = None
    configs = ["2.2.86.1", "2.2.97.0"]
    variation = "Domain variation with 1 of 11 TLDs."
    regex = "[a-fk-o]{16}"
    ends = ['.com', '.co.uk', '.de', '.org', '.net', '.eu', '.info', '.online', '.co', '.cc', '.website']

    def __init__(self, date=None, seed="2.2.97.0"):
        self.date = date

        configs = {
            "2.2.86.1": {
                'nr_domains': 24,
                'tlds': ['com', 'co.uk', 'de', 'org', 'net', 'eu', 'info', 'online',
                         'co', 'cc', 'website'],
                'digit_mapping': "abcdnfolmk",
                'separator': ':',
            },
            "2.2.97.0": {
                'nr_domains': 24 * 3,
                'tlds': ['com', 'co.uk', 'de', 'org', 'net', 'eu', 'info', 'online',
                         'co', 'cc', 'website'],
                'digit_mapping': "abcdnfolmk",
                'separator': '|'
            }
        }
        self.config = configs[seed]
        self.domain = None
        self.generator = None

    def _dga(self):
        dm = self.config['digit_mapping']
        tlds = self.config['tlds']
        for i in range(self.config['nr_domains']):
            seed_str = "{}-{}-{}{}{}".format(self.date.day, self.date.month, self.date.year,
                                             self.config['separator'], i)
            h = hashlib.sha256(seed_str.encode('ascii')).hexdigest()
            self.domain = ""
            for hh in h[3:16 + 3]:
                self.domain += dm[int(hh)] if '0' <= hh <= '9' else hh
            tld_index = int(h[-1], 16)
            tld_index = 0 if tld_index >= len(tlds) else tld_index
            self.domain += "." + self.config['tlds'][tld_index]
            yield self.domain

    def get_domain(self):
        if self.generator:
            next(self.generator)
        else:
            self.generator = self._dga()
            next(self.generator)
        return self.domain
