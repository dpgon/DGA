from itertools import product


class DGA:
    shortname = "bazarbackdoor1"
    yara = "bazarbackdoor.yar"
    name = "Bazar backdoor v1 malware"
    ref = ["https://johannesbader.ch/blog/the-dga-of-bazarbackdoor/",
           "https://johannesbader.ch/blog/a-bazarloader-dga-that-breaks-during-summer-months/",
           "https://www.fortinet.com/blog/threat-research/new-bazar-trojan-variant-is-being-spread-in-recent-phishing-campaign-part-I",
           "https://www.fortinet.com/blog/threat-research/new-bazar-trojan-variant-is-being-spread-in-recent-phishing-campaign-part-II"]
    desc = "BazarLoader (also known as Bazar Loader, Bazar Backdoor or Team9 Backdoor) is a module of the dreaded TrickBot Trojan. It is mostly used to gain a foothold in compromised enterprise networks. The malware is named after the C&C domains with top level domain .bazar. This TLD is provided by EmerDNS, a peer-to-peer decentralized domain name system in OpenNIC. This makes it very difficult, if not impossible, for law enforcement to take over these domains."
    samples = 2160
    lcg = False
    use_date = 31
    use_seed = False
    configs = [None]
    variation = "The entire domain except the TLD"
    regex = "[a-e]{1}[c-f]{1}[e-h]{1}[g-i]{1}[i-k]{1}[k-m]{1}[a-z]{6}"
    ends = [".bazar"]

    def __init__(self, date=None, seed=None):
        self.date = date
        self.month = self.date.month
        self.year = self.date.year
        self.domain = None
        self.generator = None

    def _dga(self):
        date_str = "{0:02d}{1:04d}".format(12-self.month, self.year-18)
        valid_chars = [
          "abcde",
          "cdef",
          "efgh",
          "ghi",
          "ijk",
          "klm"
        ]
        valid_chars = [list(_) for _ in valid_chars]
        for part1 in product(*valid_chars):
            self.domain = "".join(part1)
            for i, c in enumerate(part1):
                self.domain += chr(ord(c) + int(date_str[i]))
            self.domain += ".bazar"
            yield self.domain

    def get_domain(self):
        if self.generator:
            next(self.generator)
        else:
            self.generator = self._dga()
            next(self.generator)
        return self.domain
