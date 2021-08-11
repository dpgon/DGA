from itertools import product
from datetime import datetime
from collections import namedtuple


class DGA:
    shortname = "bazarbackdoor4"
    yara = "bazarbackdoor.yar"
    name = "Bazar backdoor v2 malware"
    ref = ["https://johannesbader.ch/blog/the-dga-of-bazarbackdoor/",
           "https://johannesbader.ch/blog/a-bazarloader-dga-that-breaks-during-summer-months/",
           "https://www.fortinet.com/blog/threat-research/new-bazar-trojan-variant-is-being-spread-in-recent-phishing-campaign-part-I",
           "https://www.fortinet.com/blog/threat-research/new-bazar-trojan-variant-is-being-spread-in-recent-phishing-campaign-part-II"]


    desc = "BazarLoader (also known as Bazar Loader, Bazar Backdoor or Team9 Backdoor) is a module of the dreaded TrickBot Trojan. It is mostly used to gain a foothold in compromised enterprise networks. The malware is named after the C&C domains with top level domain .bazar. This TLD is provided by EmerDNS, a peer-to-peer decentralized domain name system in OpenNIC. This makes it very difficult, if not impossible, for law enforcement to take over these domains."
    samples = 31768
    lcg = False
    use_date = 31
    use_seed = False
    configs = [None]
    variation = "The entire domain except the TLD."
    regex = "(al|am|an|ap|ar|as|at|av|az|di|dy|eg|ek|en|er|es|et|ev|ew|ex|ez|fy|gu|gy|he|ic|if|in|ip|iq|is|it|iv|iw|ix|iz|ky|le|me|mu|ne|of|oh|ol|om|on|oq|or|os|ov|ow|ox|oz|pa|pi|qa|qi|qu|qy|ra|re|ro|sa|se|si|so|su|sy|te|ti|to|tu|ty|ud|uk|ul|um|un|up|ur|us|ut|uv|uw|ux|uz|ve|vi|vu|vy|wa|we|wi|wo|wy|xa|xe|xi|xo|xu|xy|yg|yk|ym|yn|yr|ys|yv|yw|yx|yz|ze|zi|zo){3}"
    ends = [".bazar"]

    def __init__(self, date=None, seed=None):
        self.date = date
        self.seed = self.date.strftime("%m%Y")
        self.domain = None
        self.generator = None
        self.Param = namedtuple('Param', 'mul mod idx')
        self.pool = (
            "yzewevmeywreomviekwyavygontowaerudsoyr"
            "exvuamtyseweesuvizpituiqowuzoretzemuul"
            "tiazicukoqiwolxuykosupwiymitisneroxeyx"
            "anlekyixxirasiasxoapuxqaohezwooxdigyqu"
            "ziutpavezohexyvyguqyqidyovynumunuwsusy"
            "enxaatyvusivaripfyoftesaysozureginalif"
        )

    def _dga(self):
        params = [
            self.Param(19, 19, 0),
            self.Param(19, 19, 1),
            self.Param(4, 22, 4),
            self.Param(4, 4, 5)
        ]
        ranges = []
        for p in params:
            s = int(self.seed[p.idx])
            lower = p.mul * s
            upper = lower + p.mod
            ranges.append(list(range(lower, upper)))

        for indices in product(*ranges):
            self.domain = ""
            for index in indices:
                self.domain += self.pool[index * 2:index * 2 + 2]
            self.domain += ".bazar"
            yield self.domain

    def get_domain(self):
        if self.generator:
            next(self.generator)
        else:
            self.generator = self._dga()
            next(self.generator)
        return self.domain
