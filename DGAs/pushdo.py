from itertools import chain
import hashlib
import struct


class DGA:
    shortname = "pushdo"
    yara = "pushdo.yar"
    name = "PushDo trojan"
    ref = ["https://github.com/baderj/domain_generation_algorithms/tree/master/pushdo",
           "https://www.blueliv.com/cyber-security-and-cyber-threat-intelligence-blog-blueliv/research/tracking-the-footproints-of-pushdo-trojan/"]
    desc = "The Pushdo Trojan program dates back to early 2007 and is used to distribute other malware threats, like Zeus and SpyEye."
    samples = 1350
    lcg = None
    use_date = 1
    use_seed = "Three configs: kz_v1, kz_v2 and com_v1. (kz_v1 by default)"
    configs = ["kz_v1", "kz_v2", "com_v1"]
    variation = "Different domains and the tld is kz or com depending of the config."
    regex = "[a-xz-z]{8,12}"
    ends = [".kz", ".com"]

    def __init__(self, date=None, seed="kz_v1"):
        self.date = date

        configs = {
            "kz_v1": {
                "conso_a": "bcdfghjklmnpqrstvwx",
                "conso_b": "zxtsrqpnmlkgfdc",
                "vowels_a": "aeiou",
                "vowels_b": "aio",
                "mod": 7,
                "mod2": 1,
                "tld": ".kz"
            },
            "com_v1": {
                "conso_a": "bcdfghjklmnpqrstvwx",
                "conso_b": "zxtsrqpnmlkgfdc",
                "vowels_a": "aeiou",
                "vowels_b": "aio",
                "mod": 7,
                "mod2": 1,
                "tld": ".com"
            },
            "kz_v2": {
                "conso_a": "kqbhcndjfwglpmzxrsv",
                "conso_b": "qzlbtgrnkxsfdcm",
                "vowels_a": "aeiou",
                "vowels_b": "aio",
                "mod": 8,
                "mod2": 2,
                "tld": ".kz"
            }
        }
        self.seed = configs[seed]
        self.domain = None
        self.generator = None

    def part(self, r):
        mod = self.seed.get("mod")
        mod2 = self.seed.get("mod2")
        conso_a = self.seed.get('conso_a')
        conso_b = self.seed.get('conso_b')
        vowels_a = self.seed.get('vowels_a')
        vowels_b = self.seed.get('vowels_b')
        assert (len(conso_a) == 19)
        assert (len(vowels_a) == 5)
        assert (len(vowels_b) == 3)
        assert (len(conso_b) == 15)

        string = ""
        string += conso_a[r % 19]
        rp2 = r + 2
        string += vowels_a[((r + 1) & 0xFF) % 5]
        if string[1] == 'e' and rp2 & mod:
            v = vowels_b[rp2 % 3]
        else:
            if not (rp2 & mod2):
                return string
            v = conso_b[(r + 3) % 15]
        string += v
        return string

    def dga(self, md5, length, loops=16):
        domain = ""
        for i in range(loops):
            r = md5[i]
            p = self.part(r)
            domain += p
            if len(domain) >= length:
                domain = domain[:length]
                domain += self.seed['tld']
                return domain

    def days_since_0(self):
        days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        year = self.date.year
        month = self.date.month - 1
        day = self.date.day
        if not year % 4:
            days_in_month[1] = 29
        t = 0
        while month > 0:
            t += days_in_month[month]
            month -= 1
        return day + t + 365 * (year - year // 4) + 366 * (year // 4)

    def domains_for_day(self, r):
        for i in range(30):
            b = struct.pack("<I", r)
            md5 = hashlib.md5(b).digest()
            r = struct.unpack("<I", md5[:4])[0]
            length = (r & 3) + 9
            self.domain = self.dga(md5, length)
            r += 1
            yield self.domain

    def _dga(self):
        days = self.days_since_0()
        for j in chain(range(0, -31, -1), range(1, 15)):
            yield from self.domains_for_day(days + j)

    def get_domain(self):
        if self.generator:
            next(self.generator)
        else:
            self.generator = self._dga()
            next(self.generator)
        return self.domain
