class DGA:
    shortname = "tinba"
    yara = "tinba.yar"
    name = "Tinba backdoor"
    ref = ["https://johannesbader.ch/blog/new-top-level-domains-for-tinbas-dga/",
           "https://www.zscaler.com/blogs/security-research/look-recent-tinba-banking-trojan-variant"]
    desc = "Tiny Banker Trojan, also called Tinba, is a malware program that targets financial institution websites."
    samples = 408
    lcg = False
    use_date = False
    use_seed = "A configuration from 4 known options (0-3) with a seed, a domain, tlds and a limit of domains (1 by default)"
    configs = ['0', '1', '2', '3']
    variation = "The entire domain except one of eleven TLDs."
    regex = "([a-y]{12}|newstatinru|justforyou0987|phpsitegooddecoder|santaluable|santanyr|ervaluable|larnasa|blackfreeqazyio|j193hsne720uie8i)"
    ends = ['.com', '.net', '.in', '.ru', '.pw', '.us', '.xyz', '.club', '.org', '.biz', '.cc']

    def __init__(self, date=None, seed='1'):
        self.domain = None
        self.generator = None
        config = int(seed)
        configs = [
                        # http://garage4hackers.com/entry.php?b=3086
                        ('oGkS3w3sGGOGG7oc', 'ssrgwnrmgrxe.com', ('com',), 1000),
                        # https://johannesbader.ch/2015/04/new-top-level-domains-for-tinbas-dga
                        ('jc74FlUna852Ji9o', 'blackfreeqazyio.cc', ('com', 'net', 'in', 'ru'), 100),
                        # https://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/Troj~Tinba-EL/detailed-analysis.aspx
                        # https://github.com/baderj/domain_generation_algorithms/commit/c7d154a39bb172c4632f7565e0c9380e8b36c18e
                        ('yqokqFC2TPBFfJcG', 'watchthisnow.xyz', ('pw', 'us', 'xyz', 'club'), 100),
                        # https://github.com/baderj/domain_generation_algorithms/commit/c7d154a39bb172c4632f7565e0c9380e8b36c18e
                        ('j193HsnW72Yqns7u', 'j193hsne720uie8i.cc', ('com', 'net', 'biz', 'org'), 100),
                    ]
        self.seed = configs[config][0]
        self.domain = configs[config][1]
        self.tlds = configs[config][2]
        self.nr = configs[config][3]
        # Hard-coded domains: 1 line(https://www.symantec.com/security_response/writeup.jsp?docid=2014-092411-3132-99&tabid=2)
        # 2 line (https://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/Troj~Wonton-MT/detailed-analysis.aspx)
        self.hard_coded = ['newstatinru.ru', 'justforyou0987.pw', 'phpsitegooddecoder.com',
                           'santaluable.com', 'santanyr.com', 'ervaluable.com', 'larnasa.com']

    def _dga(self):
        olddom = self.domain
        for domain in self.hard_coded:
            self.domain = domain
            yield self.domain
        self.domain = olddom
        self.seed += (17 - len(self.seed)) * '\x00'
        seed_l = [ord(s) for s in self.seed]
        yield self.domain
        for _ in range(self.nr):
            domain_l = [ord(l) for l in self.domain]
            seed_sum = sum(seed_l[:16])
            new_domain = []
            tmp = seed_l[15] & 0xFF
            for i in range(12):
                while True:
                    tmp += domain_l[i]
                    tmp ^= (seed_sum & 0xFF)
                    tmp += domain_l[i + 1]
                    tmp &= 0xFF
                    if 0x61 < tmp < 0x7a:
                        new_domain.append(tmp)
                        break
                    else:
                        seed_sum += 1
            base_domain = ''.join([chr(x) for x in new_domain])
            for tld in self.tlds:
                self.domain = base_domain + '.' + tld
                yield self.domain

    def get_domain(self):
        if self.generator:
            next(self.generator)
        else:
            self.generator = self._dga()
            next(self.generator)
        return self.domain
