import time

class DGA:
    shortname = "kraken2"
    yara = "kraken.yar"
    name = "Kraken v2 botnet"
    ref = ["https://johannesbader.ch/blog/krakens-two-domain-generation-algorithms/",
           "https://www.bleepingcomputer.com/news/security/kraken-cryptor-ransomware-masquerading-as-superantispyware-security-program/",
           "https://blog.gdatasoftware.com/blog/article/dissecting-the-kraken.html"]
    desc = "Kraken (also known as Oderoor or Bobax) was a botnet primarily used to send spam messages."
    samples = 0
    lcg = "n = 1103515245 * n + 12435"
    use_date = 7
    use_seed = "Four possible seeds: a1, a2, b1, b2 (a1 by default)"
    configs = ['a1', 'a2', 'b1', 'b2']
    variation = "Seed *1 changes the domain and the tld is one of four possibilities . Seed *2 changes the subdomain. The main domain and the TLD remain the same, one of four possibilities."
    regex = "[a-z]{7,12}"
    ends = [".com", ".net", ".tv", ".cc", ".dyndns.org", ".yi.org", ".dynserv.com", ".mooo.com"]

    def __init__(self, date=None, seed='a1'):
        self.date = date
        seeds = {'a': {'ex': 24938314, 'nex': 24938315},
                 'b': {'ex': 1600000, 'nex': 1600001}}
        tld_sets = {1: ["com", "net", "tv", "cc"],
                    2: ["dyndns.org", "yi.org", "dynserv.com", "mooo.com"]}
        if 'a' in seed:
            self.seed = seeds['a']
        elif 'b' in seed:
            self.seed = seeds['b']
        else:
            raise ValueError("unsupported seed {}".format(seed))
        if '1' in seed:
            self.tlds = tld_sets[1]
        elif '2' in seed:
            self.tlds = tld_sets[2]
        else:
            raise ValueError("unsupported seed {}".format(seed))
        self.domain = None
        self.nr = 0
        self.flag = False

    def rand(self, r):
        t = (1103515245 * r + 12435) & 0xFFFFFFFF
        return t

    def crop(self, r):
        return (r // 256) % 32768

    def _dga(self, index, temp_file=True):
        domain_nr = int(index / 2)

        if temp_file:
            r = 3 * domain_nr + self.seed['ex']
        else:
            r = 3*domain_nr + self.seed['nex']

        discards = (int(time.mktime(self.date.timetuple())) - 1207000000) // 604800 + 2
        if domain_nr % 9 < 8:
            if domain_nr % 9 >= 6:
                discards -= 1
            for _ in range(discards):
                r = self.crop(self.rand(r))

        rands = 3 * [0]
        for i in range(3):
            r = self.rand(r)
            rands[i] = self.crop(r)
        domain_length = (rands[0] * rands[1] + rands[2]) % 6 + 7
        self.domain = ""
        for i in range(domain_length):
            r = self.rand(r)
            ch = self.crop(r) % 26 + ord('a')
            self.domain += chr(ch)
        self.domain += "." + self.tlds[domain_nr % 4]
        return self.domain

    def get_domain(self):
        self._dga(self.nr*2, self.flag)
        if self.flag:
            self.flag = False
            self.nr += 1
        else:
            self.flag = True
        return self.domain
