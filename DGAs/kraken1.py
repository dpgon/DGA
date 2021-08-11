from ctypes import c_int, c_uint

class DGA:
    shortname = "kraken1"
    yara = "kraken.yar"
    name = "Kraken v1 botnet"
    ref = ["https://johannesbader.ch/blog/krakens-two-domain-generation-algorithms/",
           "https://www.bleepingcomputer.com/news/security/kraken-cryptor-ransomware-masquerading-as-superantispyware-security-program/",
           "https://blog.gdatasoftware.com/blog/article/dissecting-the-kraken.html"]
    desc = "Kraken (also known as Oderoor or Bobax) was a botnet primarily used to send spam messages."
    samples = 0
    lcg = "n = 1103515245 * n + 12435"
    use_date = False
    use_seed = "Two possible seeds: a, b (a by default)"
    configs = ['a', 'b']
    variation = "The subdomain. The main domain and the TLD remain the same, one of four possibilities ."
    regex = "[a-z]{6,11}"
    ends = [".dyndns.org", ".yi.org", ".dynserv.com", ".mooo.com"]

    def __init__(self, date=None, seed='a'):
        seeds = {'a': {'ex': -0x0FCFBF88, 'nex': 0x8924541},
                 'b': {'ex': -0x1FCFBF87, 'nex': 0x7924542}}
        if seed == 'a':
            self.seed = seeds['a']
        elif seed == 'b':
            self.seed = seeds['b']
        else:
            raise ValueError("unsupported seed {}".format(seed))
        self.tlds = ["dyndns.org", "yi.org", "dynserv.com", "mooo.com"]
        self.domain = None
        self.nr = 0
        self.flag = False

    def rand(self, r):
        t = c_int(1103515245 * r + 12435).value
        return t

    def crop(self, r):
        return (r // 256) % 32768

    def _dga(self, index, temp_file=True):
        domain_nr = int(index / 2) + 1000015

        if temp_file:
            x = int(c_int(domain_nr * (domain_nr + 7) * (domain_nr + 12)).value / 9.0)
            y = domain_nr * (domain_nr + 1)
            r = c_int(x + y + self.seed['ex']).value
        else:
            x = int(c_int((domain_nr + 2) * (domain_nr + 7) * domain_nr).value / 9.0)
            y = (domain_nr * 3 + 1) * domain_nr
            r = c_int(x + y + self.seed['nex']).value

        rands = 3 * [0]
        for i in range(3):
            r = self.rand(r)
            rands[i] = self.crop(r)
        domain_length = (rands[0] * rands[1] - rands[2]) % 6 + 6
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
