import struct
import hashlib


class DGA:
    shortname = "newgoz"
    yara = "newgoz.yar"
    name = "Newgoz botnet"
    ref = ["https://johannesbader.ch/blog/the-dga-of-newgoz/",
           "https://umbrella.cisco.com/blog/at-high-noon-algorithms-do-battle"]
    desc = "Newgoz is a variant of the ZeuS Gameover (also known as Peer-to-Peer ZeuS), and this is a variant of the original ZeuS from 2012."
    samples = 0
    lcg = None
    use_date = 1
    use_seed = None
    configs = [None]
    variation = "Different domains and the tld is one of four possibilities."
    regex = "[a-z0-9]{22,28}"
    ends = ['.com', '.net', '.org', '.biz']

    def __init__(self, date=None, seed=None):
        self.date = date
        self.domain = None
        self.nr = 0

    def get_seed(self, seq_nr, date):
        key = "\x01\x05\x19\x35"
        seq_nr = struct.pack('<I', seq_nr)
        year = struct.pack('<H', date.year)
        month = struct.pack('<H', date.month)
        day = struct.pack('<H', date.day)
        m = hashlib.md5()
        m.update(seq_nr)
        m.update(year)
        m.update(key.encode('latin1'))
        m.update(month)
        m.update(key.encode('latin1'))
        m.update(day)
        m.update(key.encode('latin1'))
        return m.hexdigest()

    def generate_domain_part(self, seed, nr):
        part = []
        for i in range(nr - 1):
            edx = seed % 36
            seed //= 36
            if edx > 9:
                char = chr(ord('a') + (edx - 10))
            else:
                char = chr(edx + ord('0'))
            part += char
            if seed == 0:
                break
        part = part[::-1]
        return ''.join(part)

    def hex_to_int(self, seed):
        indices = range(0, 8, 2)
        data = [seed[x:x + 2] for x in indices]
        seed = ''.join(reversed(data))
        return int(seed, 16)

    def _dga(self):
        seed_value = self.get_seed(self.nr, self.date)
        self.domain = ""
        for i in range(0, 16, 4):
            seed = seed_value[i * 2:i * 2 + 8]
            seed = self.hex_to_int(seed)
            self.domain += self.generate_domain_part(seed, 8)
        if self.nr % 4 == 0:
            self.domain += ".com"
        elif self.nr % 3 == 0:
            self.domain += ".org"
        elif self.nr % 2 == 0:
            self.domain += ".biz"
        else:
            self.domain += ".net"
        self.nr += 1

    def get_domain(self):
        self._dga()
        return self.domain
