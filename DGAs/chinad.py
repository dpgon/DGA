import string
import hashlib


class DGA:
    shortname = "chinad"
    yara = "chinad.yar"
    name = "Chinad exploit kit"
    ref = ["https://github.com/360netlab/DGA/issues/1"]
    desc = "Chinad is an exploit kit thatcontrary to its counterparts, it is not used on mainstream websites or via malvertising attacks but rather it specifically targets Chinese websites and users."
    samples = 256
    lcg = False
    use_date = 1
    use_seed = False
    configs = [None]
    variation = "The entire domain except the TLD."
    regex = "[a-z0-9]{16}"
    ends = ['.com', '.org', '.net', '.biz', '.info', '.ru', '.cn']

    def __init__(self, date=None, seed=None):
        self.date = date
        self.domain = None
        self.generator = None

    def _dga(self):
        TLDS = ['.com', '.org', '.net', '.biz', '.info', '.ru', '.cn']
        alphanumeric = string.ascii_lowercase + string.digits
        """
            Chinad generates 1000 domains, but only 256 different domains possible
        """
        for nr in range(0x100):
            data = "{}{}{}{}".format(
                chr(self.date.year % 100),
                chr(self.date.month),
                chr(self.date.day),
                chr(nr)) + 12 * "\x00"

            h = hashlib.sha1(data.encode('latin1')).digest()
            h = ''.join(map(chr, h))
            h_le = []
            for i in range(5):
                for j in range(4):
                    h_le.append(h[i * 4 + (3 - j)])

            self.domain = ""
            for r in h_le[:16]:
                self.domain += alphanumeric[(ord(r) & 0xFF) % len(alphanumeric)]

            r = ord(h_le[-4])
            self.domain += TLDS[r % len(TLDS)]
            yield self.domain

    def get_domain(self):
        if self.generator:
            next(self.generator)
        else:
            self.generator = self._dga()
            next(self.generator)
        return self.domain
