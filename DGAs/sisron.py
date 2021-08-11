from datetime import timedelta
import base64


class DGA:
    shortname = "sisron"
    yara = None
    name = "Sisron malware"
    ref = ["https://johannesbader.ch/blog/the-dga-of-sisron/"]
    desc = "Sisron was part of a financial fraud and identity theft botnet."
    samples = 40
    lcg = False
    use_date = 1
    use_seed = False
    configs = [None]
    variation = "The entire domain except one of four TLDs."
    regex = "[a-z]{12}"
    ends = [".com", ".org", ".net", ".info"]

    def __init__(self, date=None, seed=None):
        self.date = date
        self.domain = None
        self.tlds = [x.encode('ascii') for x in [".com", ".org", ".net", ".info"]]
        self.nr = 0

    def _dga(self):
        date = self.date - timedelta(days=self.nr % 10)
        ds = date.strftime("%d%m%Y").encode('latin1')
        self.domain = base64.b64encode(ds).lower().replace(b"=", b"a") + self.tlds[self.nr // 10]
        self.domain = self.domain.decode('latin1')
        self.nr += 1

    def get_domain(self):
        self._dga()
        return self.domain
