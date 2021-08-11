import time
import hashlib
import base64


class DGA:
    shortname = "qsnatchb"
    yara = "qsnatch.yar"
    name = "Qsnatch B malware"
    ref = ["https://johannesbader.ch/blog/the-dga-of-qsnatch/",
           "https://www.kyberturvallisuuskeskus.fi/en/news/qsnatch-malware-designed-qnap-nas-devices"]
    desc = "QSnatch is a malware that infects QNAP NAS devices."
    samples = 150
    lcg = False
    use_date = 15
    use_seed = "Alphanumeric string case sensitive (IbjGOEgnuD by default)"
    configs = [None]
    variation = "Domain with one of thirty tld"
    regex = "[a-z0-9]{6,10}"
    ends = ['.cf', '.tk', '.ml', '.ga', '.gq', '.com', '.biz', '.org', '.de', '.rocks', '.mx', '.cn', '.top',
            '.nl', '.men', '.ws', '.se', '.info', '.xyz', '.net', '.today', '.ru', '.fi', '.name', '.to', '.in',
            '.com.ua', '.vg', '.vn', '.cd']

    def __init__(self, date=None, seed='IbjGOEgnuD'):
        self.tlds = ['cf', 'tk', 'ml', 'ga', 'gq', 'com', 'biz', 'org', 'de', 'rocks', 'mx', 'cn', 'top',
                     'nl', 'men', 'ws', 'se', 'info', 'xyz', 'net', 'today', 'ru', 'fi', 'name', 'to', 'in',
                     'com.ua', 'vg', 'vn', 'cd']
        self.seed = seed
        self.date = date
        self.domain = None
        self.generator = None

    def unix(self, date):
        unix = int(time.mktime(date.timetuple()))
        return unix

    def _dga(self):
        HOUR = 3600
        DAY = 24 * HOUR
        INTERVAL = 15 * DAY
        for tld in self.tlds:
            key = f"{self.unix(self.date) // INTERVAL}{self.seed}{tld}\n".encode('ascii')
            key_hash = hashlib.sha1(key).digest()
            key_hash_b64 = base64.b64encode(key_hash).decode('ascii')
            key_hash_b64_noeq_lc = key_hash_b64.rstrip("=").lower()
            trantab = str.maketrans("-+/", "abc")
            hostname_src = key_hash_b64_noeq_lc.translate(trantab)
            for hostname_len in range(6, 11):
                hostname = hostname_src[:hostname_len]
                self.domain = f"{hostname}.{tld}"
                yield self.domain

    def get_domain(self):
        if self.generator:
            next(self.generator)
        else:
            self.generator = self._dga()
            next(self.generator)
        return self.domain
