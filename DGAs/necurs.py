class DGA:
    shortname = "necurs"
    yara = "necurs.yar"
    name = "Necurs rootkit"
    ref = ["https://johannesbader.ch/blog/the-dgas-of-necurs/",
           "https://www.blueliv.com/wp-content/uploads/2018/07/Blueliv-Necurs-report-2017.pdf",
           "https://www.shadowserver.org/news/has-the-sun-set-on-the-necurs-botnet/"]
    desc = "Necurs is a malware that opens a backdoor on infected systems. This rootkit is composed of a kernel-mode driver and a user-mode component."
    samples = 2048
    lcg = None
    use_date = 4
    use_seed = "String with a integer number. (9 by default)"
    configs = [None]
    variation = "Different domains and the tld is one of fourtythree possibilities."
    regex = "[a-y]{7,21}"
    ends = ['.tj', '.in', '.jp', '.tw', '.ac', '.cm', '.la', '.mn', '.so', '.sh', '.sc', '.nu', '.nf', '.mu',
            '.ms', '.mx', '.ki', '.im', '.cx', '.cc', '.tv', '.bz', '.me', '.eu', '.de', '.ru', '.co', '.su', '.pw',
            '.kz', '.sx', '.us', '.ug', '.ir', '.to', '.ga', '.com', '.net', '.org', '.biz', '.xxx', '.pro', '.bit']

    def __init__(self, date=None, seed="9"):
        self.date = date
        try:
            self.seed = int(seed)
        except:
            raise ValueError("Incorrect seed: {}".format(seed))
        self.tlds = ['tj', 'in', 'jp', 'tw', 'ac', 'cm', 'la', 'mn', 'so', 'sh', 'sc', 'nu', 'nf', 'mu',
                'ms', 'mx', 'ki', 'im', 'cx', 'cc', 'tv', 'bz', 'me', 'eu', 'de', 'ru', 'co', 'su', 'pw',
                'kz', 'sx', 'us', 'ug', 'ir', 'to', 'ga', 'com', 'net', 'org', 'biz', 'xxx', 'pro', 'bit']
        self.domain = None
        self.nr = 0

    def pseudo_random(self, value):
        loops = (value & 0x7F) + 21
        for index in range(loops):
            value += ((value * 7) ^ (value << 15)) + 8 * index - (value >> 5)
            value &= ((1 << 64) - 1)
        return value

    def mod64(self, nr1, nr2):
        return nr1 % nr2

    def _dga(self):
        n = self.pseudo_random(self.date.year)
        n = self.pseudo_random(n + self.date.month + 43690)
        n = self.pseudo_random(n + (self.date.day >> 2))
        n = self.pseudo_random(n + self.nr)
        n = self.pseudo_random(n + self.seed)
        domain_length = self.mod64(n, 15) + 7

        self.domain = ""
        for i in range(domain_length):
            n = self.pseudo_random(n + i)
            ch = self.mod64(n, 25) + ord('a')
            self.domain += chr(ch)
            n += 0xABBEDF
            n = self.pseudo_random(n)

        tld = self.tlds[self.mod64(n, 43)]
        self.domain += '.' + tld
        self.nr += 1

    def get_domain(self):
        self._dga()
        return self.domain
