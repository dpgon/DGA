class DGA:
    shortname = "ranbyus2"
    yara = "ranbyus.yar"
    name = "Ranbyus trojan v2"
    ref = ["https://johannesbader.ch/blog/ranbyuss-dga-revisited/",
           "https://www.xylibox.com/2013/01/trojanwin32spyranbyus.html"]
    desc = "Ranbyus is a trojan that steals banking information — among other personal data."
    samples = 0
    lcg = False
    use_date = 1
    use_seed = "A string with an hexadecimal number (B6354BC3 by default)"
    configs = ['0F0D5BFA', 'F2C72B14', 'AE8714BE', 'CE7F8514', '572473BB', '17794CF1',
               'C0E32524', '7CB7966E', '9F90C9E7', '8FB8879B', 'E981684B']
    variation = "The entire domain except one of nine TLDs."
    regex = "[a-y]{17}"
    ends = [".in", ".me", ".cc", ".su", ".tw", ".net", ".com", ".pw", ".org"]

    def __init__(self, date=None, seed='0F0D5BFA'):
        self.day = date.day
        self.month = date.month
        self.year = date.year
        self.seed = int(seed, 16)
        if self.seed == 0xCE7F8514:
            self.tlds = ["in", "net", "org", "com", "me", "su", "tw", "cc", "pw"]
        else:
            self.tlds = ["in", "me", "cc", "su", "tw", "net", "com", "pw", "org"]   # org never used
        self.tld_index = self.day
        self.domain = None
        self.x = (self.day * self.month * self.year) ^ self.seed

    def to_little_array(self, val):
        a = 4 * [0]
        for i in range(4):
            a[i] = (val & 0xFF)
            val >>= 8
        return a

    def pcg_random(self, r):
        alpha = 0x5851F42D4C957F2D
        inc = 0x14057B7EF767814F
        step1 = alpha * r + inc
        step2 = alpha * step1 + inc
        step3 = alpha * step2 + inc
        tmp = (step3 >> 24) & 0xFFFFFF00 | (step3 & 0xFFFFFFFF) >> 24
        a = (tmp ^ step2) & 0x000FFFFF ^ step2
        b = (step2 >> 32)
        c = (step1 & 0xFFF00000) | ((step3 >> 32) & 0xFFFFFFFF) >> 12
        d = (step1 >> 32) & 0xFFFFFFFF
        data = 32 * [None]
        data[0:4] = self.to_little_array(a)
        data[4:8] = self.to_little_array(b)
        data[8:12] = self.to_little_array(c)
        data[12:16] = self.to_little_array(d)
        return step3 & 0xFFFFFFFFFFFFFFFF, data

    def _dga(self):
        random = 32 * [None]
        self.x, random[0:16] = self.pcg_random(self.x)
        self.x, random[16:32] = self.pcg_random(self.x)
        self.domain = ""
        for i in range(17):
            self.domain += chr(random[i] % 25 + ord('a'))
        self.domain += '.' + self.tlds[self.tld_index % (len(self.tlds) - 1)]
        self.tld_index += 1

    def get_domain(self):
        self._dga()
        return self.domain
