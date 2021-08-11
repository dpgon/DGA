from ctypes import c_uint


class DGA:
    shortname = "ranbyus1"
    yara = "ranbyus.yar"
    name = "Ranbyus trojan"
    ref = ["https://johannesbader.ch/blog/the-dga-of-ranbyus/",
           "https://www.xylibox.com/2013/01/trojanwin32spyranbyus.html"]
    desc = "Ranbyus is a trojan that steals banking information — among other personal data."
    samples = 0
    lcg = False
    use_date = 1
    use_seed = "A string with an hexadecimal number (B6354BC3 by default)"
    configs = ['C5F128F3', 'B6354BC3', '65BA0743', '0478620C']
    variation = "The entire domain except one of nine TLDs."
    regex = "[a-y]{14}"
    ends = [".in", ".me", ".cc", ".su", ".tw", ".net", ".com", ".pw"]

    def __init__(self, date=None, seed='B6354BC3'):
        self.day = c_uint()
        self.day.value = date.day
        self.month = c_uint()
        self.month.value = date.month
        self.year = c_uint()
        self.year.value = date.year
        self.seed = c_uint()
        self.seed.value = int(seed, 16)
        self.tlds = ["in", "me", "cc", "su", "tw", "net", "com", "pw", "org"]   # org never used
        self.tld_index = self.day.value
        self.domain = None
        self.nr = 0

    def _dga(self):
        self.domain = ""
        for i in range(14):
            self.day.value = (self.day.value >> 15) ^ 16 * (self.day.value & 0x1FFF ^ 4 * (self.seed.value ^ self.day.value))
            self.year.value = (((self.year.value & 0xFFFFFFF0) << 17) & 0xFFFFFFFF) ^ (((self.year.value ^ (7 * self.year.value)) & 0xFFFFFFFF) >> 11)
            self.month.value = 14 * (self.month.value & 0xFFFFFFFE) ^ (((self.month.value ^ (4 * self.month.value)) & 0xFFFFFFFF) >> 8)
            self.seed.value = (self.seed.value >> 6) ^ ((self.day.value + 8 * self.seed.value) << 8) & 0x3FFFF00
            self.domain += chr(((self.day.value ^ self.month.value ^ self.year.value) % 25) + 97)
        self.domain += "." + self.tlds[self.tld_index % 8]
        self.tld_index += 1

    def get_domain(self):
        self._dga()
        return self.domain
