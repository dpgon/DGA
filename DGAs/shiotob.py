class DGA:
    shortname = "shiotob"
    yara = "shiotob.yar"
    name = "Shiotob malware"
    ref = ["https://johannesbader.ch/blog/the-dga-of-shiotob/",
           "https://inquest.net/blog/2019/03/09/Analyzing-Sophisticated-PowerShell-Targeting-Japan"]
    desc = "The Shiotob malware family steals user credentials - most notably information related to banking."
    samples = 0
    lcg = False
    use_date = False
    use_seed = "A domain with tld end (4ypv1eehphg3a.com by default)"
    configs = ['4ypv1eehphg3a.com', 'wtipubctwiekhir.net', 'n9oonpgabxe31.net', 'dogcurbctw.com']
    variation = "The entire domain except the .net or .com TLD."
    regex = "[a-z1-8]{10,15}"
    ends = ['.net', '.com']

    def __init__(self, date=None, seed='4ypv1eehphg3a.com'):
        self.domain = seed

    def sum_of_characters(self):
        return sum([ord(d) for d in self.domain[:-3]])

    def _dga(self):
        qwerty = 'qwertyuiopasdfghjklzxcvbnm123945678'
        sof = self.sum_of_characters()
        ascii_codes = [ord(d) for d in self.domain] + 100 * [0]
        old_hostname_length = len(self.domain) - 4
        for i in range(0, 66):
            for j in range(0, 66):
                edi = j + i
                if edi < 65:
                    p = (old_hostname_length * ascii_codes[j])
                    cl = p ^ ascii_codes[edi] ^ sof
                    ascii_codes[edi] = cl & 0xFF
        # calculate the new hostname length (max: 255/16 = 15, min: 10)
        cx = ((ascii_codes[2] * old_hostname_length) ^ ascii_codes[0]) & 0xFF
        hostname_length = int(cx / 16)  # at most 15
        if hostname_length < 10:
            hostname_length = old_hostname_length

        # generate hostname
        for i in range(hostname_length):
            index = int(ascii_codes[i] / 8)  # max 31 --> last 3 chars of qwerty unreachable
            bl = ord(qwerty[index])
            ascii_codes[i] = bl
        hostname = ''.join([chr(a) for a in ascii_codes[:hostname_length]])
        # append .net or .com (alternating)
        tld = '.com' if self.domain.endswith('.net') else '.net'
        self.domain = hostname + tld

    def get_domain(self):
        self._dga()
        return self.domain
