class DGA:
    shortname = "locky2"
    yara = "locky.yar"
    name = "Locky v2 ransomware"
    ref = ["https://www.forcepoint.com/es/blog/x-labs/lockys-new-dga-seeding-new-domains-russia-update-26feb16",
           "https://blog.malwarebytes.com/threat-analysis/2016/03/look-into-locky/",
           "https://blogs.blackberry.com/en/2017/11/threat-spotlight-locky-ransomware"]
    desc = "Locky is ransomware malware released in 2016. It is delivered by email (that is allegedly an invoice requiring payment) with an attached Microsoft Word document that contains malicious macros."
    samples = 8
    lcg = False
    use_date = 2
    use_seed = "Seven possible seeds: 1 - 7 (1 by default)"
    configs = ['1', '2', '3', '4', '5', '6', '7']
    variation = "Different domains and the tld is one of fourteen possibilities."
    regex = "[a-y]{5,15}"
    ends = ['.ru', '.pw', '.eu', '.in', '.yt', '.pm', '.us', '.fr', '.de', '.it', '.be', '.uk', '.nl', '.tf']

    def __init__(self, date=None, seed='1'):
        self.date = date
        config = {
            1: {
                # md5: b28da1f2a5d889594a0e77e0853bcf29
                # sha256: 34bd23cbb9cf301ba444e1696694527ffc59edaba2bbbe25c4ac28a90df6f52a
                # sample: https://malwr.com/analysis/OTE2NzIwODkxMWUzNDBlNzhmNGZlMmFjY2ExOWEyZjQ/
                'seed': 62,
                'shift': 7,
                'mod': 8,
                'tlds': ['ru', 'pw', 'eu', 'in', 'yt', 'pm', 'us', 'fr', 'de',
                         'it', 'be', 'uk', 'nl', 'tf']
            },
            2: {
                # md5: e35bf0901f1a7db2b3752f85cd1bd044
                # sha256: 199a28336f5d3d8051754495741de1ad1bfa89919e6c44192ba34a3441d14c3d
                # sample: https://malwr.com/analysis/YjEyNWRhNTg0MzFiNDUwNzlkMmEyNjRmMzliNGMxODI/
                'seed': 75,
                'shift': 7,
                'mod': 8,
                'tlds': ['ru', 'pw', 'eu', 'in', 'yt', 'pm', 'us', 'fr', 'de',
                         'it', 'be', 'uk', 'nl', 'tf']
            },
            3: {
                # md5: 872018251970f0a739aa71d3cd313efa
                # sha256: 1a45085e959a449637a89174b1737f4d03d7e73dd7acfa3cfb96042a735cf400
                # sample:
                'seed': 9,
                'shift': 7,
                'mod': 8,
                'tlds': ['ru', 'pw', 'eu', 'in', 'yt', 'pm', 'us', 'fr', 'de',
                         'it', 'be', 'uk', 'nl', 'tf']
            },

            4: {
                # md5: 3f118d0b888430ab9f58fc2589207988
                # sha256: f927efd7cd2da3a052d857632f78ccf04b673e2774f6ce9a075e654dfd77d940
                # sample: https://malwr.com/analysis/N2M2YmFkMzY1MTY3NGIzZmJiNWMzZDU5ZDVhZjBlNjk/
                'seed': 7,
                'shift': 7,
                'mod': 8,
                'tlds': ['ru', 'pw', 'eu', 'in', 'yt', 'pm', 'us', 'fr', 'de',
                         'it', 'be', 'uk', 'nl', 'tf']
            },
            5: {
                # md5: 32e2c73ed8da34d87c64267936e632cb
                # sha256: d4dc820457bbc557b14ec0e58358646afbba70f4d5cab2276cdac8ce631a3854
                # sample: https://malwr.com/analysis/NjVkMTBlOTdhMjAwNDUxZTk2ZGFkMjc0OTQxNDBlMTk/
                'seed': 0,
                'shift': 5,
                'mod': 6,
                'tlds': ['ru', 'pw', 'eu', 'in', 'yt', 'pm', 'us', 'fr', 'de',
                         'it', 'be', 'uk', 'nl', 'tf']
            },
            6: {
                # md5: d2ea1565ae004368655edb5169b56a0f
                # sha256: 9b4b37cbb9845b093867675fb898330a8bd7ed087d587cba8cd21064c9a6e526
                # sample: https://sandbox.deepviz.com/report/hash/d2ea1565ae004368655edb5169b56a0f/
                'seed': 660,
                'shift': 7,
                'mod': 8,
                'tlds': ['ru', 'pw', 'eu', 'in', 'yt', 'pm', 'us', 'fr', 'de',
                         'it', 'be', 'uk', 'nl', 'tf']
            },
            7: {
                # md5: 69b933a694710f8ceb314dc897a94cbe
                # sha256: 07bed9baa42996bded75dacf5c2611ba5d3a3f19b8588ea734530f74c2586087
                # sample: https://malwr.com/analysis/MTM0ODY5N2VlOWQ1NGQ4YWFiNTI5ZGYxOWNlMTEwMWU/
                'seed': 555,
                'shift': 7,
                'mod': 8,
                'tlds': ['ru', 'pw', 'eu', 'in', 'yt', 'pm', 'us', 'fr', 'de',
                         'it', 'be', 'uk', 'nl', 'tf']
            }
        }
        try:
            self.seed = int(seed)
            self.c = config[self.seed]
        except:
            raise ValueError("unsupported seed {}".format(seed))
        self.c = config[self.seed]
        self.nr = 0
        self.domain = None

    def ror32(self, v, s):
        v &= 0xFFFFFFFF
        return ((v >> s) | (v << (32 - s))) & 0xFFFFFFFF

    def rol32(self, v, s):
        return ((v << s) | (v >> (32 - s))) & 0xFFFFFFFF

    def _dga(self):
        t = self.ror32(0xB11924E1 * (self.date.year + 0x1BF5), self.c['shift'])
        if self.c['seed']:
            t = self.ror32(0xB11924E1 * (t + self.c['seed'] + 0x27100001), self.c['shift'])
        t = self.ror32(0xB11924E1 * (t + (self.date.day // 2) + 0x27100001), self.c['shift'])
        t = self.ror32(0xB11924E1 * (t + self.date.month + 0x2709A354), self.c['shift'])
        nr = self.rol32(self.nr % self.c['mod'], 21)
        s = self.rol32(self.c['seed'], 17)
        r = (self.ror32(0xB11924E1 * (nr + t + s + 0x27100001), self.c['shift']) + 0x27100001) & 0xFFFFFFFF
        length = (r % 11) + 5
        self.domain = ""
        for i in range(length):
            r = (self.ror32(0xB11924E1 * self.rol32(r, i), self.c['shift']) + 0x27100001) & 0xFFFFFFFF
            self.domain += chr(r % 25 + ord('a'))
        self.domain += '.'
        r = self.ror32(r * 0xB11924E1, self.c['shift'])
        tlds = self.c['tlds']
        tld_i = ((r + 0x27100001) & 0xffffffff) % len(tlds)
        self.domain += tlds[tld_i]
        return self.domain

    def get_domain(self):
        self._dga()
        self.nr += 1
        return self.domain
