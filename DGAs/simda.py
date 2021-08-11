class DGA:
    shortname = "simda"
    yara = "simda.yar"
    name = "Simda backdoor"
    ref = ["https://johannesbader.ch/blog/the-dga-of-shiotob/",
           "https://www.youtube.com/watch?v=u2HEGDzd8KM",
           "https://secrary.com/ReversingMalware/iBank/"]
    desc = "Simda is the backdoor behind a botnet detected in 2015."
    samples = 5775  # period of 5776, 6438 in configs 1, 2
    lcg = False
    use_date = False
    use_seed = "A configuration from 6 options with a base data, a key, a tld and a lenght (1 by default)"
    configs = ['1', '2', '3', '4', '5', '6']
    variation = "The entire domain except the .com TLD."
    regex = "([a-z]{5}|[a-z]{7}|[a-z]{11})"
    ends = ['.com', '.eu', '.info']

    def __init__(self, date=None, seed='1'):
        self.domain = None
        self.seed = int(seed)
        configs = {1: {'base': 0x45AE94B2, 'key': '1676d5775e05c50b46baa5579d4fc7', 'tld': 'com', 'lenght': 7},
                   2: {'base': 0x45AE94B2, 'key': '1670cf21500911e1758e2b0dd5b4', 'tld': 'eu', 'lenght': 5},
                   3: {'base': 0x45AE94B2, 'key': '167cd47c0a09c9036d6097b754ab2e73', 'tld': 'info', 'lenght': 7},
                   4: {'base': 0x45AE94B2, 'key': '1670cf375493cf6d8889a9676ffc79', 'tld': 'info', 'lenght': 7},
                   5: {'base': 0x45AE94B2, 'key': '1670cf215403c56d8859a0636ffc74', 'tld': 'eu', 'lenght': 11},
                   6: {'base': 0x45AE94B2, 'key': '9670cf375493cf6d8889af67dffc7f', 'tld': 'info', 'lenght': 7}}
        self.length = configs[self.seed]['lenght']
        self.tld = configs[self.seed]['tld']
        self.key = configs[self.seed]['key']
        self.base = configs[self.seed]['base']
        self.step = 0
        for m in self.key:
            self.step += ord(m)

    def _dga(self):
        consonants = "qwrtpsdfghjklzxcvbnmv"    # Last V never used (21 letters an a mod 20 operation)
        vowels = "eyuioa"
        self.domain = ""
        self.base += self.step

        for i in range(self.length):
            index = int(self.base / (3 + 2 * i))
            if i % 2 == 0:
                char = consonants[index % 20]
            else:
                char = vowels[index % 6]
            self.domain += char
        self.domain += "." + self.tld

    def get_domain(self):
        self._dga()
        return self.domain
