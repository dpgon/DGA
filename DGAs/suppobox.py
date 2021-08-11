import time
from datetime import datetime

class DGA:
    shortname = "suppobox"
    yara = "suppobox.yar"
    name = "Suppobox malware"
    ref = ["https://docs.huihoo.com/rsaconference/usa-2014/br-r01-end-to-end-analysis-of-a-domain-generating-algorithm-malware-family.pdf"]
    desc = "The malware Suppobox is a known Dictionary-based DGA. The malware that uses this is generally spammed out and contains an attachment with the malware that uses this DGA."
    samples = 85
    lcg = False
    use_date = 1
    use_seed = "A 1-3 option for the 3 wordlist files (1 by default)"
    configs = ['1', '2', '3']
    variation = "The entire domain except the .org TLD."
    regex = "[a-z]{12,28}"
    ends = ['.net']

    def __init__(self, date=None, seed='1'):
        with open(f"DGAs/wordlist/words{seed}.txt", "r") as r:
            self.words = [w.strip() for w in r.readlines()]
        self.domain = None
        datefmt = "%Y-%m-%d %H:%M:%S"
        self.date = date.strftime(datefmt)
        self.date = time.mktime(datetime.strptime(self.date, datefmt).timetuple())
        self.seed = int(self.date) >> 9

    def _dga(self):
        nr = self.seed
        res = 16 * [0]
        shuffle = [3, 9, 13, 6, 2, 4, 11, 7, 14, 1, 10, 5, 8, 12, 0]
        for i in range(15):
            res[shuffle[i]] = nr % 2
            nr = nr >> 1

        first_word_index = 0
        for i in range(7):
            first_word_index <<= 1
            first_word_index ^= res[i]

        second_word_index = 0
        for i in range(7, 15):
            second_word_index <<= 1
            second_word_index ^= res[i]
        second_word_index += 0x80

        first_word = self.words[first_word_index]
        second_word = self.words[second_word_index]
        tld = ".net"
        self.domain = f"{first_word}{second_word}{tld}"
        self.seed += 1

    def get_domain(self):
        self._dga()
        return self.domain
