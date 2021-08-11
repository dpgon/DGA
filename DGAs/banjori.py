class DGA:
    shortname = "banjori"
    yara = "banjori.yar"
    name = "Banjori malware"
    ref = ["http://johannesbader.ch/2015/02/the-dga-of-banjori/"]
    desc = "The banking trojan Banjori, also known as MultiBanker 2 or BankPatch/BackPatcher. The DGA was active mostly between April and November of 2013."
    samples = 15372
    lcg = False
    use_date = False
    use_seed = "Domain as seed (earnestnessbiophysicalohax.com by default)"
    configs = ['caretallulahavaw.com', 'earnestnessbiophysicalohax.com']
    variation = "First 4 letters of the seed"
    regex = "[a-z]{4}"
    ends = ["estnessbiophysicalohax.com", "tallulahavaw.com"]

    def __init__(self, date=None, seed='earnestnessbiophysicalohax.com'):
        self.seed = seed  # default seed 15372 equal to 0 (seed = 0)
        self.domain = self.seed

    def _map_to_lowercase_letter(self, s):
        return ord('a') + ((s - ord('a')) % 26)

    def get_domain(self):
        dl = [ord(x) for x in list(self.domain)]
        dl[0] = self._map_to_lowercase_letter(dl[0] + dl[3])
        dl[1] = self._map_to_lowercase_letter(dl[0] + 2*dl[1])
        dl[2] = self._map_to_lowercase_letter(dl[0] + dl[2] - 1)
        dl[3] = self._map_to_lowercase_letter(dl[1] + dl[2] + dl[3])
        self.domain = ''.join([chr(x) for x in dl])
        return self.domain
