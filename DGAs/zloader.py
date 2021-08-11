import struct
from datetime import datetime


class DGA:
    shortname = "zloader"
    yara = "zloader.yar"
    name = "Zloader malware"
    ref = ["https://johannesbader.ch/blog/the-dga-of-zloader/",
           "https://www.guidepointsecurity.com/blog/from-zloader-to-darkside-a-ransomware-story/",
           "https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/",
           "https://www.youtube.com/watch?v=QBoj6GB79wM",
           "https://int0xcc.svbtle.com/dissecting-obfuscated-deloader-malware"]
    desc = "Zloader, also known as Terdot, DELoader or Zeus Sphinx, is a malware from 2016 with some functions borrowed from Zeus malware."
    samples = 32
    lcg = False
    use_date = 1
    use_seed = "A string with hexadecimal numbers or base64 style data (q23Cud3xsNf3 by default)"
    configs = ["q23Cud3xsNf3", "41997b4a729e1a0175208305170752dd", "kZieCw23gffpe43Sd",
               "Ts72YjsjO5TghE6m", "03d5ae30a0bd934a23b6a7f0756aa504"]
    variation = "The entire domain except the .com TLD."
    regex = "[a-y]{20}"
    ends = ['.com']

    def __init__(self, date=None, seed='q23Cud3xsNf3'):
        self.date = date
        self.seed = seed
        self.domain = None
        self.seed = self.seeding(self.date, self.seed)
        self.r = self.seed

    def seeding(self, d, key):
        rc4 = RC4(key)
        d = d.replace(hour=0, minute=0, second=0)
        timestamp = int((d - datetime(1970, 1, 1)).total_seconds())
        p = struct.pack("<I", timestamp)
        c = rc4.encrypt(p)
        seed = struct.unpack("<I", c)[0]
        return seed

    def _dga(self):
        self.domain = ""
        for j in range(20):
            letter = ord('a') + (self.r % 25)
            self.domain += chr(letter)
            self.r = self.seed ^ ((self.r + letter) & 0xFFFFFFFF)
        self.domain += ".com"

    def get_domain(self):
        self._dga()
        return self.domain


class RC4:

    def __init__(self, key_s):
        key = [ord(k) for k in key_s]

        S = 256*[0]
        for i in range(256):
            S[i] = i

        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]

        self.S = S
        self.i = 0
        self.j = 0

    def prng(self):
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.S[self.i]) % 256
        self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
        K = self.S[(self.S[self.i] + self.S[self.j]) % 256]
        return K

    def encrypt(self, data):
        res = bytearray()
        for d in data:
            c = d ^ self.prng()
            res.append(c)
        return res

    def __str__(self):
        r = ""
        for i, s in enumerate(self.S):
            r += f"{i}: {hex(s)}\n"
        return r
