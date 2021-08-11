import struct
import time


class DGA:
    shortname = "pykspa1"
    yara = "pykspa.yar"
    name = "Pykspa worm"
    ref = ["https://johannesbader.ch/blog/the-dga-of-pykspa/",
            "https://www.youtube.com/watch?v=HfSQlC76_s4"]
    desc = "Pykspa, also known as Pykse, Skyper or SkypeBot, is a worm that spreads via Skype."
    samples = 0
    lcg = "Special variable LCG"
    use_date = 1
    use_seed = "Two modes: 1 (default) to do useful dga, or 2 to noise dga."
    configs = [None]
    variation = "Different domains and the tld is one of five possibilities."
    regex = "[a-z]{6,12}"
    ends = ['.com', '.net', '.org', '.info', '.cc']

    def __init__(self, date=None, seed="1"):
        self.date = date
        self.seed = int(seed)
        self.nr = 0
        self.domain = None
        self.generator = None
        self.tlds = ['com', 'net', 'org', 'info', 'cc']

    def hash(self, nr):
        data = struct.pack("<I", nr)
        return md6hash().hex(data)

    def seeding(self, nr):

        MASK = 0xFFFFFFFF

        def lcg_random(values, index, result):
            LCG_MULT = 22695477
            v = values[index]
            v *= LCG_MULT
            v &= MASK
            v += 1
            v &= MASK
            values[index] = v

            a = (v >> 16)
            a &= 0x7FFF
            shift = result & 0xF
            a += result
            a &= MASK
            result = lrotl(a, shift)
            return result

        def lcg_random_rounds(values, result=0):
            for index in range(size):
                for r in range(index + 1):
                    result = lcg_random(values, index, result)
            return result

        def xor_encryption(values, key, result):
            for index in range(len(values)):
                result = lcg_random(values, index, result)
            nkey = key ^ (result & 0xFF)
            result += key
            result &= MASK
            values[-1] = ((values[-1] + key) & MASK)
            return nkey, result

        def lrotl(value, shift):
            overflow = ((value << shift) >> 32) & MASK
            value = (value << shift)
            value += overflow
            value &= MASK
            return value

        def transform(seed_padded, values, result, rounds, offset=0):
            index = offset
            while rounds:
                if index >= len(seed_padded):
                    index = 0
                key = seed_padded[index]
                nkey, result = xor_encryption(values, key, result)
                nkey ^= key
                seed_padded[index] = nkey
                index += 1
                rounds -= 1
            return result

        seed = self.hash(nr)
        tuples = [seed[i:i + 2] for i in range(0, len(seed), 2)]

        values = []
        for t in tuples:
            v = ord(t[0]) * 256 + ord(t[1])
            values.append(v)

        size = 0x80
        while len(values) < size:
            values.append(0)

        result = lcg_random_rounds(values)

        seed_padded = bytearray()
        for i in range(0x100):
            if i < len(seed):
                seed_padded.append(ord(seed[i]))
            else:
                seed_padded.append(0)

        numerator = len(seed_padded)
        result = transform(seed_padded, values, result, rounds=numerator)
        numerator = (numerator + 1) * 10
        result = transform(seed_padded, values, result, rounds=numerator, offset=len(seed_padded) - 1)

        values = []
        for i in range(0, len(seed_padded), 2):
            values.append(seed_padded[i] * 256 + seed_padded[i + 1])

        result = lcg_random_rounds(values)
        offset = nr % 50
        key_string = seed[offset:offset + 4]

        seed = 0
        for i, key in enumerate(key_string):
            key = ord(key)
            nkey, result = xor_encryption(values, key, result)
            seed += (nkey << (i * 8))

        return seed

    def get_sld(self, length, seed):
        sld = ""
        modulo = 541 * length + 4
        a = length * length
        for i in range(length):
            index = (a + (seed * ((seed % 5) + (seed % 123456) +
                                  i * ((seed & 1) + (seed % 4567))) & 0xFFFFFFFF)) % 26
            a += length
            a &= 0xFFFFFFFFF
            sld += chr(ord('a') + index)
            seed += (((7837632 * seed * length) & 0xFFFFFFFF) + 82344) % modulo
        return sld

    def _dga(self):
        dt = time.mktime(self.date.timetuple())
        days = 20 if self.seed == 1 else 1
        index = int(dt // (days * 3600 * 24))

        seed = self.seeding(index)

        while True:
            # determine next seed
            s = seed % (self.nr + 1)
            seed += (s + 1)

            # second level length
            length = (seed + self.nr) % 7 + 6

            # get second level domain
            second_level_domain = self.get_sld(length, seed)

            # get first level domain
            top_level_domain = self.tlds[(seed & 3)]

            # concatenate and print domain
            self.domain = second_level_domain + '.' + top_level_domain
            self.nr += 1
            yield self.domain

    def get_domain(self):
        if self.generator:
            next(self.generator)
        else:
            self.generator = self._dga()
            next(self.generator)
        return self.domain


class md6hash():
    def __to_word(self, i_byte):
        length = len(i_byte)
        o_word = []

        for i in range(0, length, 8):
            o_word.append(
                ((i_byte[i + 0] & 0xff) << 56) |
                ((i_byte[i + 1] & 0xff) << 48) |
                ((i_byte[i + 2] & 0xff) << 40) |
                ((i_byte[i + 3] & 0xff) << 32) |
                ((i_byte[i + 4] & 0xff) << 24) |
                ((i_byte[i + 5] & 0xff) << 16) |
                ((i_byte[i + 6] & 0xff) << 8) |
                ((i_byte[i + 7] & 0xff) << 0)
            )

        return o_word

    def __from_word(self, i_word):
        length = len(i_word)
        o_byte = []

        for i in range(length):
            o_byte.append((i_word[i] >> 56) & 0xff)
            o_byte.append((i_word[i] >> 48) & 0xff)
            o_byte.append((i_word[i] >> 40) & 0xff)
            o_byte.append((i_word[i] >> 32) & 0xff)
            o_byte.append((i_word[i] >> 24) & 0xff)
            o_byte.append((i_word[i] >> 16) & 0xff)
            o_byte.append((i_word[i] >> 8) & 0xff)
            o_byte.append((i_word[i] >> 0) & 0xff)

        return o_byte

    def __crop(self, size, data, right):
        length = int((size + 7) / 8)
        remain = size % 8

        if right:
            data = data[len(data) - length:]
        else:
            data = data[:length]

        if remain > 0:
            data[length - 1] &= (0xff << (8 - remain)) & 0xff

        return data

    def __hash(self, size, data, key, levels):
        b = 512
        c = 128
        n = 89
        d = size
        M = data

        K = key[:64]
        k = len(K)

        while len(K) < 64:
            K.append(0x00)

        K = self.__to_word(K)

        r = max(80 if k else 0, 40 + int(d / 4))

        L = levels
        ell = 0

        S0 = 0x0123456789abcdef
        Sm = 0x7311c2812425cfa0

        Q = [
            0x7311c2812425cfa0, 0x6432286434aac8e7, 0xb60450e9ef68b7c1,
            0xe8fb23908d9f06f1, 0xdd2e76cba691e5bf, 0x0cd0d63b2c30bc41,
            0x1f8ccf6823058f8a, 0x54e5ed5b88e3775d, 0x4ad12aae0a6d6031,
            0x3e7f16bb88222e0d, 0x8af8671d3fb50c2c, 0x995ad1178bd25c31,
            0xc878c1dd04c4b633, 0x3b72066c7a1552ac, 0x0d6f3522631effcb
        ]

        t = [17, 18, 21, 31, 67, 89]
        rs = [10,  5, 13, 10, 11, 12,  2,  7, 14, 15,  7, 13, 11,  7,  6, 12]
        ls = [11, 24,  9, 16, 15,  9, 27, 15,  6,  2, 29,  8, 15,  5, 31,  9]

        def f(N):
            S = S0
            A = list(N)

            j = 0
            i = n

            while j < r:
                for s in range(16):
                    x = S
                    x ^= A[i + s - t[5]]
                    x ^= A[i + s - t[0]]
                    x ^= A[i + s - t[1]] & A[i + s - t[2]]
                    x ^= A[i + s - t[3]] & A[i + s - t[4]]
                    x ^= x >> rs[s]

                    if len(A) <= i + s:
                        while len(A) <= i + s:
                            A.append(0x00)

                    A[i + s] = x ^ ((x << ls[s]) & 0xffffffffffffffff)

                S = (((S << 1) & 0xffffffffffffffff) ^ (S >> 63)) ^ (S & Sm)

                j += 1
                i += 16

            return A[(len(A) - 16):]

        def mid(B, C, i, p, z):
            U = ((ell & 0xff) << 56) | i & 0xffffffffffffff
            V = ((r & 0xfff) << 48) | ((L & 0xff) << 40) | ((z & 0xf) << 36) | (
                (p & 0xffff) << 20) | ((k & 0xff) << 12) | (d & 0xfff)

            return f(Q + K + [U, V] + C + B)

        def par(M):
            P = 0
            B = []
            C = []
            z = 0 if len(M) > b else 1

            while len(M) < 1 or (len(M) % b) > 0:
                M.append(0x00)
                P += 8

            M = self.__to_word(M)

            while len(M) > 0:
                B.append(M[:int(b / 8)])
                M = M[int(b / 8):]

            i = 0
            p = 0
            l = len(B)

            while i < l:
                p = P if i == (len(B) - 1) else 0
                C += mid(B[i], [], i, p, z)

                i += 1
                p = 0

            return self.__from_word(C)

        def seq(M):
            P = 0
            B = []
            C = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]

            while len(M) < 1 or (len(M) % (b - c)) > 0:
                M.append(0x00)
                P += 8

            M = self.__to_word(M)

            while len(M) > 0:
                B.append(M[:int((b - c) / 8)])
                M = M[int((b - c) / 8):]

            i = 0
            p = 0
            l = len(B)

            while i < l:
                p = P if i == (len(B) - 1) else 0
                z = 1 if i == (len(B) - 1) else 0
                C = mid(B[i], C, i, p, z)

                i += 1
                p = 0

            return self.__from_word(C)

        while True:
            ell += 1
            M = seq(M) if ell > L else par(M)

            if len(M) == c:
                break

        return self.__crop(d, M, True)

    def __bytes(self, b):
        o_byte = list(b)
        return o_byte

    def __prehash(self, data, size, key, levels):
        data = self.__bytes(data)
        key = self.__bytes(key)

        if size <= 0:
            size = 1
        elif size > 512:
            size = 512

        return self.__hash(size, data, key, levels)

    def hex(self, data=b"", size=256, key="", levels=64):
        byte = self.__prehash(data, size, key, levels)
        hexstr = ""

        for i in byte:
            hexstr += "%02x" % i

        return hexstr

    def raw(self, data=b"", size=256, key="", levels=64):
        byte = self.__prehash(data, size, key, levels)
        rawstr = ""
        return bytes(byte)
