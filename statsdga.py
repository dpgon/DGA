import nltk
import numpy as np
import dga
from datetime import datetime, timedelta
from nltk.tokenize import LegalitySyllableTokenizer
from nltk.corpus import brown
from ngram import ngrams


try:
    brown.words
except:
    nltk.download('brown')


def vcrel(domain, percentage=True):
    domain = domain.lower()
    v = 0
    c = 0
    for letter in domain:
        if letter in 'zxcvbnmsdfghjklqwrtp':
            c += 1
        if letter == 'a' or letter == 'e' or letter == 'i' or letter == 'o' or letter == 'u' or letter == 'y':
            v += 1
    if percentage:
        if (c+v) > 0:
            return v/(c+v)
        else:
            return None
    else:
        return v


def numrel(domain, percentage=True):
    v = 0
    for letter in domain:
        if letter.isdigit():
            v += 1
    if percentage:
        return v/len(domain)
    else:
        return v


def statmax(malware, date, nr, seed):
    print(dga.Col.INFO + f"* Calculating max number of samples for: {' - '.join(malware)}" + dga.Col.END)
    if not date:
        date = datetime.now()
    for name in malware:
        for config in dga.configs(name):
            if seed:
                max = dga.generate([name], date, nr, seed, limit=False)
            elif config:
                max = dga.generate([name], date, nr, config, limit=False)
            else:
                max = dga.generate([name], date, nr, None, limit=False)
            if max < nr:
                if seed:
                    print(f"* Family {name} with seed {seed} has a limit of {max} domains in a date")
                elif config:
                    print(f"* Family {name} with config {config} has a limit of {max} domains in a date")
                else:
                    print(f"* Family {name} has a limit of {max} domains in a date")
            else:
                if seed:
                    print(f"* Family {name} with seed {seed} has no limit ({nr} checked)")
                elif config:
                    print(f"* Family {name} with config {config} has no limit ({nr} checked)")
                else:
                    print(f"* Family {name} has no limit ({nr} checked)")


def collision(malware, date, nr, seed):
    print(dga.Col.INFO + f"* Calculating max number of samples for: {' - '.join(malware)}" + dga.Col.END)
    if not date:
        date = datetime.now()
    for name in malware:
        for config in dga.configs(name):
            if seed:
                domains = dga.generate([name], date, nr, seed, limit=True)
            elif config:
                domains = dga.generate([name], date, nr, config, limit=True)
            else:
                domains = dga.generate([name], date, nr, None, limit=True)
            domuniq = set(domains)
            if len(domuniq) != len(domains):
                print(f"* Family {name}: {len(domains)} generated and {len(domuniq)} unique")
                more = False
                for counter in range(1000):
                    domain = domains[counter]
                    others = domains[counter+1:]
                    for c, rep in enumerate(others):
                        if domain == rep:
                            if seed:
                                print(f"* Family {name} with seed {seed} has repeated the domain {domain} in pos {c}")
                            elif config:
                                print(f"* Family {name} with config {config} has repeated the domain {domain} in pos {c}")
                            else:
                                print(f"* Family {name} has repeated the domain {domain} in pos {c}")
                            more = True
                            break
                    if more:
                        break


def doublel(malware, date, nr):
    if not date:
        date = datetime.now()
    if not malware:
        with open("DGAs/wordlist/top-1m.csv") as f:
            topdomains = f.readlines()
            topdomains = topdomains[:nr * len(dga.listall())]
    else:
        topdomains = dga.create(malware, date, nr, None, short=True)

    data = {}
    for c, domain in enumerate(topdomains):
        if not malware:
            fulldomain = domain.split(',')[1]
            domain = fulldomain.split('.')[0]
        else:
            domain = domain.split('.')[0]

        double = 0
        for c, letter in enumerate(domain):
            if c > 0 and letter == domain[c-1]:
                double += 1
        if double in data:
            data[double] += 1
        else:
            data[double] = 1
    total = 0
    for item in data:
        total += data[item]
    temp = list(data)
    temp.sort()
    for item in temp:
        print(f"  |__ {data[item]} repeated {item} times ({data[item] / total:0.03f})")


def repeatedl(malware, date, nr):
    if not date:
        date = datetime.now()
    if not malware:
        with open("DGAs/wordlist/top-1m.csv") as f:
            topdomains = f.readlines()
            topdomains = topdomains[:nr * len(dga.listall())]
    else:
        topdomains = dga.create(malware, date, nr, None, short=True)

    data = {}
    for c, domain in enumerate(topdomains):
        if not malware:
            fulldomain = domain.split(',')[1]
            domain = fulldomain.split('.')[0]
        else:
            domain = domain.split('.')[0]

        used = []
        repeated = 0
        for c, letter in enumerate(domain):
            if letter in used:
                repeated += 1
            else:
                used.append(letter)
        if repeated in data:
            data[repeated] += 1
        else:
            data[repeated] = 1
    total = 0
    for item in data:
        total += data[item]
    temp = list(data)
    temp.sort()
    for item in temp:
        print(f"  |__ {data[item]} times {item} letters are repeated ({data[item] / total:0.03f})")


def ratiovc(malware, date, nr, numbers=False):
    if not date:
        date = datetime.now()
    if not malware:
        with open("DGAs/wordlist/top-1m.csv") as f:
            topdomains = f.readlines()
            topdomains = topdomains[:nr * len(dga.listall())]
    else:
        topdomains = dga.create(malware, date, nr, None, short=True)

    data = {}
    for c, domain in enumerate(topdomains):
        if not malware:
            fulldomain = domain.split(',')[1]
            domain = fulldomain.split('.')[0]
        else:
            domain = domain.split('.')[0]

        if numbers:
            ratio = numrel(domain)
        else:
            ratio = vcrel(domain)
        if ratio is not None:
            ratio = f"{ratio:0.1f}"
            if ratio in data:
                data[ratio] += 1
            else:
                data[ratio] = 1
    total = 0
    for item in data:
        total += data[item]
    temp = list(data)
    temp.sort()
    for item in temp:
        print(f"  |__ Ratio {item} repeated {data[item]} times ({data[item] / total:0.03f})")


def syll(malware, date, nr):
    if not date:
        date = datetime.now()
    if not malware:
        with open("DGAs/wordlist/top-1m.csv") as f:
            topdomains = f.readlines()
            topdomains = topdomains[:nr * len(dga.listall())]
    else:
        topdomains = dga.create(malware, date, nr, None, short=True)

    LP = LegalitySyllableTokenizer(brown.words())
    averagesize = 0
    maxsize = 0
    minsize = 0
    for domain in topdomains:
        if not malware:
            fulldomain = domain.split(',')[1]
            domain = fulldomain.split('.')[0]
        else:
            domain = domain.split('.')[0]

        sil = LP.tokenize(domain)
        averagesize += len(domain) // len(sil)
        m = 0
        for item in sil:
            if len(item) > m:
                m = len(item)
        maxsize += m
        m = 64
        for item in sil:
            if len(item) < m:
                m = len(item)
        minsize += m
    averagesize /= len(topdomains)
    maxsize /= len(topdomains)
    minsize /= len(topdomains)

    print(f"  |__ Average syllable lenght is {averagesize}")
    print(f"  |__ Min syllable lenght is {minsize}")
    print(f"  |__ Max syllable lenght is {maxsize}")


def calcngram(malware, ng):
    if not malware:
        with open("DGAs/wordlist/top-1m.csv") as f:
            domains = f.readlines()
            domains = domains[:2000]
    else:
        domains = dga.create(malware, datetime.now(), 2000, None, short=True)

    for l in range(1, 5):
        total = 0
        mmean = 0
        mmedian = 0
        mstd = 0
        for domain in domains:
            mean, median, std = ng.getall(domain, l)
            if mean:
                total += 1
                mmean += mean
                mmedian += median
                mstd += std
        mmean /= total
        mmedian /= total
        mstd /= total
        print(f"  |__ {l}-gram __ Mean: {mmean} - Median: {mmedian} - Std.Dev.: {mstd}")


def statvowels(malware, date, nr, seed):
    print(dga.Col.INFO + f"* Calculating vowels/consonants correlation" + dga.Col.END)
    ret = []
    for name in malware:
        for config in dga.configs(name):
            remain = nr
            tempdate = date
            domains = []
            while remain:
                if dga.samples(name) == 0 or dga.samples(name) > remain:
                    max = remain
                else:
                    max = dga.samples(name)
                if seed:
                    domains.extend(dga.generate([name], tempdate, max, seed))
                else:
                    domains.extend(dga.generate([name], tempdate, max, config))
                remain -= max
                if remain and dga.use_date(name):
                    tempdate -= timedelta(dga.use_date(name))

            vc = [name, config]
            for domain in domains:
                vc.append(vcrel(domain.split('.')[0]))
            ret.append(vc)
    return ret


def statletters(malware, date, nr, seed):
    print(dga.Col.INFO + f"* Calculating chars used" + dga.Col.END)
    ret = []
    for name in malware:
        vc = {'.tlds': []}
        minlen = 64
        maxlen = 0
        for config in dga.configs(name):
            remain = nr
            tempdate = date
            domains = []
            while remain:
                if dga.samples(name) == 0 or dga.samples(name) > remain:
                    max = remain
                else:
                    max = dga.samples(name)
                if seed:
                    domains.extend(dga.generate([name], tempdate, max, seed))
                else:
                    domains.extend(dga.generate([name], tempdate, max, config))
                remain -= max
                if remain and dga.use_date(name):
                    tempdate -= timedelta(dga.use_date(name))

            for domain in domains:
                sld = domain.split('.')[0]
                tld = '.'.join(domain.split('.')[1:])
                for letter in sld:
                    if letter in vc:
                        vc[letter] += 1
                    else:
                        vc[letter] = 1
                if tld not in vc['.tlds']:
                    vc['.tlds'].append(tld)
                if len(sld) > maxlen:
                    maxlen = len(sld)
                if len(sld) < minlen:
                    minlen = len(sld)

        reglet = ""
        newreg = ""
        temp = ""
        for key in sorted(vc):
            if len(key) == 1:
                reglet += key
        for c, n in enumerate(reglet):
            if c == 0:
                newreg += n + "-"
                temp = ord(n)
            elif ord(n) == temp + 1:
                temp += 1
            else:
                newreg += chr(temp) + n + "-"
                temp = ord(n)
        newreg += chr(temp)
        final = ''
        for c, n in enumerate(newreg):
            if n == "-":
                if newreg[c - 1] == newreg[c + 1]:
                    final += newreg[c - 1]
                else:
                    final += newreg[c - 1:c + 2]
        if "-" in reglet or len(reglet) < len(final):
            vc['.regexp'] = f"[{reglet}]{{{minlen},{maxlen}}}"
        else:
            vc['.regexp'] = f"[{final}]{{{minlen},{maxlen}}}"

        vc['.name'] = name
        vc['.minlen'] = minlen
        vc['.maxlen'] = maxlen
        ret.append(vc)
    return ret


def printserie(serie, data=None, header=False, percentage=True, name=None):
    if percentage and not header:
        serie = serie.astype('float64')
        total = 0
        for item in serie:
            total += item
        for c, item in enumerate(serie):
            serie[c] = float(item*100/total)

    for item in serie:
        if header:
            print(f"{item:.2f}     ", end='')
        elif percentage:
            print(f" |{item:7.2f}", end='')
        else:
            print(f" |{item:^7d}", end='')
    if header:
        print("")
    else:
        q75, median, q25 = np.percentile(data, [75, 50, 25])
        iqr = q75 - q25
        atip_low = q25 - iqr * 1.5
        if atip_low < 0:
            atip_low = 0
        atip_high = q75 + iqr * 1.5
        if name:
            print(f" |   {name:14} - Rango tipico: {atip_low:.2f} - {atip_high:.2f} ({median:.2f}) "
                  f"TOTAL: {len(data)} - Non Zero: {np.count_nonzero(data)} - Atipical: ",
                  np.count_nonzero((data > atip_high) | (data < atip_low)))
        else:
            print(f" |   Rango tipico: {atip_low:.2f} - {atip_high:.2f} ({median:.2f}) "
                  f"TOTAL: {len(data)} - Non Zero: {np.count_nonzero(data)} - Atipical: ",
                  np.count_nonzero((data > atip_high) | (data < atip_low)))


n = 1
while n:
    print("Available options:")
    print("  0. Exit")
    print("  1. Calculate max number of domains")
    print("  2. Check collisions")
    print("  3. Calculate chars used")
    print("  4. Calculate double chars used")
    print("  5. Calculate repeated chars used")
    print("  6. Calculate vowel/consonant ratio")
    print("  7. Calculate numbers in domain ratio")
    print("  8. Calculate the average, max and min lenght of syllables")
    print("  9. Calculate the n-gram mean, median and standard desviation")
    try:
        n = int(input("> "))
        if n == 1:
            n2 = input("How many samples to test (32000 by default)? ")
            if n2:
                n2 = int(n2)
            else:
                n2 = 32000
            statmax(dga.listall(), None, n2, None)
        elif n == 2:
            n2 = input("How many samples to check (10000 by default)? ")
            if n2:
                n2 = int(n2)
            else:
                n2 = 10000
            collision(dga.listall(), None, n2, None)
        elif n == 3:
            date = datetime.now()
            values = statletters(dga.listall(), date, 50000, None)
            for data in values:
                print(f"{data['.name']}:")
                print(f"   |__RegExp: {data['.regexp']}")
                print(f"   |__TLDs:   {data['.tlds']}")
        elif n == 4:
            n2 = input("How many domains per DGA to check (10000 by default)? ")
            if n2:
                n2 = int(n2)
            else:
                n2 = 10000
            n3 = input("Check real domains of Alexa top million (y/N)? ")
            if 'y' in n3.lower():
                print(f"Alexa top million: ({n2*len(dga.listall())}):")
                doublel(None, None, n2)
            else:
                for family in dga.listall():
                    print(f"{family}:")
                    doublel([family], None, n2)
                print("All DGA:")
                doublel(dga.listall(), None, n2)
        elif n == 5:
            n2 = input("How many domains per DGA to check (10000 by default)? ")
            if n2:
                n2 = int(n2)
            else:
                n2 = 10000
            n3 = input("Check real domains of Alexa top million (y/N)? ")
            if 'y' in n3.lower():
                print(f"Alexa top million: ({n2*len(dga.listall())}):")
                repeatedl(None, None, n2)
            else:
                for family in dga.listall():
                    print(f"{family}:")
                    repeatedl([family], None, n2)
                print("All DGA:")
                repeatedl(dga.listall(), None, n2)
        elif n == 6:
            n2 = input("How many domains per DGA to check (10000 by default)? ")
            if n2:
                n2 = int(n2)
            else:
                n2 = 10000
            n3 = input("Check real domains of Alexa top million (y/N)? ")
            if 'y' in n3.lower():
                print(f"Alexa top million: ({n2*len(dga.listall())}):")
                ratiovc(None, None, n2)
            else:
                for family in dga.listall():
                    print(f"{family}:")
                    ratiovc([family], None, n2)
                print("All DGA:")
                ratiovc(dga.listall(), None, n2)
        elif n == 7:
            n2 = input("How many domains per DGA to check (10000 by default)? ")
            if n2:
                n2 = int(n2)
            else:
                n2 = 10000
            n3 = input("Check real domains of Alexa top million (y/N)? ")
            if 'y' in n3.lower():
                print(f"Alexa top million: ({n2*len(dga.listall())}):")
                ratiovc(None, None, n2, numbers=True)
            else:
                for family in dga.listall():
                    print(f"{family}:")
                    ratiovc([family], None, n2, numbers=True)
                print("All DGA:")
                ratiovc(dga.listall(), None, n2, numbers=True)
        elif n == 8:
            n2 = input("How many domains per DGA to check (10000 by default)? ")
            if n2:
                n2 = int(n2)
            else:
                n2 = 10000
            n3 = input("Check real domains of Alexa top million (y/N)? ")
            if 'y' in n3.lower():
                print(f"Alexa top million: ({n2*len(dga.listall())}):")
                syll(None, None, n2)
            else:
                for family in dga.listall():
                    print(f"{family}:")
                    syll([family], None, n2)
                print("All DGA:")
                syll(dga.listall(), None, n2)
        elif n == 9:
            n2 = input("How many domains to calculate n-grams data (500000 by default)? ")
            if n2:
                n2 = int(n2)
            else:
                n2 = 500000
            with open("DGAs/wordlist/top-1m.csv") as f:
                lines = f.readlines()
                lines = lines[2000:n2+500000]
            domains = []
            for line in lines:
                domains.append(line.split(',')[1].strip())
            ng = ngrams()
            ng.train(domains)

            print(len(ng.ngram1))
            print(len(ng.ngram2))
            print(len(ng.ngram3))
            print(len(ng.ngram4))

            n3 = input("Check first 2000 domains of Alexa top million (y/N)? ")
            if 'y' in n3.lower():
                print(f"Alexa 2000 domains:")
                calcngram(None, ng)
            else:
                for family in dga.listall():
                    print(f"{family}:")
                    calcngram([family], ng)
                print("All DGA:")
                calcngram(dga.listall(), ng)
    except Exception as e:
        print("Incorrect option", e)
