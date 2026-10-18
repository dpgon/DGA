import argparse
import numpy as np
import pandas as pd
import dga
import pickle
from datetime import datetime, timedelta
from nltk.tokenize import LegalitySyllableTokenizer
from nltk.corpus import brown
from dns import resolver
from ngram import ngrams
from nlpdata import requirebrown
from binascii import crc32
from os.path import isfile
from sys import exit, stderr
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestRegressor, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score


etlds = []

# Data files shared by several functions, defined once so the checks and the reads cannot diverge (C6)
NGRAM = "ml-data/tranco"
TRANCO_TEST2 = "ml-data/tranco-test2.dom"


def loadetlds():
    if not etlds:
        # TLDs extracted from Alexa top 1M
        etlds.extend(['wix.com', 'wordpress.com', 'uol.com.br', 'tumblr.com', 'squarespace.com', 'gov.bd',
                      'com.bd', 'ecwid.com', 'sharepoint.com', 'xn--p1ai', 'free.fr', 'jimdo.com', 'com.mm', 
                      'com.kh', 'com.np', 'xn--80asehdb', 'livejournal.com', 'sendai.jp', 'com.pg', 'narod.ru', 
                      'podbean.com', 'xn--d1acj3b', 'kawasaki.jp', 'wikidot.com', 'ipage.com', 'ning.com', 'nagoya.jp',
                      'weebly.com', 'webnode.com', 'typepad.com', 'gov.mm', 'home.pl', 'mybigcommerce.com', 'org.pg', 
                      'ucoz.ru', 'org.np', 'ac.bd', 'ipfs.dweb.link', 'bigcartel.com', 'org.mm', 'sapporo.jp', 'edu.bd',
                      'xn--3e0b707e', 'webs.com', 'hpage.com', 'siterubix.com', 'bravesites.com', 'do.am', 'okis.ru', 
                      'gov.np', 'xn--80aswg', 'com.jm', 'org.kh', 'blogfa.com', 'cluster028.hosting.ovh.net',
                      '50webs.com', 'blogsky.com', 'nationbuilder.com', 'xn--wgbh1c', 'over-blog.com', 'lnwshop.com', 
                      'ecrater.com', 'comunidades.net', 'ts.r.appspot.com', 'clan.su',
                      'atwebpages.com', 'homestead.com', 'eb2a.com', 'org.bd', 'gov.jm', 'jigsy.com', 
                      '3dcartstores.com', 'us-3.magentosite.cloud', 'rozblog.com', 'mam9.com', 'mil.bd', 'ucoz.org', 
                      'tripod.com', 'onlinehome.us', 'demo.magentosite.cloud', 'ahlamontada.com', 'edu.kh', 'net.np',
                      'gov.kh', 'cluster027.hosting.ovh.net', 'blogs.com', 'hosting.ovh.net', 'freehostia.com', 'at.ua',
                      'ucoz.net', 'us-5.magentosite.cloud', 'xn--80adxhks', 'tameside.sch.uk', 'storenvy.com', 
                      'df.r.appspot.com', 'forumotion.com', 'eu-4.platformsh.site', 'vpweb.com', 'uc.gateway.dev', 
                      'ap-3.magentosite.cloud', 'loxblog.com', 'edu.jm', 'xn--p1acf', 'xn--90ais', 'yoo7.com', 'net.bd',
                      'edu.np', 'xn--c1avg', 'el.r.appspot.com', 'canalblog.com',
                      'my1.ru', 'ethos14-prod-va7.dev.adobeaemcloud.com', 'somee.com', 'hooxs.com', 'ucoz.com', 
                      'staffs.sch.uk', 'moy.su', 'uk.r.appspot.com', 'tr.gg', 'page.tl', 'own0.com', 'ue.r.appspot.com',
                      'ipns.dweb.link', 'wl.r.appspot.com', '16mb.com', 'xn--h2brj9c',
                      'ew.r.appspot.com', 'nn.r.appspot.com', 'xtgem.com', 'ucoz.ua', '3dn.ru', 'esy.es',
                      'niloblog.com', 'mygov.bd', 'forumvi.com', 'gov.pg',
                      'northants.sch.uk', 'doncaster.sch.uk', 'uaprom.net', 'xn--54b7fta0cc', 'xn--node', 
                      'eu-frankfurt-1.oci.customer-oci.com', 'org.jm', 'newham.sch.uk',
                      'de.r.appspot.com', 'info.bd', 'mihanblog.com', 'cumbria.sch.uk',
                      'coop.np', 'mil.np', 'info.np', 'cornwall.sch.uk', 'xn--cck2b3b',
                      'xn--bck1b9a5dre4c'])

        with open("DGAs/wordlist/effective_tld_names.dat") as f:
            lines = f.readlines()
        for line in lines:
            line = line.strip()
            if line and '//' not in line:
                if line not in etlds:
                    etlds.append(line)


def existdomain(domain, short=True):
    # https://gist.github.com/akshaybabloo/2a1df455e7643926739e934e910cbf2e
    checks = ['A', 'NS', 'CNAME', 'SOA', 'MX', 'TXT', 'AAAA', 'ALIAS']
    if not short:
        checks.extend(['NONE', 'MB', 'MG', 'MR', 'NULL', 'WKS', 'PTR', 'HINFO', 'MINFO',
                  'RP', 'AFSDB', 'X25', 'ISDN', 'RT', 'NSAP', 'NSAP-PTR', 'SIG', 'KEY',
                  'PX', 'GPOS', 'MD', 'MF', 'LOC', 'NXT', 'SRV', 'NAPTR', 'KX', 'CERT',
                  'A6', 'DNAME', 'OPT', 'APL', 'DS', 'SSHFP', 'IPSECKEY', 'RRSIG', 'NSEC',
                  'DNSKEY', 'DHCID', 'NSEC3', 'NSEC3PARAM', 'TLSA', 'HIP', 'CDS', 'CDNSKEY',
                  'CSYNC', 'SPF', 'UNSPEC', 'EUI48', 'EUI64', 'TKEY', 'TSIG', 'IXFR',
                  'AXFR', 'MAILB', 'MAILA', 'ANY', 'URI', 'CAA', 'TA', 'DLV'])
    for item in checks:
        try:
            return resolver.resolve(domain, item)
        except:
            pass
    return False


def checkdomains(malware, date, nr):
    if not date:
        date = datetime.now()
    if not malware:
        with open("DGAs/wordlist/top-1m.csv") as f:
            topdomains = f.readlines()
            topdomains = topdomains[:nr * len(dga.listall())]
    else:
        topdomains = dga.create(malware, date, nr, None, short=True)

    c = 0
    for domain in topdomains:
        if not malware:
            domain = domain.split(',')[1].strip()
        if existdomain(domain):
            print(f"Domain {domain} exists!")
            c += 1

    return c


def detect(domain):
    return dga.detect(dga.listall(), [domain], main=False)


def sldtld(domain):
    '''
    Split the SLD and the TLD
    :param domain: domain to check and split
    :return: SLD and TLD or None if not valid or SLD less of 4 chars
    '''
    sld, tld, reason = sldtldreason(domain)
    return sld, tld


def sldtldreason(domain):
    '''
    Split the SLD and the TLD, telling why a domain is not valid
    :param domain: domain to check and split
    :return: SLD, TLD and None, or None, None and the reason if not valid
    '''
    common = ["www1", "www2", "mail"]
    sld = domain.split('.')[0]
    if sld in common:
        domain = ".".join(domain.split('.')[1:])
        sld = domain.split('.')[0]
    tld = ".".join(domain.split('.')[1:])
    if not tld or tld not in etlds:
        labels = tld.split('.')
        if any(".".join(labels[c:]) in etlds for c in range(1, len(labels))):
            return None, None, "subdomain or www. prefix (only registrable domains are evaluated)"
        return None, None, "unknown suffix"
    elif len(sld) <= 3:
        return None, None, "SLD of 3 characters or fewer"
    else:
        return sld, tld, None


def vcn(domain):
    domain = domain.lower()
    v = 0
    c = 0
    n = 0
    l = len(domain)
    for letter in domain:
        if letter in 'zxcvbnmsdfghjklqwrtp':
            c += 1
        elif letter in 'aeiouy':
            v += 1
        elif letter in '0987654321':
            n += 1
    return v/l, c/l, n/l


def double(domain):
    l = len(domain)
    double = 0
    for c, letter in enumerate(domain):
        if c > 0 and letter == domain[c - 1]:
            double += 1
    double /= l
    return double


def repeated(domain):
    l = len(domain)
    used = []
    repeated = 0
    for c, letter in enumerate(domain):
        if letter in used:
            repeated += 1
        else:
            used.append(letter)
    repeated /= l
    return repeated


def syllables(domain, LP):
    l = len(domain)
    maxsize = 0
    minsize = 630

    sil = LP.tokenize(domain)
    n = len(sil) / l
    for item in sil:
        if len(item) > maxsize:
            maxsize = len(item)
        if len(item) < minsize:
            minsize = len(item)

    return n, minsize, maxsize


def createngram(domains, filename=None):
    '''
    Create a ngram and train with the data specified. If filename save it to that file
    :param domains: list of domains to train the ngram
    :param filename:  name of the file without extension to save the ngram model (4 files ng1..ng4 to each ngram)
    :return: ngram object or None if anything fails
    '''
    ng = ngrams()
    try:
        ng.train(domains)
        if filename:
            ng.save(filename)
        return ng
    except:
        return None


def loadngram(filename):
    '''
    Create a ngram loading the files
    :param filename: name of the ngram data without extension
    :return: ngram objext or None if load fails
    '''
    ng = ngrams()
    try:
        ng.load(filename)
        return ng
    except Exception as e:
        print(f"Can't load the n-gram dictionary {filename}.ng1-ng4: {e}", file=stderr)
        return None


def createstdngram():
    with open("ml-data/tranco-ngram.dom") as f:
        lines = f.readlines()

    domains = []
    for line in lines:
        domain = line.strip()
        domains.append(domain)

    createngram(domains, filename="ml-data/tranco")


def gini(x):
    # https://stackoverflow.com/questions/39512260/calculating-gini-coefficient-in-python-numpy
    # Mean absolute difference
    mad = np.abs(np.subtract.outer(x, x)).mean()
    # Relative mean absolute difference
    rmad = mad/np.mean(x)
    # Gini coefficient
    g = 0.5 * rmad
    return g


def createmaindataset():
    loadetlds()
    ng = loadngram(NGRAM)
    requirebrown()
    LP = LegalitySyllableTokenizer(brown.words())

    # Open noDGA domains
    with open("ml-data/tranco-main.dom") as f:
        lines = f.readlines()

    domains = []
    for status, line in enumerate(lines):
        if status % 100000 == 0:
            print("=", end="")

        domain = line.strip()

        # Create data from domains
        sld, tld = sldtld(domain)
        if sld:
            # CRC32 TLD
            crctld = crc32(tld.encode('UTF-8'))

            # N-Grams
            mean1, median1, stddev1 = ng.getall(domain, 1)
            mean2, median2, stddev2 = ng.getall(domain, 2)
            mean3, median3, stddev3 = ng.getall(domain, 3)
            mean4, median4, stddev4 = ng.getall(domain, 4)

            # Vowels, Consonants and numbers
            v, c, n = vcn(sld)

            # Syllables
            syln, sylmin, sylmax = syllables(sld, LP)

            # Entropy
            data = [ord(letter) for letter in sld]
            value, counts = np.unique(data, return_counts=True)
            norm_counts = counts / counts.sum()
            entropy = -(norm_counts * np.log(norm_counts)/np.log(np.e)).sum()

            # Gini coeficient
            gc = gini(np.array(data))

            domains.append([sld, tld, 'tranco', 0, len(sld)/63, crctld,
                            v, c, n, double(sld), repeated(sld), syln, sylmin, sylmax,
                            mean1, median1, stddev1, mean2, median2, stddev2,
                            mean3, median3, stddev3, mean4, median4, stddev4,
                            entropy, gc])

    print("\nCurrent domains: ", len(domains))

    # Open DGA domains
    with open("ml-data/dga.dom") as f:
        lines = f.readlines()

    for status, line in enumerate(lines):
        if status % 100000 == 0:
            print("=", end="")

        line = line.strip()
        if '#' in line or not line:
            continue
        items = line.split()
        family = items[0]
        domain = items[1]

        # Create data from domains
        sld, tld = sldtld(domain)
        if sld:
            # CRC32 TLD
            crctld = crc32(tld.encode('UTF-8'))

            # N-Grams
            mean1, median1, stddev1 = ng.getall(domain, 1)
            mean2, median2, stddev2 = ng.getall(domain, 2)
            mean3, median3, stddev3 = ng.getall(domain, 3)
            mean4, median4, stddev4 = ng.getall(domain, 4)

            # Vowels, Consonants and numbers
            v, c, n = vcn(sld)

            # Syllables
            syln, sylmin, sylmax = syllables(sld, LP)

            # Entropy
            data = [ord(letter) for letter in sld]
            value, counts = np.unique(data, return_counts=True)
            norm_counts = counts / counts.sum()
            entropy = -(norm_counts * np.log(norm_counts) / np.log(np.e)).sum()

            # Gini coeficient
            gc = gini(np.array(data))

            domains.append([sld, tld, family, 1, len(sld) / 63, crctld,
                            v, c, n, double(sld), repeated(sld), syln, sylmin, sylmax,
                            mean1, median1, stddev1, mean2, median2, stddev2,
                            mean3, median3, stddev3, mean4, median4, stddev4,
                            entropy, gc])

    print("\nTotal domains: ", len(domains))

    df = pd.DataFrame(domains, columns=['sld', 'tld', 'family', 'dga', 'len', 'crctld',
                                        'vowels', 'consonants', 'numbers', 'doubled',
                                        'repeated', 'sylnumber', 'sylmin', 'sylmax',
                                        'mean1', 'median1', 'stddev1', 'mean2', 'median2', 'stddev2',
                                        'mean3', 'median3', 'stddev3', 'mean4', 'median4', 'stddev4',
                                        'entropy', 'gini'])
    df.to_pickle('ml-data/main.pkl')


def createtestdataset():
    loadetlds()
    ng = loadngram(NGRAM)
    requirebrown()
    LP = LegalitySyllableTokenizer(brown.words())

    # Open noDGA domains
    with open(TRANCO_TEST2) as f:
        lines = f.readlines()

    domains = []
    for status, line in enumerate(lines):
        if status % 100000 == 0:
            print("=", end="")

        domain = line.strip()

        # Create data from domains
        sld, tld = sldtld(domain)
        if sld:
            # CRC32 TLD
            crctld = crc32(tld.encode('UTF-8'))

            # N-Grams
            mean1, median1, stddev1 = ng.getall(domain, 1)
            mean2, median2, stddev2 = ng.getall(domain, 2)
            mean3, median3, stddev3 = ng.getall(domain, 3)
            mean4, median4, stddev4 = ng.getall(domain, 4)

            # Vowels, Consonants and numbers
            v, c, n = vcn(sld)

            # Syllables
            syln, sylmin, sylmax = syllables(sld, LP)

            # Entropy
            data = [ord(letter) for letter in sld]
            value, counts = np.unique(data, return_counts=True)
            norm_counts = counts / counts.sum()
            entropy = -(norm_counts * np.log(norm_counts)/np.log(np.e)).sum()

            # Gini coeficient
            gc = gini(np.array(data))

            domains.append([sld, tld, 'tranco', 0, len(sld)/63, crctld,
                            v, c, n, double(sld), repeated(sld), syln, sylmin, sylmax,
                            mean1, median1, stddev1, mean2, median2, stddev2,
                            mean3, median3, stddev3, mean4, median4, stddev4,
                            entropy, gc])

    print("\nCurrent domains: ", len(domains))

    # Open DGA domains
    with open("ml-data/mydgas.dom") as f:
        lines = f.readlines()

    for status, line in enumerate(lines):
        if status % 100000 == 0:
            print("=", end="")

        line = line.strip()
        # Status lines starting with "*": lookdga.py -C mixed them with the CSV before C13 (2021 mydgas.dom)
        if '*' in line or not line:
            continue
        items = line.split(',')
        family = items[1]
        domain = items[0]

        # Create data from domains
        sld, tld = sldtld(domain)
        if sld:
            # CRC32 TLD
            crctld = crc32(tld.encode('UTF-8'))

            # N-Grams
            mean1, median1, stddev1 = ng.getall(domain, 1)
            mean2, median2, stddev2 = ng.getall(domain, 2)
            mean3, median3, stddev3 = ng.getall(domain, 3)
            mean4, median4, stddev4 = ng.getall(domain, 4)

            # Vowels, Consonants and numbers
            v, c, n = vcn(sld)

            # Syllables
            syln, sylmin, sylmax = syllables(sld, LP)

            # Entropy
            data = [ord(letter) for letter in sld]
            value, counts = np.unique(data, return_counts=True)
            norm_counts = counts / counts.sum()
            entropy = -(norm_counts * np.log(norm_counts) / np.log(np.e)).sum()

            # Gini coeficient
            gc = gini(np.array(data))

            domains.append([sld, tld, family, 1, len(sld) / 63, crctld,
                            v, c, n, double(sld), repeated(sld), syln, sylmin, sylmax,
                            mean1, median1, stddev1, mean2, median2, stddev2,
                            mean3, median3, stddev3, mean4, median4, stddev4,
                            entropy, gc])

    print("\nTotal domains: ", len(domains))

    df = pd.DataFrame(domains, columns=['sld', 'tld', 'family', 'dga', 'len', 'crctld',
                                        'vowels', 'consonants', 'numbers', 'doubled',
                                        'repeated', 'sylnumber', 'sylmin', 'sylmax',
                                        'mean1', 'median1', 'stddev1', 'mean2', 'median2', 'stddev2',
                                        'mean3', 'median3', 'stddev3', 'mean4', 'median4', 'stddev4',
                                        'entropy', 'gini'])
    df.to_pickle('ml-data/secondary.pkl')


def createalexadataset():
    loadetlds()
    ng = loadngram(NGRAM)
    requirebrown()
    LP = LegalitySyllableTokenizer(brown.words())

    # Open noDGA domains
    with open("ml-data/alexa.dom") as f:
        lines = f.readlines()

    domains = []
    for status, line in enumerate(lines):
        if status % 100000 == 0:
            print("=", end="")

        domain = line.strip()

        # Create data from domains
        sld, tld = sldtld(domain)
        if sld:
            # CRC32 TLD
            crctld = crc32(tld.encode('UTF-8'))

            # N-Grams
            mean1, median1, stddev1 = ng.getall(domain, 1)
            mean2, median2, stddev2 = ng.getall(domain, 2)
            mean3, median3, stddev3 = ng.getall(domain, 3)
            mean4, median4, stddev4 = ng.getall(domain, 4)

            # Vowels, Consonants and numbers
            v, c, n = vcn(sld)

            # Syllables
            syln, sylmin, sylmax = syllables(sld, LP)

            # Entropy
            data = [ord(letter) for letter in sld]
            value, counts = np.unique(data, return_counts=True)
            norm_counts = counts / counts.sum()
            entropy = -(norm_counts * np.log(norm_counts)/np.log(np.e)).sum()

            # Gini coeficient
            gc = gini(np.array(data))

            domains.append([sld, tld, 'alexa', 0, len(sld)/63, crctld,
                            v, c, n, double(sld), repeated(sld), syln, sylmin, sylmax,
                            mean1, median1, stddev1, mean2, median2, stddev2,
                            mean3, median3, stddev3, mean4, median4, stddev4,
                            entropy, gc])

    print("\nTotal domains: ", len(domains))

    df = pd.DataFrame(domains, columns=['sld', 'tld', 'family', 'dga', 'len', 'crctld',
                                        'vowels', 'consonants', 'numbers', 'doubled',
                                        'repeated', 'sylnumber', 'sylmin', 'sylmax',
                                        'mean1', 'median1', 'stddev1', 'mean2', 'median2', 'stddev2',
                                        'mean3', 'median3', 'stddev3', 'mean4', 'median4', 'stddev4',
                                        'entropy', 'gini'])
    df.to_pickle('ml-data/alexa.pkl')


def traindata(dataset="full"):
    df = pd.read_pickle('ml-data/main.pkl')

    # We don't need info strings
    df.drop('sld', inplace=True, axis=1)
    df.drop('tld', inplace=True, axis=1)
    df.drop('family', inplace=True, axis=1)

    # Adjust columns to dataset
    if dataset == "ngram":
        for column in ['len', 'crctld', 'vowels', 'consonants', 'numbers', 'doubled', 'repeated',
                       'sylnumber', 'sylmin', 'sylmax', 'entropy', 'gini']:
            df.drop(column, inplace=True, axis=1)
    elif dataset == "nongram":
        for column in ['mean1', 'median1', 'stddev1', 'mean2', 'median2', 'stddev2',
                       'mean3', 'median3', 'stddev3', 'mean4', 'median4', 'stddev4']:
            df.drop(column, inplace=True, axis=1)
    elif dataset == "nosyll":
        for column in ['sylnumber', 'sylmin', 'sylmax']:
            df.drop(column, inplace=True, axis=1)
    elif dataset == "nongramnosyll":
        for column in ['mean1', 'median1', 'stddev1', 'mean2', 'median2', 'stddev2',
                       'mean3', 'median3', 'stddev3', 'mean4', 'median4', 'stddev4',
                       'sylnumber', 'sylmin', 'sylmax']:
            df.drop(column, inplace=True, axis=1)
    elif dataset == "tiny":
        for column in ['mean1', 'median1', 'stddev1', 'mean2', 'median2', 'stddev2',
                       'mean3', 'median3', 'stddev3', 'mean4', 'median4', 'stddev4',
                       'sylnumber', 'sylmin', 'sylmax', 'entropy', 'gini']:
            df.drop(column, inplace=True, axis=1)

    # Split data
    X = df.iloc[:, 1:].values
    y = df.iloc[:, 0].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=100)

    # Scale data
    sc = StandardScaler()
    X_train = sc.fit_transform(X_train)
    X_test = sc.transform(X_test)

    # Save scaler for use after train
    # sc = pickle.load(open('ml-data/scaler.pkl', 'rb'))
    pickle.dump(sc, open(f'ml-data/{dataset}-scaler.pkl', 'wb'))

    # Train data
    model = RandomForestClassifier(n_estimators=30, random_state=1, verbose=1, n_jobs=14, min_samples_leaf=5)
    model.fit(X_train, y_train)

    # Save model
    pickle.dump(model, open(f'ml-data/{dataset}.pkl', 'wb'))

    # Predict
    y_pred = model.predict(X_test)

    # Show results
    print(f"Confussion matrix:")
    print(confusion_matrix(y_test, y_pred))
    print(f"Classification report:")
    print(classification_report(y_test, y_pred))
    print(f"Accuracy Score: {accuracy_score(y_test, y_pred)}")


def testsecdata(dataset="full", alexa=False):
    if alexa:
        df = pd.read_pickle('ml-data/alexa.pkl')
    else:
        df = pd.read_pickle('ml-data/secondary.pkl')

    # We don't need info strings
    df.drop('sld', inplace=True, axis=1)
    df.drop('tld', inplace=True, axis=1)
    df.drop('family', inplace=True, axis=1)

    # Adjust columns to dataset
    if dataset == "ngram":
        for column in ['len', 'crctld', 'vowels', 'consonants', 'numbers', 'doubled', 'repeated',
                       'sylnumber', 'sylmin', 'sylmax', 'entropy', 'gini']:
            df.drop(column, inplace=True, axis=1)
    elif dataset == "nongram":
        for column in ['mean1', 'median1', 'stddev1', 'mean2', 'median2', 'stddev2',
                       'mean3', 'median3', 'stddev3', 'mean4', 'median4', 'stddev4']:
            df.drop(column, inplace=True, axis=1)
    elif dataset == "nosyll":
        for column in ['sylnumber', 'sylmin', 'sylmax']:
            df.drop(column, inplace=True, axis=1)
    elif dataset == "nongramnosyll":
        for column in ['mean1', 'median1', 'stddev1', 'mean2', 'median2', 'stddev2',
                       'mean3', 'median3', 'stddev3', 'mean4', 'median4', 'stddev4',
                       'sylnumber', 'sylmin', 'sylmax']:
            df.drop(column, inplace=True, axis=1)
    elif dataset == "tiny":
        for column in ['mean1', 'median1', 'stddev1', 'mean2', 'median2', 'stddev2',
                       'mean3', 'median3', 'stddev3', 'mean4', 'median4', 'stddev4',
                       'sylnumber', 'sylmin', 'sylmax', 'entropy', 'gini']:
            df.drop(column, inplace=True, axis=1)

    # Split data
    X = df.iloc[:, 1:].values
    y = df.iloc[:, 0].values

    # Load scaler
    sc = pickle.load(open(f'ml-data/{dataset}-scaler.pkl', 'rb'))

    # Scale data
    X_test = sc.transform(X)

    # Load model
    model = pickle.load(open(f'ml-data/{dataset}.pkl', 'rb'))

    # Predict
    y_pred = model.predict(X_test)

    # Show results
    print(f"Confussion matrix:")
    print(confusion_matrix(y, y_pred))
    print(f"Classification report:")
    print(classification_report(y, y_pred))
    print(f"Accuracy Score: {accuracy_score(y, y_pred)}")


def domainfeatures(domain, sld, tld, ng, LP):
    '''
    Calculate the 24 features of a domain, in the order the full model was trained with
    :param domain: full domain (the n-grams are taken from its first label)
    :param sld: SLD returned by sldtld()
    :param tld: TLD returned by sldtld()
    :param ng: ngram object
    :param LP: syllable tokenizer
    :return: list with the 24 features
    '''
    # CRC32 TLD
    crctld = crc32(tld.encode('UTF-8'))

    # N-Grams
    mean1, median1, stddev1 = ng.getall(domain, 1)
    mean2, median2, stddev2 = ng.getall(domain, 2)
    mean3, median3, stddev3 = ng.getall(domain, 3)
    mean4, median4, stddev4 = ng.getall(domain, 4)

    # Vowels, Consonants and numbers
    v, c, n = vcn(sld)

    # Syllables
    syln, sylmin, sylmax = syllables(sld, LP)

    # Entropy
    data = [ord(letter) for letter in sld]
    value, counts = np.unique(data, return_counts=True)
    norm_counts = counts / counts.sum()
    entropy = -(norm_counts * np.log(norm_counts)/np.log(np.e)).sum()

    # Gini coeficient
    gc = gini(np.array(data))

    return [len(sld)/63, crctld,
            v, c, n, double(sld), repeated(sld), syln, sylmin, sylmax,
            mean1, median1, stddev1, mean2, median2, stddev2,
            mean3, median3, stddev3, mean4, median4, stddev4,
            entropy, gc]


def classify(domlist, model, sc, ng, LP):
    '''
    Classify domains with a model, keeping every verdict with its own domain
    :param domlist: list of domains (they are lowercased before evaluating them)
    :param model: trained model with a predict() method
    :param sc: scaler with a transform() method
    :param ng: ngram object
    :param LP: syllable tokenizer
    :return: list of (domain, verdict, reason) in the input order; verdict is None and reason says why
             when the domain could not be evaluated
    '''
    domains = [domain.lower() for domain in domlist]
    features = []
    reasons = []
    for domain in domains:
        sld, tld, reason = sldtldreason(domain)
        reasons.append(reason)
        if sld:
            features.append(domainfeatures(domain, sld, tld, ng, LP))

    verdicts = []
    if features:
        df = pd.DataFrame(features, columns=['len', 'crctld',
                                             'vowels', 'consonants', 'numbers', 'doubled',
                                             'repeated', 'sylnumber', 'sylmin', 'sylmax',
                                             'mean1', 'median1', 'stddev1', 'mean2', 'median2', 'stddev2',
                                             'mean3', 'median3', 'stddev3', 'mean4', 'median4', 'stddev4',
                                             'entropy', 'gini'])
        verdicts = list(model.predict(sc.transform(df.iloc[:, :].values)))

    results = []
    for domain, reason in zip(domains, reasons):
        if reason:
            results.append((domain, None, reason))
        else:
            results.append((domain, verdicts.pop(0), None))
    return results


def testdomains(domlist, brute=False):
    loadetlds()
    ng = loadngram(NGRAM)
    requirebrown()
    LP = LegalitySyllableTokenizer(brown.words())

    # Load scaler and model
    sc = pickle.load(open('ml-data/full-scaler.pkl', 'rb'))
    model = pickle.load(open('ml-data/full.pkl', 'rb'))

    results = classify(domlist, model, sc, ng, LP)
    evaluated = [(domain, verdict) for domain, verdict, reason in results if not reason]
    discarded = [(domain, reason) for domain, verdict, reason in results if reason]

    print("\nTotal domains: ", len(evaluated))

    # Show results

    print(f"Predictions:")
    for domain, item in evaluated:
        print(dga.Col.HEADER + f"{domain}:" + dga.Col.END)
        if item:
            print(dga.Col.WARNING + "  |__ DGA generated" + dga.Col.END)
            families = dga.detect(dga.listall(), [domain])
            if families:
                print(dga.Col.WARNING + f"  |__ Possible: {', '.join(families)}" + dga.Col.END)
                if brute:
                    print(dga.Col.WARNING + f"  |__ BRUTEFORCING..." + dga.Col.END, end="\r")
                    res = dga.bruteforce(families, [domain], None, None, 10)
                    if res:
                        print(dga.Col.ERROR + f"  |__ Detected as {res[0][1]} in {res[0][2]} position for date {res[0][3].year}-{res[0][3].month}-{res[0][3].day}" + dga.Col.END)
                    else:
                        print(dga.Col.WARNING + f"  |__ Not found by bruteforce" + dga.Col.END)

        else:
            print(dga.Col.OK + "  |__ No DGA domain" + dga.Col.END)
        print()

    if discarded:
        print(f"Not evaluated:")
        for domain, reason in discarded:
            print(dga.Col.WARNING + f"  |__ {domain}: {reason}" + dga.Col.END)


def missingngram():
    '''
    List the files of the standard n-gram dictionary that don't exist
    :return: list of missing files, empty if the dictionary is complete
    '''
    return [f"{NGRAM}.ng{n}" for n in range(1, 5) if not isfile(f"{NGRAM}.ng{n}")]


def checktranco():
    return not missingngram()


def tranconotfound():
    print(f"Tranco dictionary not found at ml-data (missing {', '.join(missingngram())}). "
          f"Try to create it with --ngram option.")
    exit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ngram",
                                help="create the standard Tranco ngram dictionary, saving it in ml-data/tranco.*",
                                action="store_true")
    parser.add_argument("--main",
                                help="create the main dataset and save it in ml-data/main.pkl", action="store_true")
    parser.add_argument("--secondary",
                                help="create the secondary dataset and save it in ml-data/secondary.pkl", action="store_true")
    parser.add_argument("--alexa",
                                help="create the alexa dataset and save it in ml-data/alexa.pkl", action="store_true")
    parser.add_argument("--train", type=str,
                                help="Train the Check the given domains (full|ngram|nongram|nosyll|nongramnosyll|tiny)",
                                choices=['full', 'ngram', 'nongram', 'nosyll', 'nongramnosyll', 'tiny'])
    parser.add_argument("--test_secondary", type=str,
                                help="test the secondary dataset of ml-data/secondary.pkl (full|ngram|nongram|nosyll|nongramnosyll|tiny)",
                                choices=['full', 'ngram', 'nongram', 'nosyll', 'nongramnosyll', 'tiny'])
    parser.add_argument("--test_alexa", type=str,
                                help="test the alexa dataset of ml-data/alexa.pkl (full|ngram|nongram|nosyll|nongramnosyll|tiny)",
                                choices=['full', 'ngram', 'nongram', 'nosyll', 'nongramnosyll', 'tiny'])
    parser.add_argument("--check", nargs="+", type=str,
                                help="Check the given domains")
    parser.add_argument("-b", "--bruteforce",
                        help="if check is selected, test DGA detected domains by bruteforce", action="store_true")
    args = parser.parse_args()

    if args.main:
        # Create the main dataset and save it in ml-data/main.pkl
        if checktranco():
            if isfile("ml-data/tranco-main.dom") and isfile("ml-data/dga.dom"):
                createmaindataset()
            else:
                print("Files ml-data/tranco-main.dom and/or ml-data/dga.dom not found")
        else:
            tranconotfound()
    elif args.secondary:
        # Create the secondary test dataset
        if checktranco():
            if isfile(TRANCO_TEST2) and isfile("ml-data/mydgas.dom"):
                createtestdataset()
            else:
                print(f"Files {TRANCO_TEST2} and/or ml-data/mydgas.dom not found")
        else:
            tranconotfound()
    elif args.alexa:
        # Create the Alexa test dataset
        if checktranco():
            if isfile("ml-data/alexa.dom"):
                createalexadataset()
            else:
                print("File ml-data/alexa.dom not found")
        else:
            tranconotfound()
    elif args.ngram:
        # Create the standard Tranco ngram dictionary
        if isfile("ml-data/tranco-ngram.dom"):
            createstdngram()
        else:
            print("File ml-data/tranco-ngram.dom not found.")
    elif args.train:
        # Train our model
        if isfile("ml-data/main.pkl"):
            traindata(dataset=args.train)
        else:
            print("File ml-data/main.pkl not found. Try to create it with --main option.")
    elif args.test_secondary:
        # Train our model
        if isfile("ml-data/secondary.pkl") and isfile(f"ml-data/{args.test_secondary}.pkl") and \
                isfile(f"ml-data/{args.test_secondary}-scaler.pkl"):
            testsecdata(dataset=args.test_secondary, alexa=False)
        else:
            print("Data file or model files not found. Try to create data file with --secondary or create model with --train option.")
    elif args.test_alexa:
        # Train our model
        if isfile("ml-data/alexa.pkl") and isfile(f"ml-data/{args.test_alexa}.pkl") and \
                isfile(f"ml-data/{args.test_alexa}-scaler.pkl"):
            testsecdata(dataset=args.test_alexa, alexa=True)
        else:
            print("Data file or model files not found. Try to create data file with --alexa or create model with --train option.")
    elif args.check:
        testdomains(args.check, brute=args.bruteforce)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
