import argparse
import numpy as np
import pandas as pd
import dga
import json
import platform
import nltk
import sklearn
import skops
import skops.io
from datetime import datetime, timedelta
from nltk.tokenize import LegalitySyllableTokenizer
from nltk.corpus import brown
from ngram import ngrams
from nlpdata import requirebrown
from fetchdata import MANIFEST, readmanifest, sha256
from binascii import crc32
from os.path import isfile
from sys import exit, stderr
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestRegressor, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score


etlds = []
# Same suffixes as etlds, for fast lookups over millions of domains
etldset = set()
etldsfile = None

# Data files shared by several functions, defined once so the checks and the reads cannot diverge (C6)
# N-gram dictionary: ml-data/tranco.ng1.csv ... ng4.csv (ngram.py)
NGRAM = "ml-data/tranco"
# Public suffix list (Mozilla, 2026-10-17; the 2021 one is ml-data/effective_tld_names-2021.dat of the 2021 set)
ETLDS = "DGAs/wordlist/effective_tld_names.dat"
DATASET = "2026"
FETCH = "Download them with: python fetchdata.py"
FETCHSET = {"2021": "Download them with: python fetchdata.py --set 2021", "2026": FETCH}
# Files a model is built from, by data set: the n-gram dictionary (ngram), the benign (main) and DGA (dga)
# domains of the main data set. No evaluation set may share a domain or an SLD with them (C5)
TRAINING = {
    "2021": {"main": "ml-data/tranco-main.dom", "ngram": "ml-data/tranco-ngram.dom", "dga": "ml-data/dga.dom"},
    "2026": {"main": "ml-data/2026/tranco-main.dom", "ngram": "ml-data/2026/tranco-ngram.dom",
             "dga": "ml-data/dga.dom"},
}
# Input files of the secondary evaluation set, by data set
SECONDARY = {
    "2021": {"tranco": "ml-data/tranco-test2.dom", "own": "ml-data/mydgas.dom"},
    "2026": {"tranco": "ml-data/2026/tranco-test2.dom", "own": "ml-data/2026/mydgas.dom", "hf": "ml-data/hf-dga.dom"},
}
UMBRELLA = "ml-data/umbrella-raw.csv"
# Models are saved with skops, not pickle (C2). skops trusts the scikit-learn estimators; the tree structure of a
# Random Forest has to be trusted explicitly. Never add types here just to make an unknown file load
TRUSTED = ["sklearn.tree._tree.Tree"]
# Hyperparameters of 2021 (min_samples_leaf, n_estimators, random_state); n_jobs=-1 uses every core (C10)
HYPERPARAMETERS = {"n_estimators": 30, "random_state": 1, "min_samples_leaf": 5, "n_jobs": -1}
# Columns of every data set: 4 info columns and the 24 features of domainfeatures()
COLUMNS = ['sld', 'tld', 'family', 'dga', 'len', 'crctld',
           'vowels', 'consonants', 'numbers', 'doubled',
           'repeated', 'sylnumber', 'sylmin', 'sylmax',
           'mean1', 'median1', 'stddev1', 'mean2', 'median2', 'stddev2',
           'mean3', 'median3', 'stddev3', 'mean4', 'median4', 'stddev4',
           'entropy', 'gini']


def requirefiles(files, hint=FETCH):
    '''
    Exit with an error if any of the data files is missing. Since C8 they are downloaded, not cloned with the code
    :param files: list of paths relative to the repository root
    :param hint: how to get the missing files
    '''
    missing = [f for f in files if not isfile(f)]
    if missing:
        print(f"Missing data files: {', '.join(missing)}. {hint}", file=stderr)
        exit(1)


def modelfiles(dataset):
    '''
    Files of a model: the model, its scaler and its metadata
    :param dataset: model (full, tiny...)
    '''
    return [f"ml-data/{dataset}.skops", f"ml-data/{dataset}-scaler.skops", f"ml-data/{dataset}.json"]


def ngramfiles(filename=NGRAM):
    return [f"{filename}.ng{n}.csv" for n in range(1, 5)]


def manifestsources():
    '''
    Where every data file comes from, as the manifest says (for instance, the ID of the Tranco list)
    :return: dict {file: source}, empty if the manifest can't be read
    '''
    try:
        return {e["file"]: e["source"] for e in readmanifest(MANIFEST)}
    except (OSError, ValueError):
        return {}


def describefiles(files):
    '''
    SHA-256 and source of data files, for the metadata of data sets and models
    :param files: list of paths
    :return: dict {file: {"sha256": ..., "source": ...}}
    '''
    sources = manifestsources()
    return {f: {"sha256": sha256(f), "source": sources.get(f, "not in the manifest")} for f in files}


def loadetlds(filename=ETLDS):
    '''
    Load the public suffixes, once per list
    :param filename: public suffix list to use, by default the 2021 one
    '''
    global etldsfile
    if etldsfile != filename:
        etlds.clear()
        etldsfile = filename
        # Suffixes extracted by hand from the Alexa top 1M (2021), on top of the public suffix list
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

        with open(filename, encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines:
            line = line.strip()
            if line and '//' not in line:
                if line not in etlds:
                    etlds.append(line)
        etldset.clear()
        etldset.update(etlds)


def existdomain(domain, short=True):
    # Dead code, like checkdomains(): it would query the DNS for the analysed domains (CLAUDE.md, rule 9; pending
    # decision in docs/FUTURE.md 1.1.10). dnspython is no longer a dependency, so the import is only here
    from dns import resolver
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


# Dead code (never called; see CLAUDE.md, rule 9). It still reads DGAs/wordlist/top-1m.csv, which is no longer in
# git: python fetchdata.py installs it with the 2021 data set
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
    if not tld or tld not in etldset:
        labels = tld.split('.')
        if any(".".join(labels[c:]) in etldset for c in range(1, len(labels))):
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
    except (OSError, ValueError) as e:
        print(f"Can't load the n-gram dictionary {filename}.ng1.csv-ng4.csv: {e}", file=stderr)
        return None


def createstdngram(dataset=DATASET):
    '''
    Create the standard n-gram dictionary (ml-data/tranco.ng1.csv ... ng4.csv) from the Tranco domains of a data set
    :param dataset: data set of the input file (2021 or 2026)
    '''
    with open(TRAINING[dataset]["ngram"]) as f:
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


def createmaindataset(dataset=DATASET):
    '''
    Create the main data set (ml-data/main.pkl), the one the models are trained with, and what it is made of
    (ml-data/main.json: input files, n-gram dictionary and public suffix list, with their SHA-256)
    :param dataset: data set of the input files (2021 or 2026)
    '''
    files = TRAINING[dataset]
    loadetlds()
    ng = loadngram(NGRAM)
    requirebrown()
    LP = LegalitySyllableTokenizer(brown.words())

    def items():
        # Open noDGA domains
        with open(files["main"]) as f:
            for line in f:
                if line.strip():
                    yield line.strip(), 'tranco', 0
        # Open DGA domains
        with open(files["dga"]) as f:
            for line in f:
                line = line.strip()
                if '#' in line or not line:
                    continue
                items = line.split()
                yield items[1], items[0], 1

    domains = []
    for status, (domain, family, dga) in enumerate(items()):
        if status % 100000 == 0:
            print("=", end="", flush=True)
        # Create data from domains. The n-grams are taken from the first label of the domain as written
        sld, tld = sldtld(domain)
        if sld:
            domains.append([sld, tld, family, dga] + domainfeatures(domain, sld, tld, ng, LP))

    print("\nTotal domains: ", len(domains))

    pd.DataFrame(domains, columns=COLUMNS).to_pickle('ml-data/main.pkl')
    report = {"set": dataset, "created": datetime.now().isoformat(timespec="seconds"),
              "files": describefiles(list(dict.fromkeys(files.values()))),
              "ngram": describefiles(ngramfiles()), "suffixes": describefiles([ETLDS]),
              "domains": len(domains)}
    with open('ml-data/main.json', 'w') as f:
        json.dump(report, f, indent=2)


def trainingdata(dataset=DATASET):
    '''
    Load the registrable domains and SLDs the models of a data set are built from, in lowercase, so that no
    evaluation set shares a domain or an SLD with them (C5)
    :param dataset: data set (2021 or 2026); its files are domain lists (one domain per line, or family and domain
                    as in dga.dom)
    :return: set of domains (sld.tld) and set of SLDs
    '''
    domains, slds = set(), set()
    for filename in dict.fromkeys(TRAINING[dataset].values()):
        with open(filename) as f:
            for line in f:
                line = line.strip()
                if '#' in line or not line:
                    continue
                items = line.split()
                sld, tld = sldtld((items[1] if len(items) > 1 else items[0]).lower())
                if sld:
                    domains.add(f"{sld}.{tld}")
                    slds.add(sld)
    return domains, slds


def datasetrows(items, exclude, ng, LP, counts):
    '''
    Calculate the rows of an evaluation set, leaving out the domains and SLDs of the training data
    :param items: iterable of (domain, family, dga); the origin is the part of family before ":"
    :param exclude: (domains, slds) returned by trainingdata()
    :param ng: ngram object
    :param LP: syllable tokenizer
    :param counts: dict updated with read, invalid, excluded and kept domains per origin
    :return: list of rows with the 28 columns of COLUMNS
    '''
    domains = []
    for status, (domain, family, dga) in enumerate(items):
        if status % 100000 == 0:
            print("=", end="", flush=True)
        origin = counts.setdefault(family.split(':')[0], {"read": 0, "invalid": 0, "excluded": 0, "kept": 0})
        origin["read"] += 1
        domain = domain.lower()
        sld, tld = sldtld(domain)
        if not sld:
            origin["invalid"] += 1
        elif f"{sld}.{tld}" in exclude[0] or sld in exclude[1]:
            origin["excluded"] += 1
        else:
            origin["kept"] += 1
            domains.append([sld, tld, family, dga] + domainfeatures(domain, sld, tld, ng, LP))
    print()
    return domains


def savedataset(name, domains, counts, dataset, files):
    '''
    Save an evaluation set in ml-data/<name>.pkl and what it is made of in ml-data/<name>.json
    '''
    pd.DataFrame(domains, columns=COLUMNS).to_pickle(f'ml-data/{name}.pkl')
    report = {"set": dataset, "created": datetime.now().isoformat(timespec="seconds"),
              "files": describefiles(files), "training": describefiles(list(dict.fromkeys(TRAINING[dataset].values()))),
              "ngram": describefiles(ngramfiles()), "suffixes": describefiles([ETLDS]), "origins": counts}
    with open(f'ml-data/{name}.json', 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Saved ml-data/{name}.pkl with {len(domains)} domains:")
    for origin, c in counts.items():
        print(f"  {origin}: {c['kept']} kept, {c['excluded']} excluded (in the training data), "
              f"{c['invalid']} not evaluable")


def loadresources():
    loadetlds()
    ng = loadngram(NGRAM)
    requirebrown()
    return ng, LegalitySyllableTokenizer(brown.words())


def createtestdataset(dataset=DATASET):
    '''
    Create the secondary evaluation set: benign Tranco domains, the own generators (own:) and, in the 2026 data
    set, the Hugging Face DGA domains (hf:), without anything of the training data
    :param dataset: data set of the input files (2021 or 2026)
    '''
    files = SECONDARY[dataset]
    requirefiles(list(files.values()) + list(TRAINING[dataset].values()), FETCHSET[dataset])
    ng, LP = loadresources()
    exclude = trainingdata(dataset)

    def items():
        with open(files["tranco"]) as f:
            for line in f:
                if line.strip():
                    yield line.strip(), 'tranco', 0
        with open(files["own"]) as f:
            for line in f:
                line = line.strip()
                # Status lines starting with "*": lookdga.py -C mixed them with the CSV before C13 (2021 mydgas.dom)
                if '*' in line or not line:
                    continue
                fields = line.split(',')
                yield fields[0], f"own:{fields[1]}", 1
        if "hf" in files:
            with open(files["hf"]) as f:
                for line in f:
                    line = line.strip()
                    if '#' in line or not line:
                        continue
                    fields = line.split()
                    yield fields[1], f"hf:{fields[0]}", 1

    counts = {}
    domains = datasetrows(items(), exclude, ng, LP, counts)
    savedataset('secondary', domains, counts, dataset, list(files.values()))


def registrable(domain):
    '''
    Reduce a domain to its registrable domain with the loaded public suffixes (a.b.example.co.uk -> example.co.uk)
    :param domain: domain or subdomain
    :return: registrable domain in lowercase, or None if the domain is a public suffix
    '''
    labels = domain.lower().split('.')
    for c in range(len(labels) - 1):
        if ".".join(labels[c + 1:]) in etldset:
            return ".".join(labels[c:])
    return None


def createumbrelladataset(dataset=DATASET):
    '''
    Create the Umbrella evaluation set (C3): the Umbrella top 1M reduced to unique registrable domains, without
    anything of the training data. It replaces the Alexa set, which shared 62% of its domains with the training data
    :param dataset: data set whose training data is excluded (2021 or 2026)
    '''
    requirefiles([UMBRELLA], "Download it with: python fetchdata.py --set 2026")
    requirefiles(list(TRAINING[dataset].values()), FETCHSET[dataset])
    ng, LP = loadresources()
    exclude = trainingdata(dataset)
    counts = {"umbrella": {"read": 0, "invalid": 0, "excluded": 0, "kept": 0, "subdomains": 0}}

    def items():
        seen = set()
        with open(UMBRELLA) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                domain = registrable(line.split(',')[-1])
                if not domain:
                    counts["umbrella"]["invalid"] += 1
                elif domain in seen:
                    counts["umbrella"]["subdomains"] += 1
                else:
                    seen.add(domain)
                    yield domain, 'umbrella', 0

    domains = datasetrows(items(), exclude, ng, LP, counts)
    savedataset('umbrella', domains, counts, dataset, [UMBRELLA])


def traindata(dataset="full"):
    '''
    Train a model with the main data set and save it with skops: ml-data/<dataset>.skops, its scaler
    (<dataset>-scaler.skops) and its metadata (<dataset>.json)
    :param dataset: model (full, tiny...), the columns it uses
    '''
    requirefiles(['ml-data/main.pkl', 'ml-data/main.json'],
                 "Create them with --main (its input files come from python fetchdata.py).")
    df = pd.read_pickle('ml-data/main.pkl')
    with open('ml-data/main.json') as f:
        data = json.load(f)

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
    features = list(df.columns[1:])
    X = df.iloc[:, 1:].values
    y = df.iloc[:, 0].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=100)

    # Scale data
    sc = StandardScaler()
    X_train = sc.fit_transform(X_train)
    X_test = sc.transform(X_test)

    # Train data
    model = RandomForestClassifier(verbose=1, **HYPERPARAMETERS)
    start = datetime.now()
    model.fit(X_train, y_train)
    seconds = (datetime.now() - start).total_seconds()

    # Save model and scaler with skops (C2)
    modelfile, scalerfile, metafile = modelfiles(dataset)
    skops.io.dump(sc, scalerfile)
    skops.io.dump(model, modelfile)

    # Predict
    y_pred = model.predict(X_test)

    # Show results
    print(f"Confussion matrix:")
    print(confusion_matrix(y_test, y_pred))
    print(f"Classification report:")
    print(classification_report(y_test, y_pred))
    print(f"Accuracy Score: {accuracy_score(y_test, y_pred)}")

    meta = {"model": dataset, "created": datetime.now().isoformat(timespec="seconds"),
            "python": platform.python_version(),
            "libraries": {"scikit-learn": sklearn.__version__, "skops": skops.__version__, "numpy": np.__version__,
                          "pandas": pd.__version__, "nltk": nltk.__version__},
            "set": data["set"], "data": data["files"], "ngram": data["ngram"], "suffixes": data["suffixes"],
            "features": features, "hyperparameters": HYPERPARAMETERS, "training_seconds": round(seconds, 1),
            "test_split": {"test_size": 0.2, "random_state": 100, "rows": len(y_test),
                           "metrics": metrics(y_test, y_pred)},
            "files": {modelfile: sha256(modelfile), scalerfile: sha256(scalerfile)},
            "evaluations": {}}
    with open(metafile, 'w') as f:
        json.dump(meta, f, indent=2)
    print(f"Saved {modelfile}, {scalerfile} and {metafile}")


def metrics(y, y_pred):
    '''
    Metrics of a prediction, for the metadata of a model
    :return: dict with the accuracy, the confusion matrix (rows: real 0 and 1) and precision and recall of DGA
    '''
    report = classification_report(y, y_pred, labels=[0, 1], zero_division=0, output_dict=True)
    return {"accuracy": accuracy_score(y, y_pred),
            "confusion_matrix": confusion_matrix(y, y_pred, labels=[0, 1]).tolist(),
            "dga_precision": report["1"]["precision"], "dga_recall": report["1"]["recall"]}


def loadmodel(dataset="full"):
    '''
    Load a model and its scaler saved with skops, after checking that the n-gram dictionary, the public suffix list
    and the model files are the ones of its metadata (CLAUDE.md, rule 5). Exits with a message if they aren't
    :param dataset: model (full, tiny...)
    :return: model, scaler and metadata
    '''
    modelfile, scalerfile, metafile = modelfiles(dataset)
    requirefiles([modelfile, scalerfile, metafile] + ngramfiles(),
                 f"{FETCH} (full and tiny), or create the model with --train {dataset}.")
    try:
        with open(metafile) as f:
            meta = json.load(f)
        expected = {**{name: v["sha256"] for name, v in {**meta["ngram"], **meta["suffixes"]}.items()},
                    **meta["files"]}
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"Can't read the metadata of the model ({metafile}): {e}", file=stderr)
        exit(1)
    for name, value in expected.items():
        if not isfile(name) or sha256(name) != value:
            print(f"{name} doesn't match the model: {metafile} expects SHA-256 {value}. The model, its scaler, the "
                  f"n-gram dictionary and the public suffix list go together; install them again with "
                  f"python fetchdata.py, or retrain the model.", file=stderr)
            exit(1)
    try:
        sc = skops.io.load(scalerfile, trusted=TRUSTED)
        model = skops.io.load(modelfile, trusted=TRUSTED)
    except skops.io.exceptions.UntrustedTypesFoundException as e:
        print(f"Refusing to load the model: {e}", file=stderr)
        exit(1)
    # Use every core of this machine, whatever the machine that trained the model had (C10)
    model.n_jobs = -1
    return model, sc, meta


def testsecdata(dataset="full", name="secondary"):
    '''
    Evaluate a model with an evaluation set
    :param dataset: model (full, tiny...)
    :param name: evaluation set, ml-data/<name>.pkl (secondary or umbrella)
    '''
    requirefiles(modelfiles(dataset), f"{FETCH} (full and tiny), or create the model with --train {dataset}.")
    requirefiles([f"ml-data/{name}.pkl", f"ml-data/{name}.json"],
                 f"Create them with --{name} (its input files come from python fetchdata.py).")
    model, sc, meta = loadmodel(dataset)
    with open(f'ml-data/{name}.json') as f:
        report = json.load(f)
    # The evaluation set must have been built with the dictionary and the suffix list of the model, and without
    # its training data (C5)
    for key in ("ngram", "suffixes"):
        if {k: v["sha256"] for k, v in report.get(key, {}).items()} != {k: v["sha256"] for k, v in meta[key].items()}:
            what = 'n-gram dictionary' if key == 'ngram' else 'public suffix list'
            print(f"ml-data/{name}.pkl was built with another {what} than the model: create it again with --{name}.",
                  file=stderr)
            exit(1)
    if {k: v["sha256"] for k, v in report.get("training", {}).items()} != \
            {k: v["sha256"] for k, v in meta["data"].items()}:
        print(f"ml-data/{name}.pkl excludes the training data of another data set than the model's "
              f"({meta['set']}): create it again with --{name} --set {meta['set']}.", file=stderr)
        exit(1)
    df = pd.read_pickle(f'ml-data/{name}.pkl')
    results = evaluate(df, dataset, model, sc)
    # Keep the metrics with the model, next to the exclusion counts of the evaluation set (C5)
    meta["evaluations"][name] = {"set": report["set"], "created": report["created"], "origins": report["origins"],
                                 **results}
    with open(modelfiles(dataset)[2], 'w') as f:
        json.dump(meta, f, indent=2)


def evaluate(df, dataset, model, sc):
    '''
    Print the metrics of a model on an evaluation set, in total and by origin (the part of family before ":")
    :param df: DataFrame with the columns of COLUMNS
    :param dataset: model (full, tiny...), to drop the columns it doesn't use
    :param model: trained model with a predict() method
    :param sc: scaler with a transform() method
    :return: dict with the metrics (metrics()) and the metrics by origin
    '''
    origins = df['family'].str.split(':').str[0].values
    df = df.copy()

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

    # Scale data and predict
    y_pred = model.predict(sc.transform(X))

    # Show results
    print(f"Confussion matrix:")
    print(confusion_matrix(y, y_pred, labels=[0, 1]))
    print(f"Classification report:")
    print(classification_report(y, y_pred, labels=[0, 1], zero_division=0))
    print(f"Accuracy Score: {accuracy_score(y, y_pred)}")
    print(f"By origin:")
    results = {"metrics": metrics(y, y_pred), "by_origin": {}}
    for origin in dict.fromkeys(origins):
        mask = origins == origin
        print(f"  {origin}: {mask.sum()} domains, {int((y_pred[mask] == 1).sum())} detected as DGA, "
              f"accuracy {accuracy_score(y[mask], y_pred[mask]):.3f}")
        results["by_origin"][origin] = {"domains": int(mask.sum()), "detected": int((y_pred[mask] == 1).sum()),
                                        "accuracy": accuracy_score(y[mask], y_pred[mask])}
    return results


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
    # Load model and scaler, checking the dictionary and the suffix list they go with
    model, sc, meta = loadmodel("full")
    loadetlds()
    ng = loadngram(NGRAM)
    requirebrown()
    LP = LegalitySyllableTokenizer(brown.words())

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
    return [f for f in ngramfiles() if not isfile(f)]


def checktranco():
    return not missingngram()


def tranconotfound():
    print(f"Tranco dictionary not found at ml-data (missing {', '.join(missingngram())}). "
          f"Download it with python fetchdata.py, or create it with --ngram option.")
    exit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ngram",
                                help="create the standard Tranco ngram dictionary, saving it in ml-data/tranco.ng*.csv",
                                action="store_true")
    parser.add_argument("--main",
                                help="create the main dataset and save it in ml-data/main.pkl", action="store_true")
    parser.add_argument("--secondary",
                                help="create the secondary dataset and save it in ml-data/secondary.pkl", action="store_true")
    parser.add_argument("--umbrella",
                                help="create the Umbrella dataset and save it in ml-data/umbrella.pkl", action="store_true")
    parser.add_argument("--alexa",
                                help="deprecated alias of --umbrella", action="store_true")
    parser.add_argument("--set", choices=['2021', '2026'], default=DATASET,
                                help=f"data set of the input files of --ngram, --main, --secondary and --umbrella "
                                     f"(default {DATASET})")
    parser.add_argument("--train", type=str,
                                help="Train the Check the given domains (full|ngram|nongram|nosyll|nongramnosyll|tiny)",
                                choices=['full', 'ngram', 'nongram', 'nosyll', 'nongramnosyll', 'tiny'])
    parser.add_argument("--test_secondary", type=str,
                                help="test the secondary dataset of ml-data/secondary.pkl (full|ngram|nongram|nosyll|nongramnosyll|tiny)",
                                choices=['full', 'ngram', 'nongram', 'nosyll', 'nongramnosyll', 'tiny'])
    parser.add_argument("--test_umbrella", type=str,
                                help="test the Umbrella dataset of ml-data/umbrella.pkl (full|ngram|nongram|nosyll|nongramnosyll|tiny)",
                                choices=['full', 'ngram', 'nongram', 'nosyll', 'nongramnosyll', 'tiny'])
    parser.add_argument("--test_alexa", type=str,
                                help="deprecated alias of --test_umbrella",
                                choices=['full', 'ngram', 'nongram', 'nosyll', 'nongramnosyll', 'tiny'])
    parser.add_argument("--check", nargs="+", type=str,
                                help="Check the given domains")
    parser.add_argument("-b", "--bruteforce",
                        help="if check is selected, test DGA detected domains by bruteforce", action="store_true")
    args = parser.parse_args()

    # The Alexa ranking was retired in 2022 and alexa.dom shared 62% of its domains with the training data (C3)
    if args.alexa:
        print("--alexa is deprecated: it now runs --umbrella", file=stderr)
        args.umbrella = True
    if args.test_alexa:
        print("--test_alexa is deprecated: it now runs --test_umbrella", file=stderr)
        args.test_umbrella = args.test_alexa

    if args.main:
        # Create the main dataset and save it in ml-data/main.pkl
        if checktranco():
            requirefiles([TRAINING[args.set]["main"], TRAINING[args.set]["dga"]], FETCHSET[args.set])
            createmaindataset(dataset=args.set)
        else:
            tranconotfound()
    elif args.secondary:
        # Create the secondary test dataset
        if checktranco():
            createtestdataset(dataset=args.set)
        else:
            tranconotfound()
    elif args.umbrella:
        # Create the Umbrella test dataset
        if checktranco():
            createumbrelladataset(dataset=args.set)
        else:
            tranconotfound()
    elif args.ngram:
        # Create the standard Tranco ngram dictionary
        requirefiles([TRAINING[args.set]["ngram"]], FETCHSET[args.set])
        createstdngram(dataset=args.set)
    elif args.train:
        # Train our model
        traindata(dataset=args.train)
    elif args.test_secondary:
        # Train our model
        testsecdata(dataset=args.test_secondary, name="secondary")
    elif args.test_umbrella:
        testsecdata(dataset=args.test_umbrella, name="umbrella")
    elif args.check:
        testdomains(args.check, brute=args.bruteforce)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
