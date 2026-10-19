'''
Characterization tests of detectdga.py --check with the model of the 2026 data set (docs/MVP.md sections 8-9; the
README example gives the same verdicts as the 2021 model). They need ml-data/full.skops, full-scaler.skops,
full.json, tranco.ng1-4.csv and the NLTK brown corpus (NLTK_DATA).
'''
import csv
import os
import re

import pytest

from conftest import ROOT, run

pytestmark = pytest.mark.model


def verdicts(text):
    '''
    Parse the --check output into {domain: verdict}
    :param text: stdout of detectdga.py --check
    :return: dict with "DGA generated" or "No DGA domain" for every printed domain
    '''
    result = {}
    domain = None
    for line in text.splitlines():
        match = re.match(r'^(\S+):$', line)
        if match:
            domain = match.group(1)
        elif domain and ("DGA generated" in line or "No DGA domain" in line):
            result[domain] = line.split("|__")[1].strip()
            domain = None
    return result


def test_check_readme_example(nltk_data):
    out = run("detectdga.py", "--check", "ughdnmmgdpscliraqnpl.com", "nvfowikhevmy.net",
              "uquslaigwaannie.ddns.net", "google.com", "facebook.com").stdout
    assert verdicts(out) == {
        "ughdnmmgdpscliraqnpl.com": "DGA generated",
        "nvfowikhevmy.net": "DGA generated",
        "uquslaigwaannie.ddns.net": "DGA generated",
        "google.com": "No DGA domain",
        "facebook.com": "No DGA domain",
    }


def test_check_well_known_domains(nltk_data):
    out = run("detectdga.py", "--check", "google.com", "facebook.com", "wikipedia.org").stdout
    assert set(verdicts(out).values()) == {"No DGA domain"} and len(verdicts(out)) == 3


def test_check_netlab_reference(nltk_data):
    # Domains of the 11 families confirmed by the 360 Netlab feed (C2). They are in dga.dom, the training data, so
    # this is a sanity check, not a metric: the 2026 model detects 172 of 188. A threshold, not equality, so that
    # a retrained model can pass
    with open(os.path.join(ROOT, "tests", "data", "referencia_netlab.csv")) as f:
        domains = [row["domain"] for row in csv.DictReader(line for line in f if not line.startswith("#"))]
    result = verdicts(run("detectdga.py", "--check", *domains).stdout)
    assert len(result) == len(domains)
    assert sum(v == "DGA generated" for v in result.values()) >= 0.85 * len(domains)


@pytest.mark.slow
def test_check_bruteforce(nltk_data):
    out = run("detectdga.py", "-b", "--check", "nvfowikhevmy.net").stdout
    assert "Detected as tinba in 10 position" in out


# --- C12: every verdict must belong to its own domain (docs/CORRECCIONES.md) -------------------------------

@pytest.mark.model
def test_check_pairs_verdicts_with_domains(nltk_data):
    # bbc.com is discarded (SLD of 3 characters); before C12 its neighbour's verdict was printed next to it
    out = run("detectdga.py", "--check", "bbc.com", "google.com", "ughdnmmgdpscliraqnpl.com").stdout
    assert verdicts(out) == {"google.com": "No DGA domain", "ughdnmmgdpscliraqnpl.com": "DGA generated"}
    assert "bbc.com: SLD of 3 characters or fewer" in out


@pytest.mark.model
def test_check_all_discarded(nltk_data):
    proc = run("detectdga.py", "--check", "bbc.com")
    assert proc.returncode == 0
    assert "Traceback" not in proc.stderr
    assert "bbc.com: SLD of 3 characters or fewer" in proc.stdout


class FakeModel:
    # Returns the first feature (len(sld)/63) as the verdict, so each verdict tells which domain it came from
    def __init__(self):
        self.calls = 0

    def predict(self, X):
        self.calls += 1
        return [row[0] for row in X]


class FakeScaler:
    def transform(self, X):
        return X


class FakeNgram:
    def getall(self, domain, n):
        return 0.0, 0.0, 0.0


class FakeTokenizer:
    def tokenize(self, word):
        return [word]


@pytest.fixture
def detect(nltk_data):
    import detectdga
    detectdga.loadetlds()
    return detectdga


def classify(detect, domains, model=None):
    return detect.classify(domains, model or FakeModel(), FakeScaler(), FakeNgram(), FakeTokenizer())


def test_classify_pairs_by_domain(detect):
    results = classify(detect, ["bbc.com", "google.com", "ughdnmmgdpscliraqnpl.com"])
    assert [(r[0], r[1], r[2]) for r in results] == [
        ("bbc.com", None, "SLD of 3 characters or fewer"),
        ("google.com", 6 / 63, None),
        ("ughdnmmgdpscliraqnpl.com", 20 / 63, None),
    ]


def test_classify_nothing_to_evaluate(detect):
    model = FakeModel()
    results = classify(detect, ["bbc.com"], model)
    assert results == [("bbc.com", None, "SLD of 3 characters or fewer")]
    assert model.calls == 0


def test_classify_lowercases(detect):
    assert classify(detect, ["GOOGLE.COM"]) == [("google.com", 6 / 63, None)]


def test_classify_unknown_suffix(detect):
    assert classify(detect, ["example.notasuffix"]) == [("example.notasuffix", None, "unknown suffix")]


def test_classify_subdomain(detect):
    # www. and subdomains are not evaluated (unchanged by C12), but the reason must say so
    assert classify(detect, ["www.google.com"]) == [
        ("www.google.com", None, "subdomain or www. prefix (only registrable domains are evaluated)")]
