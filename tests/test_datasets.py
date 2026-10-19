'''
Evaluation data sets of detectdga.py (C5, C3): they never share a domain or an SLD with the data the model of
their data set is built from (2026/tranco-main.dom, 2026/tranco-ngram.dom, dga.dom), and they report how many
domains were excluded.
They run on a small repository in tmp_path with known overlaps. They need the NLTK brown corpus (NLTK_DATA).
'''
import json
import os

import pandas as pd
import pytest

from conftest import NGRAM_FILES, ROOT, missingdata, run


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


@pytest.fixture
def small_repo(tmp_path):
    '''
    Training data: google.com, example.org (tranco-main), wikipedia.org (tranco-ngram) and qwertyuiopas.com
    (dga.dom). The evaluation files repeat some of them, with other suffixes or in upper case.
    '''
    if missingdata(NGRAM_FILES):
        pytest.skip("missing the n-gram dictionary: run python fetchdata.py")
    os.symlink(os.path.join(ROOT, "DGAs"), tmp_path / "DGAs")
    data = tmp_path / "ml-data"
    data.mkdir()
    for name in NGRAM_FILES:
        os.symlink(os.path.join(ROOT, "ml-data", name), data / name)
    write(data / "2026" / "tranco-main.dom", "google.com\nexample.org\n")
    write(data / "2026" / "tranco-ngram.dom", "wikipedia.org\n")
    write(data / "dga.dom", "# header\nbanjori\tqwertyuiopas.com\t2021-08-08 00:00:00\t2021-08-08 23:59:59\n")
    write(data / "2026" / "tranco-test2.dom", "GOOGLE.com\ngoogle.de\nwikipedia.org\nnewsite.net\nfreshdomain.com\n")
    write(data / "2026" / "mydgas.dom", "qwertyuiopas.com,banjori,None,2026-10-18\n"
                                        "abcdefghijk.net,banjori,None,2026-10-18\n")
    write(data / "hf-dga.dom", "# header\nmatsnu\tQWERTYUIOPAS.biz\nmatsnu\tzzyyxxwwvvuu.com\n")
    write(data / "umbrella-raw.csv", "1,com\r\n2,www.google.com\r\n3,a.b.mynewshop.co.uk\r\n4,cdn.mynewshop.co.uk\r\n"
                                     "5,newsite.net\r\n6,api.wikipedia.org\r\n7,Shop.FreshDomain.com\r\n")
    return tmp_path


def rows(repo, name):
    df = pd.read_pickle(repo / "ml-data" / f"{name}.pkl")
    return sorted(zip(df["sld"] + "." + df["tld"], df["family"], df["dga"]))


def test_secondary_excludes_training_domains_and_slds(small_repo, nltk_data):
    proc = run("detectdga.py", "--secondary", "--set", "2026", cwd=small_repo)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert rows(small_repo, "secondary") == [
        ("abcdefghijk.net", "own:banjori", 1),
        ("freshdomain.com", "tranco", 0),
        ("newsite.net", "tranco", 0),
        ("zzyyxxwwvvuu.com", "hf:matsnu", 1),
    ]
    report = json.loads((small_repo / "ml-data" / "secondary.json").read_text())
    assert report["set"] == "2026"
    assert {o: report["origins"][o]["excluded"] for o in report["origins"]} == {"tranco": 3, "own": 1, "hf": 1}
    assert {o: report["origins"][o]["kept"] for o in report["origins"]} == {"tranco": 2, "own": 1, "hf": 1}
    assert "tranco: 2 kept, 3 excluded" in proc.stdout


def test_umbrella_reduces_to_registrable_domains(small_repo, nltk_data):
    proc = run("detectdga.py", "--umbrella", cwd=small_repo)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert rows(small_repo, "umbrella") == [
        ("freshdomain.com", "umbrella", 0),
        ("mynewshop.co.uk", "umbrella", 0),
        ("newsite.net", "umbrella", 0),
    ]
    report = json.loads((small_repo / "ml-data" / "umbrella.json").read_text())
    # google.com and wikipedia.org are in the training data; "com" has no registrable domain
    assert report["origins"]["umbrella"]["excluded"] == 2
    assert report["origins"]["umbrella"]["invalid"] == 1


def test_registrable_domain():
    import detectdga
    detectdga.loadetlds()
    assert detectdga.registrable("a.b.example.co.uk") == "example.co.uk"
    assert detectdga.registrable("www.google.com") == "google.com"
    assert detectdga.registrable("uquslaigwaannie.ddns.net") == "uquslaigwaannie.ddns.net"
    assert detectdga.registrable("com") is None


def test_alexa_options_are_deprecated_aliases(small_repo, nltk_data):
    proc = run("detectdga.py", "--alexa", cwd=small_repo)
    assert "deprecated" in proc.stderr and "--umbrella" in proc.stderr
    assert (small_repo / "ml-data" / "umbrella.pkl").is_file()
    proc = run("detectdga.py", "--test_alexa", "full", cwd=small_repo)
    assert "deprecated" in proc.stderr and "--test_umbrella" in proc.stderr


class FakeModel:
    # Predicts DGA when the first feature (len, already scaled by the identity scaler) is above 0.5
    def predict(self, X):
        return (X[:, 0] > 0.5).astype(int)


class Identity:
    def transform(self, X):
        return X


def test_evaluation_by_origin(capsys):
    import detectdga
    data = []
    for family, dga, length in [("tranco", 0, 0.1), ("tranco", 0, 0.9), ("umbrella", 0, 0.1),
                                ("own:banjori", 1, 0.9), ("own:tinba", 1, 0.1), ("hf:matsnu", 1, 0.9)]:
        data.append(["x", "com", family, dga, length] + [0] * 23)
    df = pd.DataFrame(data, columns=detectdga.COLUMNS)
    detectdga.evaluate(df, "full", FakeModel(), Identity())
    out = capsys.readouterr().out
    assert "Accuracy Score: 0.6666" in out
    assert "tranco: 2 domains, 1 detected as DGA, accuracy 0.500" in out
    assert "umbrella: 1 domains, 0 detected as DGA, accuracy 1.000" in out
    assert "own: 2 domains, 1 detected as DGA, accuracy 0.500" in out
    assert "hf: 1 domains, 1 detected as DGA, accuracy 1.000" in out
