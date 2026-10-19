'''
Tests of the n-gram dictionary of ngram.py (C2): it is saved as one CSV file per order (<name>.ng1.csv ...
<name>.ng4.csv, columns ngram,value) instead of pickles, and loading it gives the same values.
'''
import csv
import os

import pytest

from conftest import ROOT

from ngram import ngrams

# n-grams that a careless CSV reader would turn into something else: "null" and "nan" into NaN, quotes and commas
# into broken fields. The quote also broke the eval() lookup of _checkdom(). One domain is repeated so that the
# counts differ and the scaled values are not all 0
DOMAINS = ["nullnanny.com", "abc'defg.com", "abc'defg.com", 'quo"tedname.net', "comma,name.org", "kimiaco.com",
           "www2.short.com"]


@pytest.fixture
def trained():
    ng = ngrams()
    ng.train(DOMAINS)
    return ng


def test_save_writes_one_csv_per_order(trained, tmp_path):
    trained.save(str(tmp_path / "dict"))
    for n in range(1, 5):
        with open(tmp_path / f"dict.ng{n}.csv", newline="", encoding="utf-8") as f:
            rows = list(csv.reader(f))
        assert rows[0] == ["ngram", "value"]
        assert len(rows) - 1 == len(getattr(trained, f"ngram{n}"))


def test_save_and_load_keep_every_value(trained, tmp_path):
    trained.save(str(tmp_path / "dict"))
    loaded = ngrams()
    loaded.load(str(tmp_path / "dict"))
    for n in range(1, 5):
        assert getattr(loaded, f"ngram{n}") == getattr(trained, f"ngram{n}")
    assert "null" in loaded.ngram4 and "nann" in loaded.ngram4
    assert "c'de" in loaded.ngram4 and 'o"te' in loaded.ngram4 and "a,na" in loaded.ngram4


def test_getall_with_quotes(trained, tmp_path):
    trained.save(str(tmp_path / "dict"))
    loaded = ngrams()
    loaded.load(str(tmp_path / "dict"))
    for domain in DOMAINS:
        for n in range(1, 5):
            assert loaded.getall(domain, n) == trained.getall(domain, n)
    mean, median, stddev = loaded.getall("abc'defg.com", 4)
    assert mean > 0


def test_values_are_scaled_between_0_and_1(trained):
    for n in range(1, 5):
        values = getattr(trained, f"ngram{n}").values()
        # MinMaxScaler may leave the maximum one unit in the last place below 1, as it did in 2021
        assert min(values) == 0 and max(values) == pytest.approx(1)


def frames2021():
    # The 2021 dictionary (pandas pickles, release v2021). Loaded only here, from files whose SHA-256 the manifest
    # fixes (test_data.py), to check the conversion
    names = [os.path.join(ROOT, "ml-data", f"tranco.ng{n}") for n in range(1, 5)]
    if not all(os.path.isfile(name) for name in names):
        pytest.skip("missing the 2021 n-gram dictionary: run python fetchdata.py --set 2021")
    import pandas as pd
    return [pd.read_pickle(name) for name in names]


def old_checkdom(frame, domain, l):
    # The lookup of _checkdom() in 2021: membership in the index of the Series, then its value
    import numpy as np
    data = []
    for c in range(len(domain) - l + 1):
        ng = domain[c:c + l]
        data.append(frame['value'][ng] if ng in frame['value'] else 0)
    return np.mean(data), np.median(data), np.std(data)


# Unpickling the pandas 1.3 frames warns about numpy.core, renamed in numpy 2
@pytest.mark.filterwarnings("ignore:numpy.core:DeprecationWarning")
def test_2021_dictionary_converted_gives_the_same_results(tmp_path):
    frames = frames2021()
    converted = ngrams()
    for n, frame in enumerate(frames, 1):
        setattr(converted, f"ngram{n}", {key: float(value) for key, value in frame['value'].items()})
    converted.save(str(tmp_path / "tranco"))
    loaded = ngrams()
    loaded.load(str(tmp_path / "tranco"))
    domains = ["google.com", "ughdnmmgdpscliraqnpl.com", "nvfowikhevmy.net", "uquslaigwaannie.ddns.net",
               "facebook.com", "wikipedia.org", "nullable.com", "el_dwarf.com", "qqqqzzzz.com"]
    for domain in domains:
        sld = domain.split('.')[0]
        for n, frame in enumerate(frames, 1):
            assert loaded.getall(domain, n) == old_checkdom(frame, sld, n)
