'''
Tests of how detectdga.py saves and loads its models (C2, C10): skops instead of pickle, a metadata file that ties
the model to its scaler, n-gram dictionary and public suffix list, and n_jobs adapted to the machine. They train a
small model on random data in a temporary repository, so they don't need the real one.
'''
import io
import json
import os
import pickle

import numpy as np
import pandas as pd
import pytest
import skops.io

from conftest import ROOT

import detectdga


class Untrusted:
    # A type skops has never heard of: a model file that contains it must not load
    def predict(self, X):
        return np.zeros(len(X))


def write_ngram(path):
    for n in range(1, 5):
        with open(f"{path}.ng{n}.csv", "w") as f:
            f.write("ngram,value\nab,1.0\n")


@pytest.fixture
def messages(monkeypatch):
    # detectdga.py imports stderr from sys when it is first imported, so capsys doesn't see its messages
    stream = io.StringIO()
    monkeypatch.setattr(detectdga, "stderr", stream)
    return stream


@pytest.fixture
def model_repo(tmp_path, monkeypatch):
    '''
    Repository with DGAs/, a small n-gram dictionary and a main data set of 400 random rows, as --main leaves them
    '''
    os.symlink(os.path.join(ROOT, "DGAs"), tmp_path / "DGAs")
    (tmp_path / "ml-data").mkdir()
    monkeypatch.chdir(tmp_path)
    write_ngram(detectdga.NGRAM)
    rng = np.random.default_rng(1)
    rows = []
    for c in range(400):
        dga = c % 2
        rows.append([f"d{c}", "com", "tranco" if not dga else "banjori", dga] + list(rng.random(24) + dga))
    pd.DataFrame(rows, columns=detectdga.COLUMNS).to_pickle("ml-data/main.pkl")
    main = {"set": "2026", "created": "2026-10-19T00:00:00",
            "files": {"ml-data/2026/tranco-main.dom": {"sha256": "1" * 64, "source": "Tranco list 467YX"}},
            "ngram": detectdga.describefiles(detectdga.ngramfiles()),
            "suffixes": detectdga.describefiles([detectdga.ETLDS]), "domains": 400}
    with open("ml-data/main.json", "w") as f:
        json.dump(main, f)
    return tmp_path


@pytest.fixture
def trained(model_repo):
    detectdga.traindata("full")
    return model_repo


def test_train_saves_skops_and_metadata(trained):
    assert {"full.skops", "full-scaler.skops", "full.json"} <= set(os.listdir("ml-data"))
    assert not os.path.exists("ml-data/full.pkl")
    with open("ml-data/full.json") as f:
        meta = json.load(f)
    assert meta["model"] == "full" and meta["set"] == "2026"
    assert {"python", "created", "libraries", "data", "ngram", "suffixes", "hyperparameters", "features",
            "test_split", "files", "evaluations"} <= set(meta)
    assert {"scikit-learn", "skops", "numpy", "pandas", "nltk"} <= set(meta["libraries"])
    assert meta["data"]["ml-data/2026/tranco-main.dom"]["source"] == "Tranco list 467YX"
    assert set(meta["ngram"]) == set(detectdga.ngramfiles())
    assert meta["suffixes"][detectdga.ETLDS]["sha256"] == detectdga.sha256(detectdga.ETLDS)
    assert meta["hyperparameters"] == {"n_estimators": 30, "random_state": 1, "min_samples_leaf": 5, "n_jobs": -1}
    assert meta["features"] == detectdga.COLUMNS[4:]
    assert 0 <= meta["test_split"]["metrics"]["accuracy"] <= 1


def test_load_without_pickle(trained, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("pickle must not be used to load the model")
    monkeypatch.setattr(pickle, "load", refuse)
    monkeypatch.setattr(pickle, "loads", refuse)
    model, sc, meta = detectdga.loadmodel("full")
    X = np.random.default_rng(2).random((3, 24))
    assert len(model.predict(sc.transform(X))) == 3


def test_load_sets_n_jobs(trained):
    # A model trained on another machine may say n_jobs=14; it must use the cores of this one (C10)
    model, sc, meta = detectdga.loadmodel("full")
    model.n_jobs = 14
    skops.io.dump(model, "ml-data/full.skops")
    meta["files"]["ml-data/full.skops"] = detectdga.sha256("ml-data/full.skops")
    with open("ml-data/full.json", "w") as f:
        json.dump(meta, f)
    model, sc, meta = detectdga.loadmodel("full")
    assert model.n_jobs == -1


@pytest.mark.parametrize("name", ["ml-data/tranco.ng2.csv", "DGAs/wordlist/effective_tld_names.dat",
                                  "ml-data/full-scaler.skops"])
def test_altered_file_is_rejected(trained, messages, name):
    with open("ml-data/full.json") as f:
        meta = json.load(f)
    # Change the expected hash instead of the file: DGAs/ is a link to the real repository
    for group in ("ngram", "suffixes"):
        if name in meta[group]:
            meta[group][name]["sha256"] = "0" * 64
    if name in meta["files"]:
        meta["files"][name] = "0" * 64
    with open("ml-data/full.json", "w") as f:
        json.dump(meta, f)
    with pytest.raises(SystemExit) as e:
        detectdga.loadmodel("full")
    assert e.value.code == 1
    assert f"{name} doesn't match the model" in messages.getvalue()


def test_altered_ngram_file_is_rejected(trained, messages):
    with open("ml-data/tranco.ng3.csv", "a") as f:
        f.write("zz,0.5\n")
    with pytest.raises(SystemExit):
        detectdga.loadmodel("full")
    assert "ml-data/tranco.ng3.csv doesn't match the model" in messages.getvalue()


def test_untrusted_type_is_rejected(trained, messages):
    skops.io.dump(Untrusted(), "ml-data/full.skops")
    with open("ml-data/full.json") as f:
        meta = json.load(f)
    meta["files"]["ml-data/full.skops"] = detectdga.sha256("ml-data/full.skops")
    with open("ml-data/full.json", "w") as f:
        json.dump(meta, f)
    with pytest.raises(SystemExit) as e:
        detectdga.loadmodel("full")
    assert e.value.code == 1
    err = messages.getvalue()
    assert "Refusing to load the model" in err and "Untrusted" in err


def test_missing_metadata_asks_for_fetchdata(trained, messages):
    os.remove("ml-data/full.json")
    with pytest.raises(SystemExit):
        detectdga.loadmodel("full")
    assert "python fetchdata.py" in messages.getvalue()


def test_evaluation_metrics_are_kept_with_the_model(trained):
    # --test_secondary adds the metrics and the exclusion counts of the evaluation set to the metadata
    with open("ml-data/main.json") as f:
        main = json.load(f)
    df = pd.read_pickle("ml-data/main.pkl").head(20)
    df.to_pickle("ml-data/secondary.pkl")
    report = {"set": "2026", "created": "2026-10-19T00:00:00", "files": {}, "training": main["files"],
              "ngram": main["ngram"], "suffixes": main["suffixes"],
              "origins": {"tranco": {"read": 12, "invalid": 0, "excluded": 2, "kept": 10}}}
    with open("ml-data/secondary.json", "w") as f:
        json.dump(report, f)
    detectdga.testsecdata("full", "secondary")
    with open("ml-data/full.json") as f:
        meta = json.load(f)
    evaluation = meta["evaluations"]["secondary"]
    assert evaluation["origins"]["tranco"]["excluded"] == 2
    assert 0 <= evaluation["metrics"]["accuracy"] <= 1
    assert set(evaluation["by_origin"]) == {"tranco", "banjori"}


def test_evaluation_set_of_another_dictionary_is_rejected(trained, messages):
    with open("ml-data/main.json") as f:
        main = json.load(f)
    pd.read_pickle("ml-data/main.pkl").head(20).to_pickle("ml-data/secondary.pkl")
    ngram = {k: {"sha256": "0" * 64, "source": ""} for k in main["ngram"]}
    report = {"set": "2026", "created": "", "files": {}, "training": main["files"], "ngram": ngram,
              "suffixes": main["suffixes"], "origins": {}}
    with open("ml-data/secondary.json", "w") as f:
        json.dump(report, f)
    with pytest.raises(SystemExit):
        detectdga.testsecdata("full", "secondary")
    assert "another n-gram dictionary" in messages.getvalue()


class Recorder:
    # Scaler that keeps the feature vectors classify() computes
    def transform(self, X):
        self.X = X
        return X


class Benign:
    def predict(self, X):
        return np.zeros(len(X))


@pytest.mark.slow
def test_feature_parity_with_the_main_dataset(nltk_data, monkeypatch):
    # The vector --check computes for a domain is the row --main computed for it, column by column (CLAUDE.md,
    # rule 4). The domain is rebuilt from sld and tld: --main took the n-grams from the domain as written
    monkeypatch.chdir(ROOT)
    if not (os.path.isfile("ml-data/main.pkl") and os.path.isfile("ml-data/main.json")):
        pytest.skip("missing ml-data/main.pkl: run python detectdga.py --main")
    with open("ml-data/main.json") as f:
        main = json.load(f)
    if any(detectdga.sha256(name) != v["sha256"] for name, v in {**main["ngram"], **main["suffixes"]}.items()):
        pytest.skip("ml-data/main.pkl was built with another n-gram dictionary or suffix list")
    rows = pd.read_pickle("ml-data/main.pkl").sample(100, random_state=1)
    ng, LP = detectdga.loadresources()
    scaler = Recorder()
    results = detectdga.classify(list(rows["sld"] + "." + rows["tld"]), Benign(), scaler, ng, LP)
    assert all(reason is None for domain, verdict, reason in results)
    assert np.array_equal(scaler.X, rows[detectdga.COLUMNS[4:]].values.astype(float))
