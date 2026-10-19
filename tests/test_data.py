'''
Checks of the data files listed in ml-data/MANIFEST (C3, C8): the installed files match the manifest, and the
three Tranco splits of each data set don't share any domain. Files that are not installed are skipped
(python fetchdata.py, or fetchdata.py --set 2026). They read hundreds of MB: marked slow.
'''
import os

import pytest

from conftest import ROOT

import fetchdata

pytestmark = pytest.mark.slow

ENTRIES = fetchdata.readmanifest(os.path.join(ROOT, "ml-data", "MANIFEST"))
SPLITS = {
    "2021": ["ml-data/tranco-main.dom", "ml-data/tranco-test2.dom", "ml-data/tranco-ngram.dom"],
    "2026": ["ml-data/2026/tranco-main.dom", "ml-data/2026/tranco-test2.dom", "ml-data/2026/tranco-ngram.dom"],
}


def installed(name):
    path = os.path.join(ROOT, name)
    if not os.path.isfile(path):
        pytest.skip(f"{name} is not installed")
    return path


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e["file"])
def test_file_matches_manifest(entry):
    path = installed(entry["file"])
    assert os.path.getsize(path) == entry["size"]
    assert fetchdata.sha256(path) == entry["sha256"]


@pytest.mark.parametrize("dataset", sorted(SPLITS))
def test_tranco_splits_are_disjoint(dataset):
    seen = {}
    for name in SPLITS[dataset]:
        with open(installed(name)) as f:
            domains = {line.strip() for line in f if line.strip()}
        for other, previous in seen.items():
            common = domains & previous
            assert not common, f"{name} and {other} share {len(common)} domains, e.g. {sorted(common)[:3]}"
        seen[name] = domains


def test_every_file_of_a_set_is_in_the_manifest_once():
    for dataset in ("2021", "2026"):
        files = [e["file"] for e in ENTRIES if dataset in e["set"]]
        assert len(files) == len(set(files))
