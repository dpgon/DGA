'''
Tests of the SLD/TLD split of detectdga.py with each public suffix list (C7): the 2021 one, which the bundled
model was trained with, and the new one of the 2026 data set (ml-data/public_suffix_list.dat, fetchdata.py --set
2026). The new list is only prepared here; detectdga.py keeps using the 2021 one until the model is retrained.
'''
import os

import pytest

from conftest import ROOT

LISTS = {
    "2021": "DGAs/wordlist/effective_tld_names.dat",
    "2026": "ml-data/public_suffix_list.dat",
}


@pytest.fixture(params=sorted(LISTS))
def suffixes(request):
    path = os.path.join(ROOT, LISTS[request.param])
    if not os.path.isfile(path):
        pytest.skip(f"missing {LISTS[request.param]}: run python fetchdata.py --set 2026")
    import detectdga
    detectdga.loadetlds(path)
    yield detectdga
    # Leave the default list loaded for the other tests
    detectdga.loadetlds()


def test_multilevel_suffix(suffixes):
    assert suffixes.sldtld("example.co.uk") == ("example", "co.uk")


def test_private_suffix(suffixes):
    assert suffixes.sldtld("uquslaigwaannie.ddns.net") == ("uquslaigwaannie", "ddns.net")


def test_short_sld_is_discarded(suffixes):
    assert suffixes.sldtldreason("bbc.com") == (None, None, "SLD of 3 characters or fewer")


def test_default_is_the_2021_list():
    import detectdga
    detectdga.loadetlds()
    assert detectdga.etldsfile == LISTS["2021"]


def test_suffix_only_in_the_new_list():
    # a2hosted.com was added to the private section of the list after 2021
    new = os.path.join(ROOT, LISTS["2026"])
    if not os.path.isfile(new):
        pytest.skip(f"missing {LISTS['2026']}: run python fetchdata.py --set 2026")
    import detectdga
    detectdga.loadetlds(new)
    assert detectdga.sldtld("example.a2hosted.com") == ("example", "a2hosted.com")
    detectdga.loadetlds(os.path.join(ROOT, LISTS["2021"]))
    assert detectdga.sldtld("example.a2hosted.com") == (None, None)
    detectdga.loadetlds()
