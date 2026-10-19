'''
Tests of the SLD/TLD split of detectdga.py with each public suffix list (C7): the 2026 one, the default since the
model was retrained (DGAs/wordlist/effective_tld_names.dat), and the one the 2021 model was trained with
(ml-data/effective_tld_names-2021.dat, python fetchdata.py --set 2021).
'''
import os

import pytest

from conftest import ROOT

LISTS = {
    "2021": "ml-data/effective_tld_names-2021.dat",
    "2026": "DGAs/wordlist/effective_tld_names.dat",
}


@pytest.fixture(params=sorted(LISTS))
def suffixes(request):
    path = os.path.join(ROOT, LISTS[request.param])
    if not os.path.isfile(path):
        pytest.skip(f"missing {LISTS[request.param]}: run python fetchdata.py --set {request.param}")
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


def test_default_is_the_2026_list():
    import detectdga
    detectdga.loadetlds()
    assert detectdga.etldsfile == LISTS["2026"]


def test_suffix_only_in_the_new_list():
    # a2hosted.com was added to the private section of the list after 2021
    old = os.path.join(ROOT, LISTS["2021"])
    if not os.path.isfile(old):
        pytest.skip(f"missing {LISTS['2021']}: run python fetchdata.py --set 2021")
    import detectdga
    detectdga.loadetlds(os.path.join(ROOT, LISTS["2026"]))
    assert detectdga.sldtld("example.a2hosted.com") == ("example", "a2hosted.com")
    detectdga.loadetlds(old)
    assert detectdga.sldtld("example.a2hosted.com") == (None, None)
    detectdga.loadetlds()
