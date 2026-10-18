'''
Characterization tests of detectdga.py --check with the bundled 2021 model (docs/MVP.md sections 8-9).
They need ml-data/full.pkl, full-scaler.pkl, tranco.ng1-4 and the NLTK brown corpus (NLTK_DATA).
'''
import re

import pytest

from conftest import run

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


@pytest.mark.slow
def test_check_bruteforce(nltk_data):
    out = run("detectdga.py", "-b", "--check", "nvfowikhevmy.net").stdout
    assert "Detected as tinba in 10 position" in out
