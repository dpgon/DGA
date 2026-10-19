'''
Characterization tests of the statsdga.py menu (docs/MVP.md section 10), driven through the standard input.
statsdga.py runs its menu on import, so it can only be tested as a script.
'''
import os

import pytest

from conftest import ROOT, run


def test_max_domains(nltk_data):
    out = run("statsdga.py", stdin="1\n50\n0\n").stdout
    assert "dircrypt has a limit of 30 domains in a date" in out


def test_collisions(nltk_data):
    out = run("statsdga.py", stdin="2\n50\n0\n").stdout
    assert "kraken2: 50 generated and 45 unique" in out


@pytest.mark.slow
def test_syllables_dga(nltk_data):
    lines = run("statsdga.py", stdin="8\n50\nn\n0\n").stdout.splitlines()
    pos = next(i for i, line in enumerate(lines) if line.strip() == "All DGA:")
    assert "Average syllable lenght is" in lines[pos + 1]
    assert "Min syllable lenght is" in lines[pos + 2]
    assert "Max syllable lenght is" in lines[pos + 3]


# --- C3: the real domains come from the Tranco list of the 2026 data set (ml-data/tranco.csv) -------------

def test_real_domains_from_tranco(nltk_data):
    if not os.path.isfile(os.path.join(ROOT, "ml-data", "tranco.csv")):
        pytest.skip("missing ml-data/tranco.csv: run python fetchdata.py --set 2026")
    out = run("statsdga.py", stdin="4\n1\ny\n0\n").stdout
    assert "Tranco" in out and "Alexa" not in out
    assert "times" in out


def test_missing_tranco_asks_for_fetchdata(tmp_path, nltk_data):
    os.symlink(os.path.join(ROOT, "DGAs"), tmp_path / "DGAs")
    proc = run("statsdga.py", stdin="4\n1\ny\n0\n", cwd=tmp_path)
    assert "python fetchdata.py --set 2026" in proc.stdout + proc.stderr
    assert proc.returncode != 0
