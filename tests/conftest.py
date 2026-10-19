import os
import re
import subprocess
import sys
import time
from os.path import abspath, dirname, isdir, join

import pytest

ROOT = dirname(dirname(abspath(__file__)))
ANSI = re.compile(r'\x1b\[[0-9;]*m')

# The project modules (dga, ngram, DGAs) live in the repository root, not in an installed package
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Several generators use time.mktime(), which works in local time: pykspa2 and suppobox give different
# domains in different time zones (and pykspa1, qadars, qsnatcha, qsnatchb, kraken2 may near their period
# boundaries). Tests always run in UTC, here and in the scripts they launch, so results do not depend on the
# machine. time.tzset() does not exist on Windows; there the TZ variable only reaches the launched scripts.
os.environ["TZ"] = "UTC"
if hasattr(time, "tzset"):
    time.tzset()


def strip(text):
    '''
    Remove the ANSI colour codes used by the scripts (class Col)
    :param text: output of a script
    :return: the same text without colour codes
    '''
    return ANSI.sub('', text)


def run(script, *args, stdin=None, timeout=900, cwd=ROOT):
    '''
    Run a script of the repository, by default from its root as the README says
    :param script: script name, e.g. lookdga.py
    :param args: command line arguments
    :param stdin: text sent to the standard input
    :param timeout: seconds before failing
    :param cwd: working directory; the scripts resolve ml-data/ and DGAs/wordlist/ against it
    :return: CompletedProcess with stdout and stderr already without colour codes
    '''
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run([sys.executable, join(ROOT, script), *args], cwd=cwd, env=env, input=stdin,
                          capture_output=True, text=True, timeout=timeout)
    proc.stdout = strip(proc.stdout)
    proc.stderr = strip(proc.stderr)
    return proc


NGRAM_FILES = [f"tranco.ng{n}.csv" for n in range(1, 5)]
MODEL_FILES = ["full.skops", "full-scaler.skops", "full.json"] + NGRAM_FILES


def missingdata(names):
    return [n for n in names if not os.path.isfile(join(ROOT, "ml-data", n))]


def pytest_runtest_setup(item):
    # The data files are downloaded with fetchdata.py (C8); without them the model tests can't run
    if item.get_closest_marker("model") and missingdata(MODEL_FILES):
        pytest.skip(f"missing ml-data/{', ml-data/'.join(missingdata(MODEL_FILES))}: run python fetchdata.py")


@pytest.fixture
def nltk_data():
    '''
    Skip the test when the NLTK brown corpus is not available, so the scripts never download it during tests.
    Set NLTK_DATA to a directory with corpora/brown (python -m nltk.downloader -d <dir> brown).
    '''
    path = os.environ.get("NLTK_DATA")
    if not path or not isdir(join(path, "corpora", "brown")):
        pytest.skip("NLTK_DATA with corpora/brown is required")
    return path


@pytest.fixture
def strip_ansi():
    return strip


def head(src, dst, lines):
    with open(src) as fin, open(dst, "w") as fout:
        for c, line in enumerate(fin):
            if c >= lines:
                break
            fout.write(line)


@pytest.fixture
def repo_tmp(tmp_path):
    '''
    Working directory with a link to DGAs/ and a small ml-data/: the real n-gram dictionary and the first lines
    of the domain lists of the 2026 data set. Scripts run with run(..., cwd=repo_tmp) write there instead of the
    real ml-data/.
    '''
    lists = ["2026/tranco-main.dom", "2026/tranco-test2.dom", "2026/tranco-ngram.dom", "2026/mydgas.dom", "hf-dga.dom"]
    needed = NGRAM_FILES + lists + ["dga.dom"]
    if missingdata(needed):
        pytest.skip(f"missing ml-data/{', ml-data/'.join(missingdata(needed))}: run python fetchdata.py")
    os.symlink(join(ROOT, "DGAs"), tmp_path / "DGAs")
    data = tmp_path / "ml-data"
    (data / "2026").mkdir(parents=True)
    for name in NGRAM_FILES:
        os.symlink(join(ROOT, "ml-data", name), data / name)
    for name in lists:
        head(join(ROOT, "ml-data", name), data / name, 20)
    # dga.dom starts with a comment header: keep it and 20 data lines
    head(join(ROOT, "ml-data", "dga.dom"), data / "dga.dom", 40)
    return tmp_path
