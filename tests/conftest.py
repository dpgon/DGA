import os
import re
import subprocess
import sys
from os.path import abspath, dirname, isdir, join

import pytest

ROOT = dirname(dirname(abspath(__file__)))
ANSI = re.compile(r'\x1b\[[0-9;]*m')

# The project modules (dga, ngram, DGAs) live in the repository root, not in an installed package
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def strip(text):
    '''
    Remove the ANSI colour codes used by the scripts (class Col)
    :param text: output of a script
    :return: the same text without colour codes
    '''
    return ANSI.sub('', text)


def run(script, *args, stdin=None, timeout=900):
    '''
    Run a script of the repository from its root, as the README says
    :param script: script name, e.g. lookdga.py
    :param args: command line arguments
    :param stdin: text sent to the standard input
    :param timeout: seconds before failing
    :return: CompletedProcess with stdout and stderr already without colour codes
    '''
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run([sys.executable, script, *args], cwd=ROOT, env=env, input=stdin,
                          capture_output=True, text=True, timeout=timeout)
    proc.stdout = strip(proc.stdout)
    proc.stderr = strip(proc.stderr)
    return proc


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
