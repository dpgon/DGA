'''
C11: importing the scripts must never download anything; a missing NLTK corpus is reported with the command
that installs it. The scripts run in a subprocess with NLTK_DATA pointing to an empty directory and with
nltk.download replaced by a function that fails, so these tests never reach the network.
'''
import os
import subprocess
import sys

from conftest import ROOT, strip

BOOM = "import nltk\n" \
       "def boom(*args, **kwargs):\n" \
       "    raise SystemExit('nltk.download was called')\n" \
       "nltk.download = boom\n"


def python(code, tmp_path, stdin=None):
    empty = tmp_path / "nltk_data"
    empty.mkdir()
    env = dict(os.environ, NLTK_DATA=str(empty), HOME=str(tmp_path), PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run([sys.executable, "-c", BOOM + code], cwd=ROOT, env=env, input=stdin,
                          capture_output=True, text=True, timeout=300)
    return proc.returncode, strip(proc.stdout + proc.stderr)


def test_import_detectdga_does_not_download(tmp_path):
    code, out = python("import detectdga\nprint('imported')", tmp_path)
    assert "nltk.download was called" not in out
    assert code == 0 and "imported" in out


def test_statsdga_reports_missing_corpus(tmp_path):
    # Option 8 (syllables) is the one that needs the corpus
    code, out = python("import runpy\nrunpy.run_path('statsdga.py', run_name='__main__')", tmp_path,
                       stdin="8\n50\nn\n0\n")
    assert "nltk.download was called" not in out
    assert "python -m nltk.downloader" in out
    assert code != 0
