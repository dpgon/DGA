'''
Tests of detectdga.py dataset commands on a small ml-data/ (fixture repo_tmp), so the real files are never
touched. They need the NLTK brown corpus (NLTK_DATA).
'''
import os

import pytest

from conftest import NGRAM_FILES, run


def test_secondary_uses_tranco_test2(repo_tmp, nltk_data):
    # C6: main() checked ml-data/tranco-secondary.dom but createtestdataset() reads ml-data/tranco-test2.dom
    proc = run("detectdga.py", "--secondary", cwd=repo_tmp)
    assert "not found" not in proc.stdout
    assert proc.returncode == 0
    assert (repo_tmp / "ml-data" / "secondary.pkl").is_file()


@pytest.mark.parametrize("missing", NGRAM_FILES)
def test_main_reports_missing_ngram_file(repo_tmp, nltk_data, missing):
    # C9: checktranco() looked four times at tranco.ng1, so a missing ng2-ng4 failed later without saying why
    os.remove(repo_tmp / "ml-data" / missing)
    proc = run("detectdga.py", "--main", cwd=repo_tmp)
    assert proc.returncode != 0
    assert f"ml-data/{missing}" in proc.stdout + proc.stderr
    assert not (repo_tmp / "ml-data" / "main.pkl").exists()


@pytest.fixture
def empty_repo(tmp_path):
    # A clone that has not run fetchdata.py yet: DGAs/ is there but ml-data/ is empty
    os.symlink(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "DGAs"),
               tmp_path / "DGAs")
    (tmp_path / "ml-data").mkdir()
    return tmp_path


@pytest.mark.parametrize("args", [["--check", "google.com"], ["--test_secondary", "full"],
                                  ["--test_alexa", "full"]])
def test_missing_data_asks_for_fetchdata(empty_repo, nltk_data, args):
    # C8: the data files are no longer in git; without them the scripts must say how to get them
    proc = run("detectdga.py", *args, cwd=empty_repo)
    assert proc.returncode != 0
    assert "python fetchdata.py" in proc.stdout + proc.stderr
    assert "Traceback" not in proc.stderr
