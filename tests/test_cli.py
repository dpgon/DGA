'''
Tests of detectdga.py dataset commands on a small ml-data/ (fixture repo_tmp), so the real files are never
touched. They need the NLTK brown corpus (NLTK_DATA).
'''
import os

import pytest

from conftest import run


def test_secondary_uses_tranco_test2(repo_tmp, nltk_data):
    # C6: main() checked ml-data/tranco-secondary.dom but createtestdataset() reads ml-data/tranco-test2.dom
    proc = run("detectdga.py", "--secondary", cwd=repo_tmp)
    assert "not found" not in proc.stdout
    assert proc.returncode == 0
    assert (repo_tmp / "ml-data" / "secondary.pkl").is_file()


@pytest.mark.parametrize("missing", ["tranco.ng1", "tranco.ng2", "tranco.ng3", "tranco.ng4"])
def test_main_reports_missing_ngram_file(repo_tmp, nltk_data, missing):
    # C9: checktranco() looked four times at tranco.ng1, so a missing ng2-ng4 failed later without saying why
    os.remove(repo_tmp / "ml-data" / missing)
    proc = run("detectdga.py", "--main", cwd=repo_tmp)
    assert proc.returncode != 0
    assert f"ml-data/{missing}" in proc.stdout + proc.stderr
    assert not (repo_tmp / "ml-data" / "main.pkl").exists()
