'''
Tests of fetchdata.py (C8) against a local http.server, so they never reach the network. Files are installed in a
temporary root with --root and described by a temporary manifest with --manifest.
'''
import functools
import hashlib
import http.server
import threading

import pytest

from conftest import ROOT, run

HEADER = "# test manifest\nfile\turl\tsize\tsha256\tsource\tlicense\tset\n"


@pytest.fixture
def server(tmp_path):
    '''
    Serve tmp_path/www over HTTP on a free local port
    :return: (directory served, base URL, list of requested paths)
    '''
    www = tmp_path / "www"
    www.mkdir()
    requests = []

    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            requests.append(self.path)

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0),
                                            functools.partial(Handler, directory=str(www)))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield www, f"http://127.0.0.1:{httpd.server_address[1]}", requests
    httpd.shutdown()
    httpd.server_close()


def entry(name, content, url, sha=None, sets="2021"):
    sha = sha or hashlib.sha256(content).hexdigest()
    return f"ml-data/{name}\t{url}/{name}\t{len(content)}\t{sha}\ttest\ttest\t{sets}\n"


def fetch(tmp_path, lines, *args):
    manifest = tmp_path / "MANIFEST"
    manifest.write_text(HEADER + "".join(lines))
    root = tmp_path / "repo"
    root.mkdir(exist_ok=True)
    return run("fetchdata.py", "--manifest", str(manifest), "--root", str(root), *args), root


def test_downloads_and_verifies(tmp_path, server):
    www, url, requests = server
    (www / "a.dom").write_bytes(b"example.com\n")
    proc, root = fetch(tmp_path, [entry("a.dom", b"example.com\n", url)])
    assert proc.returncode == 0, proc.stderr
    assert (root / "ml-data" / "a.dom").read_bytes() == b"example.com\n"
    assert requests == ["/a.dom"]


def test_wrong_hash_fails_and_leaves_nothing(tmp_path, server):
    www, url, requests = server
    (www / "a.dom").write_bytes(b"example.com\n")
    proc, root = fetch(tmp_path, [entry("a.dom", b"example.com\n", url, sha="0" * 64)])
    assert proc.returncode != 0
    assert "doesn't match" in proc.stderr
    assert list((root / "ml-data").iterdir()) == []


def test_second_run_downloads_nothing(tmp_path, server):
    www, url, requests = server
    (www / "a.dom").write_bytes(b"example.com\n")
    lines = [entry("a.dom", b"example.com\n", url)]
    fetch(tmp_path, lines)
    proc, root = fetch(tmp_path, lines)
    assert proc.returncode == 0
    assert "already installed" in proc.stdout
    assert requests == ["/a.dom"]


def test_existing_file_that_differs_is_kept(tmp_path, server):
    www, url, requests = server
    (www / "a.dom").write_bytes(b"example.com\n")
    root = tmp_path / "repo"
    (root / "ml-data").mkdir(parents=True)
    (root / "ml-data" / "a.dom").write_bytes(b"regenerated locally\n")
    proc, root = fetch(tmp_path, [entry("a.dom", b"example.com\n", url)])
    assert proc.returncode != 0
    assert (root / "ml-data" / "a.dom").read_bytes() == b"regenerated locally\n"
    assert requests == []


def test_only_the_selected_set(tmp_path, server):
    www, url, requests = server
    (www / "old.dom").write_bytes(b"old\n")
    (www / "new.dom").write_bytes(b"new\n")
    (www / "both.dom").write_bytes(b"both\n")
    lines = [entry("old.dom", b"old\n", url), entry("new.dom", b"new\n", url, sets="2026"),
             entry("both.dom", b"both\n", url, sets="2021,2026")]
    proc, root = fetch(tmp_path, lines, "--set", "2026")
    assert proc.returncode == 0, proc.stderr
    assert sorted(p.name for p in (root / "ml-data").iterdir()) == ["both.dom", "new.dom"]


def test_from_local_directory(tmp_path):
    local = tmp_path / "release"
    local.mkdir()
    (local / "a.dom").write_bytes(b"example.com\n")
    proc, root = fetch(tmp_path, [entry("a.dom", b"example.com\n", "http://127.0.0.1:9")], "--from", str(local))
    assert proc.returncode == 0, proc.stderr
    assert (root / "ml-data" / "a.dom").read_bytes() == b"example.com\n"


def test_from_local_directory_altered_file(tmp_path):
    local = tmp_path / "release"
    local.mkdir()
    (local / "a.dom").write_bytes(b"altered.com\n")
    proc, root = fetch(tmp_path, [entry("a.dom", b"example.com\n", "http://127.0.0.1:9")], "--from", str(local))
    assert proc.returncode != 0
    assert not (root / "ml-data" / "a.dom").exists()


def test_unreachable_url_fails(tmp_path):
    # Port 9 (discard) is closed on the test machines: the download fails without hanging
    proc, root = fetch(tmp_path, [entry("a.dom", b"example.com\n", "http://127.0.0.1:9")])
    assert proc.returncode != 0
    assert "Not installed: ml-data/a.dom" in proc.stderr
    assert list((root / "ml-data").iterdir()) == []


def test_repository_manifest_is_valid():
    # The real manifest parses, and the default set has the files the 2021 model needs
    import fetchdata
    files = {e["file"] for e in fetchdata.readmanifest(f"{ROOT}/ml-data/MANIFEST") if "2021" in e["set"]}
    assert {"ml-data/full.pkl", "ml-data/full-scaler.pkl", "ml-data/tranco.ng1", "ml-data/tranco.ng4"} <= files


# --- Files that are not redistributed: extracted from a zip, or derived from another file ------------------

def test_member_of_a_zip(tmp_path, server):
    import zipfile
    www, url, requests = server
    with zipfile.ZipFile(www / "list.zip", "w") as z:
        z.writestr("top-1m.csv", "1,example.com\r\n")
    proc, root = fetch(tmp_path, [entry("raw.csv", b"1,example.com\r\n", url).replace(
        f"{url}/raw.csv", f"{url}/list.zip#top-1m.csv")])
    assert proc.returncode == 0, proc.stderr
    assert (root / "ml-data" / "raw.csv").read_bytes() == b"1,example.com\r\n"
    assert not [p for p in (root / "ml-data").iterdir() if p.name != "raw.csv"]


def test_lines_derived_from_another_file(tmp_path, server):
    # Same result as the README: sed -n 'A,Bp' list.csv | cut -d ',' -f 2, without the \r
    www, url, requests = server
    full = b"1,a.com\r\n2,b.com\r\n3,c.com\r\n4,d.com\r\n"
    (www / "list.csv").write_bytes(full)
    lines = [entry("list.csv", full, url),
             entry("first.dom", b"a.com\nb.com\n", "x").replace("x/first.dom", "lines:ml-data/list.csv:1-2"),
             entry("rest.dom", b"c.com\nd.com\n", "x").replace("x/rest.dom", "lines:ml-data/list.csv:3-20")]
    proc, root = fetch(tmp_path, lines)
    assert proc.returncode == 0, proc.stderr
    assert (root / "ml-data" / "rest.dom").read_bytes() == b"c.com\nd.com\n"
    assert requests == ["/list.csv"]


def test_derived_file_needs_its_source(tmp_path):
    proc, root = fetch(tmp_path, [entry("first.dom", b"a.com\n", "x").replace(
        "x/first.dom", "lines:ml-data/list.csv:1-1")])
    assert proc.returncode != 0
    assert "ml-data/list.csv" in proc.stderr


def test_from_falls_back_to_the_source(tmp_path, server):
    # Files that are not in the local release directory are downloaded from their URL
    www, url, requests = server
    (www / "b.dom").write_bytes(b"b.com\n")
    local = tmp_path / "release"
    local.mkdir()
    (local / "a.dom").write_bytes(b"a.com\n")
    proc, root = fetch(tmp_path, [entry("a.dom", b"a.com\n", "http://127.0.0.1:9"), entry("b.dom", b"b.com\n", url)],
                       "--from", str(local))
    assert proc.returncode == 0, proc.stderr
    assert requests == ["/b.dom"]
