import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from os.path import basename, dirname, isfile, join

# Only the standard library: this script runs before the dependencies of detectdga.py are useful

MANIFEST = "ml-data/MANIFEST"
COLUMNS = ["file", "url", "size", "sha256", "source", "license", "set"]
CHUNK = 1024 * 1024


class Col:
    HEADER = '\033[95m'
    OK = '\033[92m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'
    END = '\033[0m'


def readmanifest(filename):
    '''
    Read the data manifest
    :param filename: path of the manifest (tab separated, # comments, first non comment line is the header)
    :return: list of dicts with the manifest columns; size is an int and set a list
    '''
    entries = []
    header = None
    with open(filename, encoding="utf-8") as f:
        for number, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            fields = line.split("\t")
            if header is None:
                header = fields
                if header != COLUMNS:
                    raise ValueError(f"{filename}:{number}: header must be {' '.join(COLUMNS)}")
                continue
            if len(fields) != len(COLUMNS):
                raise ValueError(f"{filename}:{number}: expected {len(COLUMNS)} columns, found {len(fields)}")
            entry = dict(zip(COLUMNS, fields))
            entry["size"] = int(entry["size"])
            entry["set"] = entry["set"].split(",")
            entries.append(entry)
    return entries


def sha256(filename):
    h = hashlib.sha256()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def verified(filename, entry):
    return os.path.getsize(filename) == entry["size"] and sha256(filename) == entry["sha256"]


def copyfrom(src, dst):
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        shutil.copyfileobj(fin, fout, CHUNK)


def download(url, dst):
    request = urllib.request.Request(url, headers={"User-Agent": "DGA-fetchdata"})
    with urllib.request.urlopen(request, timeout=60) as response, open(dst, "wb") as fout:
        shutil.copyfileobj(response, fout, CHUNK)


def extract(url, dst):
    '''
    Download a zip file and extract one of its members
    :param url: URL of the zip file followed by #member
    :param dst: file where the member is saved
    '''
    base, member = url.split("#", 1)
    archive = dst + ".zip"
    try:
        download(base, archive)
        with zipfile.ZipFile(archive) as z, z.open(member) as fin, open(dst, "wb") as fout:
            shutil.copyfileobj(fin, fout, CHUNK)
    except (zipfile.BadZipFile, KeyError) as e:
        raise OSError(f"can't extract {member} from {base}: {e}")
    finally:
        if isfile(archive):
            os.remove(archive)


def derive(spec, root, dst):
    '''
    Create a domain list from lines of another installed file, as the README does with
    sed -n 'FIRST,LASTp' SOURCE | cut -d ',' -f 2 (and without the \\r of the Tranco list)
    :param spec: lines:SOURCE:FIRST-LAST, with SOURCE relative to the repository root
    :param root: repository root
    :param dst: file where the list is saved
    '''
    _, source, span = spec.split(":")
    first, last = (int(n) for n in span.split("-"))
    if not isfile(join(root, source)):
        raise OSError(f"needs {source}, which is not installed")
    with open(join(root, source), encoding="utf-8", newline="") as fin, \
            open(dst, "w", encoding="utf-8", newline="\n") as fout:
        for number, line in enumerate(fin, 1):
            if number > last:
                break
            if number >= first:
                line = line.replace("\r", "").rstrip("\n")
                fout.write((line.split(",")[1] if "," in line else line) + "\n")


def obtain(entry, root, local, part):
    '''
    Get one file of the manifest into part, from the local directory if it is there, or else from its URL:
    a plain URL, URL#member of a zip file, or lines:SOURCE:FIRST-LAST of another file
    :return: description of where it came from
    '''
    url = entry["url"]
    if local and isfile(join(local, basename(entry["file"]))):
        copyfrom(join(local, basename(entry["file"])), part)
        return f"copied from {local}"
    if url.startswith("lines:"):
        derive(url, root, part)
        return f"derived from {url}"
    if "#" in url:
        extract(url, part)
        return f"extracted from {url}"
    download(url, part)
    return f"downloaded from {url}"


def install(entry, root, local=None):
    '''
    Download (or copy from a local directory) one file of the manifest and check its size and SHA-256
    :param entry: manifest entry
    :param root: repository root where the file is installed
    :param local: directory with the files to copy instead of downloading them, or None. Files that are not
                  there are obtained from their URL
    :return: True if the file is installed and verified
    '''
    dst = join(root, entry["file"])
    if isfile(dst):
        if verified(dst, entry):
            print(Col.OK + f"  {entry['file']}: already installed" + Col.END)
            return True
        # Never overwrite a file that doesn't match: it may be a local copy someone regenerated (CLAUDE.md, rule 13)
        print(Col.ERROR + f"  {entry['file']}: exists but doesn't match the manifest. Move it away and run again."
              + Col.END, file=sys.stderr)
        return False

    os.makedirs(dirname(dst) or ".", exist_ok=True)
    part = dst + ".part"
    try:
        print(f"  {entry['file']}: {obtain(entry, root, local, part)}")
    except OSError as e:
        print(Col.ERROR + f"  {entry['file']}: {e}" + Col.END, file=sys.stderr)
        if isfile(part):
            os.remove(part)
        return False

    if not verified(part, entry):
        os.remove(part)
        print(Col.ERROR + f"  {entry['file']}: size or SHA-256 doesn't match the manifest, file deleted" + Col.END,
              file=sys.stderr)
        return False
    os.replace(part, dst)
    print(Col.OK + f"  {entry['file']}: verified" + Col.END)
    return True


def installbrown():
    '''
    Install the NLTK brown corpus with the command nlpdata.py recommends, in NLTK_DATA or ~/nltk_data
    :return: True if the command succeeded
    '''
    directory = os.environ.get("NLTK_DATA", "").split(os.pathsep)[0] or join(os.path.expanduser("~"), "nltk_data")
    print(f"Installing the NLTK brown corpus in {directory}")
    return subprocess.run([sys.executable, "-m", "nltk.downloader", "-d", directory, "brown"]).returncode == 0


def main():
    parser = argparse.ArgumentParser(description="Download and verify the data files listed in ml-data/MANIFEST")
    parser.add_argument("--set", default="2021",
                        help="data set to install (default 2021, the one the bundled model was trained with)")
    parser.add_argument("--from", dest="local", metavar="DIRECTORY",
                        help="copy the files from a local directory instead of downloading them "
                             "(files that are not there are still obtained from their URL)")
    parser.add_argument("--nltk", action="store_true",
                        help="also install the NLTK brown corpus (in NLTK_DATA, or ~/nltk_data)")
    parser.add_argument("--manifest", default=MANIFEST, help=f"manifest file (default {MANIFEST})")
    parser.add_argument("--root", default=".", help="repository root where files are installed (default .)")
    args = parser.parse_args()

    try:
        entries = [e for e in readmanifest(args.manifest) if args.set in e["set"]]
    except (OSError, ValueError) as e:
        print(Col.ERROR + f"Can't read the manifest: {e}" + Col.END, file=sys.stderr)
        sys.exit(1)
    if not entries:
        print(Col.ERROR + f"No files in data set {args.set}" + Col.END, file=sys.stderr)
        sys.exit(1)

    print(Col.HEADER + f"Data set {args.set}: {len(entries)} files" + Col.END)
    failed = [e["file"] for e in entries if not install(e, args.root, args.local)]
    if args.nltk and not installbrown():
        failed.append("NLTK brown corpus")

    if failed:
        print(Col.ERROR + f"Not installed: {', '.join(failed)}" + Col.END, file=sys.stderr)
        sys.exit(1)
    print(Col.OK + "All files installed and verified" + Col.END)


if __name__ == "__main__":
    main()
