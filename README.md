# DGA
Study of the different algorithms and techniques for generating DGA and discrimination against non-DGA domains.
I developed three tools in python 3:
1. lookdga.py to create DGA domains and detect them by reg.exp.
2. statsdga.py to calculate some statistics.
3. detectdga.py to train a model and detect DGA domains using machine learning stuff. 

The project started as a Master's project in malware analysis and reverse engineering. It ships 50 DGA
generators (in the `DGAs` directory), a Random Forest detector trained on n-grams and other lexical features,
and a brute-force search that recovers the family, seed, day and position that generated a domain.

## Who is it for

Students, teachers and researchers who want to understand how DGAs work, reproduce the study or reuse the
generators. It is a learning and research lab: it is **not** a production tool, it doesn't monitor traffic,
and it doesn't contact the domains it analyses.

## Status (2026)

This repository is a 2021 snapshot that is being brought up to date. What works today, and how it was
checked, is listed in [`docs/MVP.md`](docs/MVP.md). In short:

- `lookdga.py` and `statsdga.py` work as described below.
- Since October 2026, everything runs on Python 3.12 and 3.13, also natively on Apple Silicon. The model was
  retrained on 2026 data and is saved with [skops](https://skops.readthedocs.io/) instead of pickle.
- Accuracy figures on evaluation sets that share no domain with the training data are in
  [`docs/MVP.md`](docs/MVP.md): with the full model, 1.2% false positives on Tranco and 79% of the DGA domains
  detected. Random-looking CDN names, such as `d3lnoy3aplwg2k.cloudfront.net`, are often flagged as DGA.
- There are automated tests (see Tests).
- The plan (setup refresh, recent DGA data, YARA-based sample identification) is in
  [`docs/FUTURE.md`](docs/FUTURE.md).

## Install
Clone the repository and install the dependencies with pip, preferably in a virtual environment of Python 3.12 or
3.13:

`$ pip install -r requirements-lock.txt`

`requirements-lock.txt` pins the exact versions the project is tested with; `requirements.txt` lists only the
direct dependencies with their minimum versions. `lookdga.py` only uses the standard library and needs none of
these packages.

> **The 2021 environment.** The model of the master's project (release `v2021`) was saved with pickle and
> scikit-learn 0.24.2, and only loads with the exact versions of 2021, on Python 3.9 for x86_64. That setup is
> kept in the [`v2021` tag](https://github.com/dpgon/DGA/tree/v2021); see [`docs/MVP.md`](docs/MVP.md) §0.

Cloning is not enough since 2026: the model, the n-gram dictionary and the domain lists are not in git, but in
release assets or at their original source. Download them, together with the NLTK `brown` corpus that
`detectdga.py` and `statsdga.py` use to count syllables:

```
$ python fetchdata.py --nltk
```

`fetchdata.py` only needs the standard library. It reads `ml-data/MANIFEST`, checks the SHA-256 of every file
and deletes any that doesn't match; run it again to resume. The corpus goes to `~/nltk_data`, or to the first
directory of `NLTK_DATA` if it is set. Without `--nltk`, install the corpus yourself:

```
$ python -m nltk.downloader -d ~/nltk_data brown
```

This installs the 2026 data set: the model and its n-gram dictionary, and the lists they come from (Tranco and
Umbrella lists of October 2026, DGA domains from Hugging Face). Files that can't be redistributed are downloaded
from their original source; the details are in `ml-data/MANIFEST`. `python fetchdata.py --set 2021` installs the
data of the master's project (release `v2021`) instead.

The scripts never download anything themselves: if a data file or the corpus is missing, they stop and say
which command to run.

Run every command **from the repository root**: all paths (`ml-data/…`, `DGAs/wordlist/…`) are relative.

## lookdga.py
This tool can calculate the domains of various malware that use DGA. It can also detect by domain possible DGA using regular expressions, and finally, it can bruteforce it in order to detect the day and order of generation.

List all DGA available:

`$ python lookdga.py -L`

View info about a DGA:

`$ python lookdga.py -m zloader -I`

Generate 5 domains of a DGA:

`$ python lookdga.py -m tinba -n 5 -G`

Detect possible DGA using reg.exp:

`$ python lookdga.py -D google.com nvfowikhevmy.net`

Bruteforce previous domains (it is also detected before of bruteforce):

`$ python lookdga.py -B google.com nvfowikhevmy.net`

Generate a blocklist with the domains of every family for today and the following days:

`$ python lookdga.py -F`

Other options: `-d YYYY-MM-DD` (date, default today), `-n N` (number of domains, default 10), `-s` (seed),
`-b DAYS` (days to search backwards when bruteforcing, default 366) and `-C` (labelled CSV corpus). Run
`python lookdga.py -h` for the full list.

> **Known limits (2026):**
> - The regular expressions are a pre-filter, not a verdict: `google.com` matches 6 families.
> - The bruteforce only searches the first `-n` positions (10 by default) of each day, going back `-b` days
>   from `-d`. A domain outside that window is reported as not found.
> - `-F` covers today plus the next seven days, with `-n` domains per family and day.

## statsdga.py

This tool can calculate some domain statistics generated by lookdga.py. It can also calculate statistics for domains from the Alexa top million list.

> **Note (2026):** Alexa retired its ranking in 2022 (and the bundled copy held 638,215 domains, not one
> million). The real domains now come from the Tranco list of the 2026 data set, `ml-data/tranco.csv`
> (`python fetchdata.py --set 2026`). Option 9, with the Tranco branch, still measures `1,google`
> instead of `google`.

Its use is self-explanatory:

`$ python statsdga.py`

## detectdga.py

In order to be able to use it, some domain list files are needed first. These files have to be saved in the ml-data directory.

First, download Tranco wordlist from https://tranco-list.eu/list/9Q72/full, and then split the list into three files:

```
$ sed -n '1,1500000p' tranco.csv | cut -d ',' -f 2 > tranco-main.dom
$ sed -n '1500001,2000000p' tranco.csv | cut -d ',' -f 2 > tranco-test2.dom
$ sed -n '2000001,20000000p' tranco.csv | cut -d ',' -f 2 > tranco-ngram.dom
```

Second, download the DGA domains for the main dataset from https://data.netlab.360.com/feeds/dga/dga.txt, and save it in the ml-data directory.

> **Note (2026):** the code reads this file as `ml-data/dga.dom`. The 360 Netlab feed no longer answers. All
> these files, as used in 2021, are downloaded by `python fetchdata.py` (see Install).

To create to second test dataset:
```
$ python lookdga.py -d 2019-12-31 -n 3000 -C > ml-data/mydgas.dom
```

The n-gram dictionary was create and saved in the repository (since 2026, in the `model-2026` release, downloaded by `fetchdata.py`), but it's possible to recreate it with:

`$ python3 detectdga.py --ngram`

> **Note (2026):** the dictionary is saved as text, one CSV file per n-gram length (`ml-data/tranco.ng1.csv` …
> `ng4.csv`).

Now, we can create the main dataset:

`$ python detectdga.py --main`

To create the secondary dataset or the alexa dataset use --secondary or --alexa options.

> **Changes (2026):**
> - `--alexa` and `--test_alexa` are deprecated aliases of `--umbrella` and `--test_umbrella`: the Alexa set
>   shared 62% of its domains with the training set. The Umbrella set uses the Cisco Umbrella list of the 2026
>   data set, reduced to registrable domains.
> - `--ngram`, `--main`, `--secondary` and `--umbrella` use the 2026 data set (`ml-data/2026/…`, plus the
>   Hugging Face DGA domains in the secondary set). `--set 2021` uses the 2021 files instead.
> - Evaluation sets leave out every domain and SLD of the training data, print what they excluded (also saved
>   in `ml-data/<set>.json`) and report the results by origin.
> - The metrics of the 2021 and 2026 models on these sets are in [`docs/MVP.md`](docs/MVP.md).
>
> These commands overwrite files in `ml-data/`. On an Apple Silicon Mac (12 cores), `--main` took 6 minutes,
> `--secondary` 4 minutes, and `--ngram`, `--umbrella` and `--train` less than a minute each. Back up the files
> you want to keep first.

The repository has the full model (downloaded by `fetchdata.py`), but it's possible to train it or train a different model (ngram, nosyll...): 

> **Note (2026):** models are saved in `ml-data/<model>.skops`, with their scaler (`<model>-scaler.skops`) and
> their metadata (`<model>.json`: versions, SHA-256 of the input files, n-gram dictionary and public suffix list,
> hyperparameters and metrics). A model doesn't load if its dictionary, suffix list or scaler don't match its
> metadata. `--test_secondary` and `--test_umbrella` add their metrics to the metadata.


`$ python detectdga.py --train ngram`

To check it with secondary model, use (umbrella with --test_umbrella):

`$ python detectdga.py --test_secondary ngram`

Finally, to test a domains with the full model: (-b option to try bruteforce, remove it to use only the ML model)

`$ python detectdga.py -b --check ughdnmmgdpscliraqnpl.com nvfowikhevmy.net uquslaigwaannie.ddns.net google.com facebook.com`

> **Known issues (2026):**
> - With `-b`, only `nvfowikhevmy.net` is attributed today (Tinba, position 10). The other two DGA domains
>   are "Not found by bruteforce": `-b` searches 10 positions and 366 days back from today, and these domains
>   are probably older than that.
> - Only registrable domains are evaluated: domains with an SLD of 3 characters or fewer, a `www.` prefix,
>   a subdomain or an unknown suffix are listed under "Not evaluated" with the reason. Input is lowercased.
>
> Details in [`docs/MVP.md`](docs/MVP.md) §8-9.

## Tests

Tests use `pytest` and run from the repository root after `python fetchdata.py --nltk`:

```
$ pip install -r requirements-dev.txt
$ NLTK_DATA=~/nltk_data pytest            # default run, without the slow tests
$ NLTK_DATA=~/nltk_data pytest -m slow    # slow tests (more than 30 s each)
```

Tests that need the NLTK corpus or the data files are skipped when they are not available. `tests/test_lookdga.py`,
`test_generators.py` (a snapshot of the 50 generators and domains confirmed by the 360 Netlab feed),
`test_check.py` and `test_statsdga.py` pin the behaviour verified in [`docs/MVP.md`](docs/MVP.md); the rest
cover the fixes of [`docs/CORRECCIONES.md`](docs/CORRECCIONES.md). Tests always run in UTC, because some
generators depend on the local time zone.

## Documentation

The project documentation is in Spanish, in the `docs/` directory:

| Document | Contents |
|---|---|
| [`docs/ESTUDIO.md`](docs/ESTUDIO.md) | What the code actually does, with file and line references |
| [`docs/IDEA.md`](docs/IDEA.md) | Purpose, audience, main features, principles and non-goals |
| [`docs/MVP.md`](docs/MVP.md) | What works today, verified by running it, with known limitations |
| [`docs/FUTURE.md`](docs/FUTURE.md) | Roadmap: 1.1 setup refresh → 1.2 recent data → 1.3 sample-to-domains (YARA) |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Real architecture, data model, decisions and technical debt |
| [`CLAUDE.md`](CLAUDE.md) | Working agreement for contributors and AI agents |

## Credits

Almost all DGAs algorithms were taken from https://github.com/baderj/domain_generation_algorithms and were adapted in the DGAs directory.

Johannes Bader's work with DGA malware is very valuable. Look it at https://johannesbader.ch/

The yara rules for the malware were extracted from https://malpedia.caad.fkie.fraunhofer.de/

Benign domains come from the [Tranco list](https://tranco-list.eu/), and DGA domains for training come from
the 360 Netlab DGA feed.

## License

GNU General Public License v2. See [`LICENSE`](LICENSE). The YARA rules in `yara/` keep their own license
(CC BY-SA 4.0, stated in each file's header).
