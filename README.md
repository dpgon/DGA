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

The project was written in 2021 and brought up to date in October 2026. What works, and how it was checked, is
listed in [`docs/MVP.md`](docs/MVP.md). In short:

- The three tools run on Python 3.12 and 3.13, also natively on Apple Silicon. `lookdga.py` needs nothing
  beyond the standard library.
- The detector was retrained on 2026 data and its model is saved with [skops](https://skops.readthedocs.io/)
  instead of pickle. The data and the model are downloaded and verified by `fetchdata.py`.
- Its accuracy is measured on evaluation sets that share no domain with the training data (see
  [Results](#results)): with the full model, 1.2% false positives on Tranco domains and 79% of the DGA domains
  detected. Random-looking CDN names, such as `d3lnoy3aplwg2k.cloudfront.net`, are often flagged as DGA, and
  DGAs that build domains from words are almost never detected.
- There are no real DGA domains newer than 2021 in the data: the figures measure how the model generalises to
  unseen domains, not how it ages against new families.
- There are automated tests, run by the CI on Linux, macOS and Windows (see [Tests](#tests)).
- The plan (recent DGA data, YARA-based sample identification) is in [`docs/FUTURE.md`](docs/FUTURE.md).

## Install
Just clone the repository and install the dependencies with pip. It is preferable to use of a virtual environment of python3.7 or above:

`$ pip install -r requirements.txt`

> **Note (2026):** the dependencies now need **Python 3.12 or newer** (tested with 3.12 and 3.13).
> `requirements.txt` lists the direct dependencies with their minimum versions; to get the exact versions the
> project is tested with, install `requirements-lock.txt` instead:
>
> ```
> $ pip install -r requirements-lock.txt
> ```
>
> The 2021 versions only installed on Python 3.9 for x86_64, and the 2021 model only loads with them. That setup
> is kept in the [`v2021` tag](https://github.com/dpgon/DGA/tree/v2021); see [`docs/MVP.md`](docs/MVP.md) §0.
> `lookdga.py` only uses the standard library and needs none of these packages.

Cloning is not enough since 2026: the model, the n-gram dictionary and the domain lists are not in git, but in
release assets or at their original source. Download them, together with the NLTK `brown` corpus that
`detectdga.py` and `statsdga.py` use to count syllables:

```
$ python fetchdata.py --nltk
```

`fetchdata.py` only needs the standard library. It reads `ml-data/MANIFEST`, checks the SHA-256 of every file
and deletes any that doesn't match; run it again to resume. It never overwrites a local file that doesn't match.
The corpus goes to `~/nltk_data`, or to the first directory of `NLTK_DATA` if it is set. Without `--nltk`,
install the corpus yourself:

```
$ python -m nltk.downloader -d ~/nltk_data brown
```

This installs the 2026 data set: the model and its n-gram dictionary (release `model-2026`), and the lists they
come from (Tranco and Umbrella lists of October 2026, DGA domains from Hugging Face, release `data-2026`). Files
that can't be redistributed are downloaded from their original source; the details are in `ml-data/MANIFEST`.
`python fetchdata.py --set 2021` installs the data of the master's project (release `v2021`) instead, and
`--from DIRECTORY` copies the files from a local directory.

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
> - Without `-d`, the date includes the current time, and pizd, pykspa2 and suppobox generate different domains
>   depending on the time of day (pykspa2 and suppobox also on the time zone). Pass `-d` for reproducible
>   results.

## statsdga.py

This tool can calculate some domain statistics generated by lookdga.py. It can also calculate statistics for domains from the Alexa top million list.

> **Note (2026):** Alexa retired its ranking in 2022 (and the bundled copy held 638,215 domains, not one
> million). The real domains now come from the Tranco list of the 2026 data set, `ml-data/tranco.csv`,
> installed by `python fetchdata.py`. Option 9, with the Tranco branch, still measures `1,google` instead of
> `google`.

Its use is self-explanatory:

`$ python statsdga.py`

## detectdga.py

In order to be able to use it, some domain list files are needed first. These files have to be saved in the ml-data directory.

> **Note (2026):** `python fetchdata.py` downloads all of them, and the model, already built (see Install). The
> instructions below explain how they were made, and serve to rebuild them.

First, download Tranco wordlist from https://tranco-list.eu/list/9Q72/full, and then split the list into three files:

```
$ sed -n '1,1500000p' tranco.csv | cut -d ',' -f 2 > tranco-main.dom
$ sed -n '1500001,2000000p' tranco.csv | cut -d ',' -f 2 > tranco-test2.dom
$ sed -n '2000001,20000000p' tranco.csv | cut -d ',' -f 2 > tranco-ngram.dom
```

> **Note (2026):** the 2026 data set uses the Tranco list [`467YX`](https://tranco-list.eu/list/467YX/full)
> (`ml-data/tranco.csv`), split the same way into `ml-data/2026/`. `fetchdata.py` does the split itself.

Second, download the DGA domains for the main dataset from https://data.netlab.360.com/feeds/dga/dga.txt, and save it in the ml-data directory.

> **Note (2026):** the code reads this file as `ml-data/dga.dom`. The 360 Netlab feed no longer answers, so both
> data sets use the 2021 copy (release `v2021`).

To create to second test dataset:
```
$ python lookdga.py -d 2019-12-31 -n 3000 -C > ml-data/mydgas.dom
```

> **Note (2026):** the 2026 data set has its own, generated in UTC:
> `TZ=UTC python lookdga.py -d 2026-10-18 -n 3000 -C > ml-data/2026/mydgas.dom`. Status messages go to the
> standard error, so the file only holds the CSV.

The n-gram dictionary was create and saved in the repository (since 2026, in the `model-2026` release, downloaded by `fetchdata.py`), but it's possible to recreate it with:

`$ python3 detectdga.py --ngram`

> **Note (2026):** the dictionary is saved as text, one CSV file per n-gram length (`ml-data/tranco.ng1.csv` …
> `ng4.csv`).

Now, we can create the main dataset:

`$ python detectdga.py --main`

To create the secondary dataset or the alexa dataset use --secondary or --alexa options.

> **Changes (2026):**
> - The Alexa dataset is replaced by the Umbrella one: use `--umbrella` and `--test_umbrella`. The Alexa set
>   shared 62% of its domains with the training data, so its figures were not valid. It uses the Cisco Umbrella
>   top 1M of 2026-10-17, reduced to registrable domains. `--alexa` and `--test_alexa` still work, as deprecated
>   aliases.
> - `--ngram`, `--main`, `--secondary` and `--umbrella` use the 2026 data set (`ml-data/2026/…`, plus the
>   Hugging Face DGA domains in the secondary set). `--set 2021` uses the 2021 files instead.
> - Evaluation sets leave out every domain and SLD of the training data, print what they excluded (also saved
>   in `ml-data/<set>.json`) and report the results by origin.
>
> These commands overwrite files in `ml-data/`. On an Apple Silicon Mac (12 cores), `--main` took 6 minutes,
> `--secondary` 4 minutes, and `--ngram`, `--umbrella` and `--train` less than a minute each. Back up the files
> you want to keep first.

The repository has the full model (downloaded by `fetchdata.py`), but it's possible to train it or train a different model (ngram, nosyll...): 

`$ python detectdga.py --train ngram`

> **Note (2026):** models are saved in `ml-data/<model>.skops`, with their scaler (`<model>-scaler.skops`) and
> their metadata (`<model>.json`: versions, SHA-256 of the input files, n-gram dictionary and public suffix list,
> hyperparameters and metrics). A model doesn't load if its dictionary, suffix list or scaler don't match its
> metadata. `--test_secondary` and `--test_umbrella` add their metrics to the metadata.

To check it with secondary model, use (alexa with --test_alexa):

`$ python detectdga.py --test_secondary ngram`

Finally, to test a domains with the full model: (-b option to try bruteforce, remove it to use only the ML model)

`$ python detectdga.py -b --check ughdnmmgdpscliraqnpl.com nvfowikhevmy.net uquslaigwaannie.ddns.net google.com facebook.com`

With the 2026 model, the first three domains are "DGA generated" and `google.com` and `facebook.com` are "No
DGA domain", as with the 2021 one. Each DGA verdict lists the families whose regular expression matches.

> **Known issues (2026):**
> - With `-b`, only `nvfowikhevmy.net` is attributed (Tinba, position 10; checked on 2026-10-19). The other two
>   DGA domains are "Not found by bruteforce": `-b` searches 10 positions and 366 days back from today, and these
>   domains are probably older than that. The search takes about a minute.
> - Only registrable domains are evaluated: domains with an SLD of 3 characters or fewer, a `www.` prefix,
>   a subdomain or an unknown suffix are listed under "Not evaluated" with the reason. Input is lowercased.
>
> Details in [`docs/MVP.md`](docs/MVP.md) §8-9.

### Results

Measured in October 2026 on evaluation sets that share no domain and no SLD with the training data of each
model. The secondary set has benign Tranco domains (lines 1,500,001-2,000,000) and DGA domains from the own
generators and from Hugging Face; the Umbrella set only has benign domains.

| Set | Model | False positives (2021 → 2026) | DGA detected (2021 → 2026) |
|---|---|---:|---:|
| Secondary | full | 1.9% → 1.2% | 78.8% → 79.0% |
| Secondary | tiny | 6.1% → 8.2% | 54.7% → 56.4% |
| Umbrella | full | 10.8% → 36.8% | — |
| Umbrella | tiny | 10.4% → 19.3% | — |

- **The Umbrella rise comes from the set, not from the model.** The 2026 Tranco and Umbrella lists overlap a
  lot, so excluding the 2026 training data leaves mostly random-looking infrastructure names: 8,857 of the
  10,935 false positives are under `cloudfront.net`. On the domains that are in both Umbrella sets, the 2021
  model flags 45.1% and the 2026 one 44.2%. With single-label suffixes such as `.com`, the full model flags
  2.3%.
- DGAs that build domains from words (pizd, nymaim2, suppobox, matsnu) are almost never detected; arithmetic
  ones, such as newgoz or zeus, always are.

Details, in Spanish, in [`docs/MVP.md`](docs/MVP.md).

## Tests

Tests use `pytest` and run from the repository root after `python fetchdata.py --nltk`:

```
$ pip install -r requirements-dev.txt
$ NLTK_DATA=~/nltk_data pytest            # default run, without the slow tests (about 1 minute)
$ NLTK_DATA=~/nltk_data pytest -m slow    # slow tests (more than 30 s each)
```

Tests that need the NLTK corpus or the data files are skipped when they are not available. They always run in
UTC, because some generators depend on the local time zone.

| File | What it covers |
|---|---|
| `test_lookdga.py`, `test_statsdga.py` | The behaviour of `lookdga.py` and of the `statsdga.py` menu verified in [`docs/MVP.md`](docs/MVP.md) |
| `test_generators.py` | A snapshot of the 50 generators, and domains confirmed by the 360 Netlab feed |
| `test_check.py` | `detectdga.py --check` with the model: the README example and the Netlab domains |
| `test_model.py` | Saving and loading models with skops, their metadata and hashes, and feature parity with the training data |
| `test_ngram.py` | The n-gram dictionary in CSV |
| `test_datasets.py`, `test_cli.py` | Evaluation sets without training data, and the data set commands |
| `test_sldtld.py` | The split of domains with the 2021 and 2026 public suffix lists |
| `test_fetchdata.py`, `test_data.py` | `fetchdata.py` against a local server, and the installed files against the manifest |
| `test_offline.py` | No script downloads anything when imported |

The CI (`.github/workflows/tests.yml`) runs the default tests on Linux, macOS and Windows with Python 3.12 and
3.13; all six jobs pass.

## Documentation

The project documentation is in Spanish, in the `docs/` directory:

| Document | Contents |
|---|---|
| [`docs/ESTUDIO.md`](docs/ESTUDIO.md) | What the code did in 2021, with file and line references |
| [`docs/IDEA.md`](docs/IDEA.md) | Purpose, audience, main features, principles and non-goals |
| [`docs/MVP.md`](docs/MVP.md) | What works today, verified by running it, with known limitations and metrics |
| [`docs/FUTURE.md`](docs/FUTURE.md) | Roadmap: 1.1 setup refresh → 1.2 recent data → 1.3 sample-to-domains (YARA) |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Real architecture, data model, decisions and technical debt |
| [`docs/CORRECCIONES.md`](docs/CORRECCIONES.md) | Design of the 2026 update: what was fixed and why |
| [`CLAUDE.md`](CLAUDE.md) | Working agreement for contributors and AI agents |

## Credits

Almost all DGAs algorithms were taken from https://github.com/baderj/domain_generation_algorithms and were adapted in the DGAs directory.

Johannes Bader's work with DGA malware is very valuable. Look it at https://johannesbader.ch/

The yara rules for the malware were extracted from https://malpedia.caad.fkie.fraunhofer.de/

Data:
- Benign domains come from the [Tranco list](https://tranco-list.eu/): list `9Q72` in 2021 and list
  [`467YX`](https://tranco-list.eu/list/467YX/full) in 2026 (V. Le Pochat et al., "Tranco: A Research-Oriented
  Top Sites Ranking Hardened Against Manipulation", NDSS 2019).
- The Umbrella evaluation set uses the [Cisco Umbrella popularity list](https://s3-us-west-1.amazonaws.com/umbrella-static/index.html)
  of 2026-10-17.
- DGA domains for training come from the 360 Netlab DGA feed (2021 copy; the feed no longer answers).
- The secondary evaluation set uses the dataset [`harpomaxx/dga-detection`](https://huggingface.co/datasets/harpomaxx/dga-detection)
  by harpomaxx, on Hugging Face, licensed under [CC BY 2.0](https://creativecommons.org/licenses/by/2.0/). The
  domains were extracted from it (`ml-data/hf-dga.dom`, release `data-2026`).
- The public suffix list is Mozilla's [Public Suffix List](https://publicsuffix.org/) (MPL 2.0).

## License

GNU General Public License v2. See [`LICENSE`](LICENSE). The YARA rules in `yara/` keep their own license
(CC BY-SA 4.0, stated in each file's header).
