'''
Regression tests of the 50 DGA generators (docs/MVP.md section 3).
- snapshot: the first 3 domains of every family and config for 2026-10-18 must not change, e.g. when the
  Python or library versions are upgraded.
- netlab reference: for the 11 variants with external confirmation, domains seen in the 360 Netlab feed must
  still be generated for their config and date.
'''
import csv
import os
from datetime import datetime

import pytest

import dga

DATA = os.path.join(os.path.dirname(__file__), "data")


def load(name):
    with open(os.path.join(DATA, name)) as f:
        return list(csv.DictReader(line for line in f if not line.startswith("#")))


def group(rows, *keys):
    groups = {}
    for row in rows:
        groups.setdefault(tuple(row[k] for k in keys), []).append(row)
    return groups


SNAPSHOT = group(load("snapshot_2026-10-18.csv"), "family", "config")
REFERENCE = group(load("referencia_netlab.csv"), "family", "config", "date")


@pytest.mark.parametrize("family,config", sorted(SNAPSHOT), ids=lambda v: v or "default")
def test_snapshot(family, config):
    expected = [row["domain"] for row in sorted(SNAPSHOT[(family, config)], key=lambda r: int(r["position"]))]
    assert dga.generate([family], datetime(2026, 10, 18), 3, config or None) == expected


@pytest.mark.parametrize("family,config,date", sorted(REFERENCE), ids=lambda v: v or "default")
def test_netlab_reference(family, config, date):
    generated = set(dga.generate([family], datetime.strptime(date, "%Y-%m-%d"), 3000, config or None))
    missing = [row["domain"] for row in REFERENCE[(family, config, date)] if row["domain"] not in generated]
    assert not missing


@pytest.mark.parametrize("family", dga.listall())
def test_every_family_generates(family):
    assert dga.generate([family], datetime(2026, 10, 18), 1, None)
