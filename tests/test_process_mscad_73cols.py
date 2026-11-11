#!/usr/bin/env python3
"""Tests for preprocessing/process_mscad_73cols.py.

Three kinds of tests:

* Full-scale SYNTHETIC run. A synthetic Kaggle reference with the real shape and class counts
  (128,799 x 67, quoted headers) and six synthetic CICFlowMeter captures with exactly the verified
  extracted row counts of the command-line re-extraction (21 / 641 / 45 / 11,081 / 28 / 88,526 = 100,342),
  structured like the real data: W-B-02 = 88,501 one-to-one Brute_Force flows + 8 extra copies + 17
  attack-session fragments absent from the reference (one reference row not reproduced), plus planted
  CICFlowMeter artefacts (an ARP-misread row, a protocol-0 ICMP row, TCP FIN-tail flows). Collisions are
  planted on purpose: App-01 flows whose signatures the reference also (or
  only) associates with Normal, 12-feature signatures shared by Brute_Force and Normal, a W-B-02 flow
  identical to a Port_Scan reference row, duplicated reference rows, and Infinity values.
* Small synthetic fixtures for the edge cases of the matching logic, the malformed-line repair and the
  damaged GUI-extracted W-B-01 file (26 flows, one cut line).
* Checks of the REAL outputs (default D:\\mscad\\CSV_73Cols, or the MSCAD_OUTPUT_DIR environment
  variable). They are skipped, with the reason shown, when those outputs do not exist.

Run:  pytest -q tests/test_process_mscad_73cols.py      (or: python tests/test_process_mscad_73cols.py)
"""

from __future__ import annotations

import atexit
import hashlib
import logging
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "preprocessing"))
import process_mscad_73cols as pm  # noqa: E402

# Verified ground truth, stated here independently of the module's configuration.
EXPECTED_DISTRIBUTION = {
    "N-0.pcap_Flow.csv": {"Normal": 21},
    "App-01.pcap_Flow.csv": {"HTTP_DDoS": 641},
    "App-02.pcap_Flow.csv": {"ICMP_Flood": 45},
    "Scan-1.pcap_Flow.csv": {"Port_Scan": 11_081},
    "W-B-01.pcap_Flow.csv": {"Web_Crwling": 28},
    "W-B-02.pcap_Flow.csv": {"Brute_Force": 88_526},
}
EXPECTED_TOTAL = 100_342
EXPECTED_GAP = 28_457                      # 128,799 - 100,342 = Normal 28,481 - Brute_Force 24
IN_DIR = pm.INPUT_SUBDIR                   # CSV_REEXTRACTED
EXPECTED_ROWS = {f: sum(d.values()) for f, d in EXPECTED_DISTRIBUTION.items()}
KAGGLE_COUNTS = {"Brute_Force": 88_502, "Normal": 28_502, "Port_Scan": 11_081,
                 "HTTP_DDoS": 641, "ICMP_Flood": 45, "Web_Crwling": 28}
METADATA = ["Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp"]
TS_FORMAT = "%d/%m/%Y %H:%M:%S"
TS_FORMAT_AMPM = "%d/%m/%Y %I:%M:%S %p"   # the format CICFlowMeter wrote for the real W-B-01/W-B-02
ATTACK_SESSION = {"Src IP": "192.168.159.1", "Dst IP": "192.168.159.131", "Dst Port": "80", "Protocol": "6"}
FEAT = pm.FEATURE_COLUMNS
TAIL_ROWS = slice(200, 210)                # Brute_Force reference rows shaped like CICFlowMeter FIN-tail flows
SIG = pm.SIGNATURE_COLUMNS

RAW_ORDER = (
    ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp"]
    + FEAT[:29]
    + ["Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags"]
    + FEAT[31:52]
    + ["Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg", "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg"]
    + FEAT[52:56]
    + ["Init Fwd Win Byts", "Init Bwd Win Byts", "Fwd Act Data Pkts", "Fwd Seg Size Min"]
    + FEAT[58:]
    + ["Label"]
)
assert len(RAW_ORDER) == 84 and set(FEAT) <= set(RAW_ORDER)


# =============================================================================
# Helpers
# =============================================================================


def _reset_log():
    for handler in list(pm.LOG.handlers):
        pm.LOG.removeHandler(handler)
        handler.close()


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


def run_pipeline(*argv, capture: _Capture | None = None) -> int:
    _reset_log()
    if capture is not None:
        pm.LOG.addHandler(capture)
        pm.LOG.setLevel(logging.INFO)
    try:
        return pm.main([str(a) for a in argv])
    finally:
        _reset_log()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_output(path: Path) -> pd.DataFrame:
    return pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8")


def copy_rows(df: pd.DataFrame, dst, src, columns) -> None:
    """Copy feature values from rows ``src`` to rows ``dst`` column by column (keeps dtypes)."""
    for col in columns:
        df.loc[dst, col] = df.loc[src, col].to_numpy()


# =============================================================================
# Full-scale synthetic dataset
# =============================================================================


def build_reference(rng) -> tuple[pd.DataFrame, dict]:
    n = sum(KAGGLE_COUNTS.values())
    labels = np.concatenate([[lab] * c for lab, c in KAGGLE_COUNTS.items()])
    ref = pd.DataFrame({c: (rng.random(n) * 1000).round(6) for c in FEAT})
    for c in SIG:
        ref[c] = rng.integers(0, 10**12, n).astype("float64")
    ref["Label"] = labels
    idx = {lab: np.flatnonzero(labels == lab) for lab in KAGGLE_COUNTS}
    B, N, H, P = idx["Brute_Force"], idx["Normal"], idx["HTTP_DDoS"], idx["Port_Scan"]
    copy_rows(ref, N[0:5], B[0:5], SIG)        # 12-feature signature shared by Brute_Force and Normal
    copy_rows(ref, N[5:10], H[0:5], FEAT)      # all 66 features shared by HTTP_DDoS and Normal
    copy_rows(ref, P[0:1], B[10:11], FEAT)     # Port_Scan reference row identical to a Brute_Force row
    copy_rows(ref, B[21:22], B[20:21], FEAT)   # duplicated Brute_Force reference row
    tail = B[TAIL_ROWS]                        # 2-packet TCP flows without SYN or RST (FIN-tail artefacts)
    ref.loc[tail, "SYN Flag Cnt"] = 0.0
    ref.loc[tail, "RST Flag Cnt"] = 0.0
    ref.loc[tail, "FIN Flag Cnt"] = 0.0          # as CICFlowMeter writes most tails: the closing FIN not counted
    ref.loc[tail, "Tot Fwd Pkts"] = 1.0
    ref.loc[tail, "Tot Bwd Pkts"] = 1.0
    return ref, idx


def random_meta(rng, n: int) -> pd.DataFrame:
    secs = rng.integers(0, 60 * 86_400, n)  # spans two months: day-first strings do not sort lexicographically
    return pd.DataFrame({
        "Src IP": [f"10.0.{a}.{b}" for a, b in zip(rng.integers(0, 255, n), rng.integers(1, 255, n))],
        "Src Port": rng.integers(1024, 65535, n).astype(str),
        "Dst IP": [f"192.168.159.{a}" for a in rng.integers(1, 255, n)],
        "Dst Port": "80",
        "Protocol": "6",
        "Timestamp": (pd.Timestamp("2021-01-05") + pd.to_timedelta(secs, unit="s")).strftime(TS_FORMAT),
    })


def write_capture(path: Path, part: pd.DataFrame, rng, meta: pd.DataFrame | None = None, *, pad_headers=False,
                  duplicate_fwd_header=False, repeated_header_at=None, corrupt_row=None) -> None:
    """Write a CICFlowMeter-style CSV. ``corrupt_row`` (index into ``part``) is written like the real broken
    W-B-01 line: its Flow ID field and the start of its Src IP are lost, so the line has one field too few."""
    df = part.reset_index(drop=True).copy()
    n = len(df)
    meta = random_meta(rng, n) if meta is None else meta.reset_index(drop=True)
    for c in METADATA:
        df[c] = meta[c].to_numpy()
    df["__order"] = np.arange(n)
    df = df.sample(frac=1.0, random_state=int(rng.integers(0, 2**31))).reset_index(drop=True)
    corrupt_pos = None if corrupt_row is None else int(np.flatnonzero(df["__order"].to_numpy() == corrupt_row)[0])
    df = df.drop(columns="__order")
    df["Flow ID"] = df["Src IP"] + "-" + df["Dst IP"]
    for c in pm.DROP_COLUMNS[1:]:
        df[c] = 0
    df["Label"] = "No Label"
    df = df[RAW_ORDER]
    for c in ("Flow Byts/s", "Flow Pkts/s"):
        df[c] = df[c].map(lambda v: "Infinity" if v == np.inf else ("-Infinity" if v == -np.inf else v))
    if duplicate_fwd_header:
        df.insert(df.columns.get_loc("Bwd Header Len"), "Fwd Header Len (copy)", df["Fwd Header Len"])
        df.columns = ["Fwd Header Len" if c == "Fwd Header Len (copy)" else c for c in df.columns]
    if repeated_header_at is not None:
        text = df.astype(str)
        header = pd.DataFrame([list(df.columns)], columns=df.columns)
        df = pd.concat([text.iloc[:repeated_header_at], header, text.iloc[repeated_header_at:]], ignore_index=True)
    if pad_headers:
        df.columns = [f" {c} " for c in df.columns]
    df.to_csv(path, index=False)
    if corrupt_pos is not None:
        lines = path.read_text().splitlines()
        line = lines[corrupt_pos + 1].split(",", 1)[1]          # Flow ID field lost
        assert line.startswith("192.168.15")
        lines[corrupt_pos + 1] = line[len("192.168.15"):]       # ... and the start of the Src IP
        path.write_text("\n".join(lines) + "\n")


def build_full_dataset(base: Path) -> dict:
    rng = np.random.default_rng(20261110)
    ref, idx = build_reference(rng)
    (base / IN_DIR).mkdir(parents=True)
    quoted = ref.copy()
    quoted.columns = [f"'{c}'" for c in quoted.columns]
    quoted.to_csv(base / "MSCAD.csv", index=False)

    B, N, H = idx["Brute_Force"], idx["Normal"], idx["HTTP_DDoS"]
    feats = lambda rows: ref.loc[rows, FEAT].reset_index(drop=True)  # noqa: E731

    write_capture(base / IN_DIR / "N-0.pcap_Flow.csv", feats(N[200:221]), rng)
    # App-01: 638 HTTP_DDoS flows (5 of them share all features with Normal reference rows) plus 3 flows
    # whose features exist in the reference ONLY as Normal. The capture rule must keep all 641 as HTTP_DDoS.
    app01 = pd.concat([feats(H[:638]), feats(N[300:303])], ignore_index=True)
    app01.loc[7, "Flow Byts/s"] = np.inf
    write_capture(base / IN_DIR / "App-01.pcap_Flow.csv", app01, rng)
    app02 = feats(idx["ICMP_Flood"])
    app02.loc[0, "Flow Pkts/s"] = -np.inf
    app02_meta = random_meta(rng, len(app02))
    app02_meta.loc[3, ["Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol"]] = ["8.0.6.4", "0", "8.6.0.1", "0", "0"]
    write_capture(base / IN_DIR / "App-02.pcap_Flow.csv", app02, rng, app02_meta, pad_headers=True)
    write_capture(base / IN_DIR / "Scan-1.pcap_Flow.csv", feats(idx["Port_Scan"]), rng, repeated_header_at=5000)
    # W-B-01: the 28 Web_Crwling flows of the command-line re-extraction, AM/PM timestamps; row 1 is an mDNS flow,
    # row 2 an ICMP flow that CICFlowMeter writes as protocol 0 with ports 0.
    w01_meta = random_meta(rng, 28)
    w01_meta["Timestamp"] = (pd.Timestamp("2020-01-02 00:48:34") + pd.to_timedelta(np.arange(28) * 3, unit="s")
                             ).strftime(TS_FORMAT_AMPM)
    w01_meta.loc[1, ["Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol"]] = \
        ["192.168.159.131", "5353", "224.0.0.251", "5353", "17"]
    w01_meta.loc[2, ["Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol"]] = \
        ["192.168.159.131", "0", "192.168.159.1", "0", "0"]
    write_capture(base / IN_DIR / "W-B-01.pcap_Flow.csv", feats(idx["Web_Crwling"]), rng, w01_meta)

    # W-B-02 mirrors the real capture: 88,501 Brute_Force reference flows (B[40] is not reproduced), 8 extra
    # copies of reference flows (B[50:58]) and 17 attack-session fragments that are not in the reference.
    # Infinity in 3 flows forces the 12-feature level for them. Two verified flows are LLMNR background traffic
    # that the reference labels Brute_Force.
    verified = feats(np.delete(B, 40))
    verified.loc[30:32, "Flow Byts/s"] = np.inf
    copies = feats(B[50:58])
    fragments = feats(B[60:77])
    fragments["Tot Fwd Pkts"] = 10.0**13 + np.arange(17)       # signatures absent from the reference
    wb02 = pd.concat([verified, copies, fragments], ignore_index=True)
    n02 = len(wb02)
    start = pd.Timestamp("2020-01-02 01:45:02")
    secs = rng.integers(0, 183, n02)
    secs[0], secs[1] = 0, 182                                   # verified window 01:45:02 .. 01:48:04
    secs[-17:] = rng.integers(3, 7, 17)                         # fragments inside the window
    wb02_meta = pd.DataFrame({**{k: [v] * n02 for k, v in ATTACK_SESSION.items()},
                              "Src Port": rng.integers(1024, 65535, n02).astype(str),
                              "Timestamp": (start + pd.to_timedelta(secs, unit="s")).strftime(TS_FORMAT_AMPM)})
    wb02_meta.loc[100:101, ["Src IP", "Dst IP", "Dst Port", "Protocol"]] = ["192.168.159.131", "224.0.0.252", "5355", "17"]
    write_capture(base / IN_DIR / "W-B-02.pcap_Flow.csv", wb02, rng, wb02_meta, duplicate_fwd_header=True)
    return {"ref": ref, "idx": idx}


_DATA: dict = {}


def dataset() -> dict:
    """Build the full-scale dataset and run the pipeline once per test session."""
    if not _DATA:
        base = Path(tempfile.mkdtemp(prefix="mscad_full_"))
        atexit.register(shutil.rmtree, base, True)
        info = build_full_dataset(base)
        inputs_before = {p.name: sha256(p) for p in (base / IN_DIR).glob("*.csv")}
        ref_before = sha256(base / "MSCAD.csv")
        rc = run_pipeline("--base-dir", base)
        _DATA.update(info, base=base, out=base / "CSV_73Cols", rc=rc,
                     inputs_before=inputs_before, ref_before=ref_before)
    return _DATA


_OUTPUTS: dict = {}


def outputs() -> dict:
    if not _OUTPUTS:
        out = dataset()["out"]
        for fname in EXPECTED_DISTRIBUTION:
            _OUTPUTS[fname] = read_output(out / fname)
    return _OUTPUTS


def report(name: str) -> pd.DataFrame:
    return pd.read_csv(dataset()["out"] / name)


# =============================================================================
# A. Input files
# =============================================================================


def test_module_configuration_matches_verified_ground_truth():
    assert set(pm.INPUT_FILES) == set(EXPECTED_DISTRIBUTION)
    assert pm.EXPECTED_CAPTURE_DISTRIBUTION == EXPECTED_DISTRIBUTION
    assert pm.EXPECTED_RAW_TOTAL == EXPECTED_TOTAL == sum(EXPECTED_ROWS.values())
    assert pm.INPUT_SUBDIR == "CSV_REEXTRACTED"
    assert "W-B-01.pcap_Flow.csv" not in pm.CAPTURE_VARIATION_STATUS
    assert pm.EXPECTED_CLASS_COUNTS == KAGGLE_COUNTS and sum(KAGGLE_COUNTS.values()) == 128_799
    assert set(pm.SINGLE_CLASS_CAPTURES) | set(pm.MIXED_CLASS_CAPTURES) == set(EXPECTED_DISTRIBUTION)
    assert set(pm.MIXED_CLASS_CAPTURES) == {"W-B-02.pcap_Flow.csv"}


def test_all_six_inputs_recognised_and_processed():
    data = dataset()
    assert data["rc"] == 0, "pipeline exit code"
    summary = report("processing_summary.csv")
    assert sorted(summary["Filename"]) == sorted(EXPECTED_DISTRIBUTION)
    assert (summary["Status"] == "OK").all(), summary[["Filename", "Status", "Error"]].to_string()


def test_missing_input_file_fails_clearly():
    data = dataset()
    tmp = Path(tempfile.mkdtemp(prefix="mscad_missing_"))
    try:
        (tmp / IN_DIR).mkdir()
        for p in (data["base"] / IN_DIR).glob("*.csv"):
            if p.name != "App-02.pcap_Flow.csv":
                shutil.copy(p, tmp / IN_DIR / p.name)
        capture = _Capture()
        rc = run_pipeline("--base-dir", tmp, "--reference", data["base"] / "MSCAD.csv", capture=capture)
        assert rc == 2
        assert any("Missing input files" in m and "App-02.pcap_Flow.csv" in m for m in capture.messages)
        assert not (tmp / "CSV_73Cols").exists(), "nothing may be written when an input is missing"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_inputs_not_merged_or_skipped():
    out = dataset()["out"]
    csvs = sorted(p.name for p in out.glob("*.csv"))
    assert sorted(set(csvs) - set(pm.REPORT_CSV_FILES)) == sorted(EXPECTED_DISTRIBUTION)
    for fname in EXPECTED_DISTRIBUTION:
        prov = pd.read_csv(out / "_provenance" / fname.replace(".csv", ".provenance.csv"))
        raw_rows = len(pd.read_csv(dataset()["base"] / IN_DIR / fname, usecols=[0]))
        dropped = 1 if fname == "Scan-1.pcap_Flow.csv" else 0
        assert prov["input_row"].is_unique and len(prov) == raw_rows - dropped == EXPECTED_ROWS[fname], fname
        assert prov["input_row"].max() < raw_rows, f"{fname}: row from another file"


# =============================================================================
# B/C. Row counts and label distributions
# =============================================================================


def test_exact_row_counts():
    for fname, df in outputs().items():
        assert len(df) == EXPECTED_ROWS[fname], f"{fname}: {len(df)} rows"
    assert sum(len(df) for df in outputs().values()) == EXPECTED_TOTAL


def test_exact_label_distributions():
    for fname, df in outputs().items():
        actual = {k: int(v) for k, v in df["Label"].value_counts().items()}
        assert actual == EXPECTED_DISTRIBUTION[fname], f"{fname}: {actual}"


def test_app01_never_labels_normal_despite_signature_collisions():
    df = outputs()["App-01.pcap_Flow.csv"]
    assert (df["Label"] == "HTTP_DDoS").all() and len(df) == 641
    summary = report("processing_summary.csv").set_index("Filename")
    # The 3 flows whose features exist in the reference only as Normal are collisions, overridden.
    assert summary.loc["App-01.pcap_Flow.csv", "Signature Collisions Overridden By Capture Rule"] == 3
    prov = pd.read_csv(dataset()["out"] / "_provenance" / "App-01.pcap_Flow.provenance.csv")
    assert set(prov["Label_Source"]) == {"capture_rule"}
    assert prov["Signature_Collision"].sum() == 3
    assert (prov.loc[prov["Signature_Collision"], "Label"] == "HTTP_DDoS").all()
    assert (prov["Match_Status"] == "ambiguous").sum() == 5  # HTTP_DDoS/Normal shared vectors


def test_single_class_captures_use_capture_rule_only():
    out = dataset()["out"]
    for fname, cls in pm.SINGLE_CLASS_CAPTURES.items():
        prov = pd.read_csv(out / "_provenance" / fname.replace(".csv", ".provenance.csv"))
        assert set(prov["Label_Source"]) == {"capture_rule"} and set(prov["Label"]) == {cls}, fname


# =============================================================================
# D. Mixed-class (W-B-02) matching
# =============================================================================


def _rows(values) -> pd.DataFrame:
    """Each value is (signature_value, other_value): the 12 signature features get the first value and
    the other 54 features the second (NaN = invalid value, e.g. Infinity)."""
    return pd.DataFrame([{c: float(s) if c in SIG else float(o) for c in FEAT} for s, o in values], columns=FEAT)


def _small_lookups():
    ref_rows = [
        (1, 10, "Brute_Force"), (1, 11, "Normal"),            # signature shared, full vectors differ
        (2, 20, "Brute_Force"), (2, 20, "Brute_Force"),       # duplicate reference rows, one label
        (3, 30, "Brute_Force"), (3, 30, "Normal"),            # conflicting labels on the full vector
        (4, 40, "Port_Scan"),                                 # only a label not permitted in W-B-02
        (5, 50, "Brute_Force"), (5, 50, "Port_Scan"),         # cross-capture collision
        (6, 60, "Normal"),
    ]
    ref = _rows([(s, o) for s, o, _ in ref_rows])
    labels = pd.Series([lab for _, _, lab in ref_rows])
    sig, _ = pm.prepare_signature_lookup(ref, labels)
    full, _ = pm.prepare_signature_lookup(ref, labels, columns=FEAT)
    return sig, full


def _levels(sig, full):
    return [(pm.SOURCE_KAGGLE_FULL, FEAT, full), (pm.SOURCE_KAGGLE_SIG, SIG, sig)]


def test_mixed_matching_edge_cases():
    sig, full = _small_lookups()
    flows = _rows([(1, 10), (1, 11), (1, np.nan), (2, 20), (2, 20), (2, 20), (3, 30), (4, 40), (5, 50),
                   (6, np.nan), (9, 90)])
    res, stats = pm.resolve_mixed_capture_labels(flows, _levels(sig, full), {"Brute_Force", "Normal"})
    expected = [
        ("verified", "Brute_Force", pm.SOURCE_KAGGLE_FULL),   # exact 66-feature match
        ("verified", "Normal", pm.SOURCE_KAGGLE_FULL),        # same signature, other full vector
        ("ambiguous", None, pm.SOURCE_KAGGLE_SIG),            # invalid feature -> signature level -> BF/Normal
        ("verified", "Brute_Force", pm.SOURCE_KAGGLE_FULL),   # duplicates in reference
        ("verified", "Brute_Force", pm.SOURCE_KAGGLE_FULL),
        ("verified", "Brute_Force", pm.SOURCE_KAGGLE_FULL),
        ("ambiguous", None, pm.SOURCE_KAGGLE_FULL),           # conflicting labels: never guessed
        ("prohibited_only", None, pm.SOURCE_KAGGLE_FULL),
        ("verified", "Brute_Force", pm.SOURCE_KAGGLE_FULL),   # Port_Scan label belongs to Scan-1
        ("verified", "Normal", pm.SOURCE_KAGGLE_SIG),         # invalid feature -> signature level
        ("unmatched", None, ""),
    ]
    got = list(zip(res["Mixed_Status"], res["Mixed_Label"], res["Evidence_Level"]))
    assert got == expected, got
    assert res["Cross_Capture_Collision"].tolist() == [False] * 8 + [True, False, False]
    # 3 capture rows share a key that has only 2 reference rows.
    assert res["Exceeds_Reference_Multiplicity"].tolist()[3:6] == [True, True, True]
    assert stats["ambiguous"] == 2 and stats["prohibited_only"] == 1 and stats["unmatched"] == 1
    assert stats["verified_by_label"] == {"Brute_Force": 5, "Normal": 2}
    assert stats["extra_copies_by_label"] == {"Brute_Force": 1, "Normal": 0}  # 3 capture rows, 2 reference rows


def test_mixed_matching_is_deterministic():
    sig, full = _small_lookups()
    flows = _rows([(1, 10), (2, 20), (3, 30), (6, np.nan), (9, 90), (5, 50)])
    first, _ = pm.resolve_mixed_capture_labels(flows, _levels(sig, full), {"Brute_Force", "Normal"})
    second, _ = pm.resolve_mixed_capture_labels(flows.iloc[::-1].reset_index(drop=True), _levels(sig, full),
                                                {"Brute_Force", "Normal"})
    assert first.equals(pm.resolve_mixed_capture_labels(flows, _levels(sig, full), {"Brute_Force", "Normal"})[0])
    assert first.iloc[::-1].reset_index(drop=True)[["Mixed_Status", "Mixed_Label"]].equals(
        second[["Mixed_Status", "Mixed_Label"]])


def test_unresolved_rows_raise_instead_of_guessing():
    sig, full = _small_lookups()
    flows = _rows([(1, 10), (3, 30), (9, 90)])
    try:
        pm.assign_capture_labels("W-B-02.pcap_Flow.csv", flows, sig, full)
    except pm.UnresolvedLabelsError as exc:
        assert list(exc.rows.index) == [1, 2]
        assert list(exc.rows["Mixed_Status"]) == ["ambiguous", "unmatched"]
    else:
        raise AssertionError("ambiguous/unmatched W-B-02 rows must not be labelled")
    labels, prov, stats = pm.assign_capture_labels("W-B-02.pcap_Flow.csv", _rows([(1, 10), (6, 60)]), sig, full)
    assert list(labels) == ["Brute_Force", "Normal"] and stats["mode"] == "mixed_class"
    assert list(prov["Label_Source"]) == [pm.SOURCE_KAGGLE_FULL] * 2


def test_capture_rule_overrides_signature_matching():
    sig, full = _small_lookups()
    flows = _rows([(6, 60), (3, 30), (9, 90), (1, 11)])  # Normal-only, conflicting, unmatched, Normal
    labels, prov, stats = pm.assign_capture_labels("App-01.pcap_Flow.csv", flows, sig, full)
    assert list(labels) == ["HTTP_DDoS"] * 4
    assert stats["signature_collisions_overridden"] == 3 and stats["signature_rows_not_in_reference"] == 1


def test_wb02_all_brute_force_with_evidence_levels():
    df = outputs()["W-B-02.pcap_Flow.csv"]
    assert (df["Label"] == "Brute_Force").sum() == 88_526 and set(df["Label"]) == {"Brute_Force"}
    prov = pd.read_csv(dataset()["out"] / "_provenance" / "W-B-02.pcap_Flow.provenance.csv")
    sources = prov.groupby(["Label_Source", "Label"]).size().to_dict()
    assert sources == {(pm.SOURCE_KAGGLE_FULL, "Brute_Force"): 88_506, (pm.SOURCE_KAGGLE_SIG, "Brute_Force"): 3,
                       (pm.SOURCE_SESSION_RULE, "Brute_Force"): 17}
    assert set(prov["Match_Status"]) == {"verified"}
    assert prov["Signature_Collision"].sum() == 1  # the flow identical to a Port_Scan reference row
    summary = report("processing_summary.csv").set_index("Filename")
    assert summary.loc["W-B-02.pcap_Flow.csv", "Extra Copies Of Reference Flows"] == 8
    assert summary.loc["W-B-02.pcap_Flow.csv", "Verified By Attack-Session Rule"] == 17
    assert not (dataset()["out"] / "_diagnostics" / "W-B-02.pcap_Flow.unresolved_rows.csv").exists()


def test_unresolved_wb02_stops_capture_and_reports_rows():
    data = dataset()
    ref, idx = data["ref"], data["idx"]
    tmp = Path(tempfile.mkdtemp(prefix="mscad_unresolved_"))
    try:
        (tmp / IN_DIR).mkdir()
        for p in (data["base"] / IN_DIR).glob("*.csv"):
            if p.name != "W-B-02.pcap_Flow.csv":
                shutil.copy(p, tmp / IN_DIR / p.name)
        rng = np.random.default_rng(5)
        part = ref.loc[idx["Brute_Force"][100:105], FEAT].reset_index(drop=True)
        extra = ref.loc[idx["Brute_Force"][[0, 50]], FEAT].reset_index(drop=True)
        extra.loc[0, "Flow Byts/s"] = np.inf        # forces the signature level, shared by BF and Normal
        extra.loc[1, SIG] = 7.0e13                  # signature not in the reference ...
        extra.loc[1, "Flow IAT Mean"] = 123.25
        frame = pd.concat([part, extra], ignore_index=True)
        meta = pd.DataFrame({**{k: [v] * 7 for k, v in ATTACK_SESSION.items()}, "Src Port": "40000",
                             "Timestamp": ["02/01/2020 01:45:0%d AM" % i for i in range(7)]})
        meta.loc[6, "Dst Port"] = "22"              # ... and not part of a verified attack session
        write_capture(tmp / IN_DIR / "W-B-02.pcap_Flow.csv", frame, rng, meta)
        rc = run_pipeline("--base-dir", tmp, "--reference", data["base"] / "MSCAD.csv")
        out = tmp / "CSV_73Cols"
        assert rc == 1
        assert not (out / "W-B-02.pcap_Flow.csv").exists(), "no W-B-02 output may be written"
        unresolved = pd.read_csv(out / "_diagnostics" / "W-B-02.pcap_Flow.unresolved_rows.csv")
        assert sorted(unresolved["Mixed_Status"]) == ["ambiguous", "unmatched"]
        assert {"input_row", "input_csv_line", "Src IP", "Timestamp", "Session_Rule_Reason"} <= set(unresolved.columns)
        reason = unresolved.loc[unresolved["Mixed_Status"] == "unmatched", "Session_Rule_Reason"].item()
        assert "no verified attack flow" in reason
        checks = pd.read_csv(out / "validation_checks.csv")
        failed = checks[checks["Status"] == "FAIL"]
        assert ((failed["File"] == "W-B-02.pcap_Flow.csv") & (failed["Check"] == "file processed")).any()
        assert (pd.read_csv(out / "processing_summary.csv").set_index("Filename")
                .drop(index="W-B-02.pcap_Flow.csv")["Status"] == "OK").all()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_attack_session_rule():
    sig, full = _small_lookups()
    flows = _rows([(1, 10), (2, 20), (9, 90), (9, 91), (9, 92), (9, 93), (3, 30)])
    meta = pd.DataFrame({
        "Src IP": ["192.168.159.1"] * 7, "Src Port": "1",
        "Dst IP": ["192.168.159.131"] * 7, "Dst Port": ["80", "80", "80", "80", "22", "80", "80"], "Protocol": "6",
        "Timestamp": ["02/01/2020 01:45:02 AM", "02/01/2020 01:45:09 AM",   # verified Brute_Force window
                      "02/01/2020 01:45:05 AM",                             # inside, same key -> Brute_Force
                      "02/01/2020 01:45:10 AM",                             # outside the window
                      "02/01/2020 01:45:05 AM",                             # other Dst Port
                      "garbage",                                            # unparseable timestamp
                      "02/01/2020 01:45:05 AM"],                            # ambiguous: never touched
    })
    try:
        pm.assign_capture_labels("W-B-02.pcap_Flow.csv", flows, sig, full, meta=meta)
    except pm.UnresolvedLabelsError as exc:
        rows = exc.rows
        assert list(rows.index) == [3, 4, 5, 6]
        assert list(rows["Mixed_Status"]) == ["unmatched", "unmatched", "unmatched", "ambiguous"]
        assert "outside the time window" in rows.loc[3, "Session_Rule_Reason"]
        assert "no verified attack flow" in rows.loc[4, "Session_Rule_Reason"]
        assert "unparseable timestamp" in rows.loc[5, "Session_Rule_Reason"]
    else:
        raise AssertionError("rows outside a verified attack session must stay unresolved")
    labels, prov, stats = pm.assign_capture_labels("W-B-02.pcap_Flow.csv", flows.iloc[:3], sig, full, meta=meta.iloc[:3])
    assert list(labels) == ["Brute_Force"] * 3
    assert list(prov["Label_Source"]) == [pm.SOURCE_KAGGLE_FULL, pm.SOURCE_KAGGLE_FULL, pm.SOURCE_SESSION_RULE]
    assert stats["session_rule_rows"] == 1 and stats["unmatched"] == 0
    # Without metadata the rule is not applied and the unmatched row stays unresolved.
    try:
        pm.assign_capture_labels("W-B-02.pcap_Flow.csv", flows.iloc[:3], sig, full)
    except pm.UnresolvedLabelsError:
        pass
    else:
        raise AssertionError("session rule needs metadata")


def test_repeated_runs_give_identical_outputs():
    data = dataset()
    tmp = Path(tempfile.mkdtemp(prefix="mscad_rerun_"))
    try:
        rc = run_pipeline("--base-dir", data["base"], "--output-dir", tmp / "out")
        assert rc == 0
        for fname in EXPECTED_DISTRIBUTION:
            assert sha256(tmp / "out" / fname) == sha256(data["out"] / fname), fname
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# =============================================================================
# E. Schema
# =============================================================================


def test_output_schema_exact():
    ref_header = [c.strip().strip("'").strip() for c in pd.read_csv(dataset()["base"] / "MSCAD.csv", nrows=0).columns]
    kaggle_features = [c for c in ref_header if c != "Label"]
    assert len(kaggle_features) == 66 and kaggle_features[0] == "Flow Duration" and kaggle_features[-1] == "Idle Min"
    expected = METADATA + kaggle_features + ["Label"]
    for fname, df in outputs().items():
        cols = list(df.columns)
        assert len(cols) == 73 and cols == expected, fname
        assert len(set(cols)) == 73, f"{fname}: duplicate column names"
        assert cols[:6] == METADATA and cols[6:72] == kaggle_features and cols[72] == "Label"
        assert not [c for c in cols if c.startswith("__") or c in ("input_row", "Flow ID")], fname


def test_reference_with_different_feature_order_is_rejected():
    n = sum(KAGGLE_COUNTS.values())
    order = FEAT.copy()
    order[1], order[2] = order[2], order[1]
    ref = pd.DataFrame(np.zeros((n, 66)), columns=order)
    ref["Label"] = np.concatenate([[lab] * c for lab, c in KAGGLE_COUNTS.items()])
    try:
        pm.validate_reference_dataset(ref, Path("synthetic.csv"))
    except pm.ReferenceDatasetError as exc:
        assert "feature order" in str(exc)
    else:
        raise AssertionError("a reordered reference must be rejected")


# =============================================================================
# F. Chronological sorting
# =============================================================================


def test_outputs_sorted_chronologically():
    for fname, df in outputs().items():
        parsed, stats = pm.parse_timestamps(df["Timestamp"])
        assert stats["invalid_timestamps"] == 0 and parsed.is_monotonic_increasing, fname
        pattern = r"^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}( [AP]M)?$"
        assert df["Timestamp"].str.match(pattern).all(), f"{fname}: format changed"
    assert outputs()["W-B-02.pcap_Flow.csv"]["Timestamp"].str.endswith(("AM", "PM")).all()  # kept as written
    lex = outputs()["Scan-1.pcap_Flow.csv"]["Timestamp"]
    assert not lex.is_monotonic_increasing, "sorted lexicographically instead of chronologically"


def test_day_first_parsing_and_invalid_timestamp_policy():
    df = pd.DataFrame({"Timestamp": ["01/02/2021 00:00:00", "bad", "02/01/2021 00:00:00", "01/01/2021 12:00:00"],
                       "x": [1, 2, 3, 4]})
    out, stats = pm.sort_flows_chronologically(df)
    assert list(out["x"]) == [4, 3, 1, 2]  # 1 Jan 12:00, 2 Jan, 1 Feb, invalid last
    assert stats["invalid_timestamps"] == 1
    assert list(out["Timestamp"])[0] == "01/01/2021 12:00:00"


def test_sorting_is_per_file():
    out = dataset()["out"]
    for fname in EXPECTED_DISTRIBUTION:
        prov = pd.read_csv(out / "_provenance" / fname.replace(".csv", ".provenance.csv"), dtype={"Timestamp": str})
        assert (prov["Timestamp"].to_numpy() == outputs()[fname]["Timestamp"].to_numpy()).all()


# =============================================================================
# G. Validation and coverage report
# =============================================================================


def test_coverage_reconciliation_totals():
    cov = report("aggregated_class_verification.csv").set_index("Class")
    total = cov.loc["TOTAL"]
    assert total["Kaggle Rows"] == 128_799 and total["PCAP Output Rows"] == EXPECTED_TOTAL
    assert total["Difference (Kaggle - PCAP)"] == EXPECTED_GAP
    assert cov.loc["Normal", "Difference (Kaggle - PCAP)"] == 28_481
    assert cov.loc["Brute_Force", "Difference (Kaggle - PCAP)"] == -24
    for lab in ("Normal", "Brute_Force"):
        assert cov.loc[lab, "Category"] == "EXPECTED_VARIATION", lab
    for lab in ("Port_Scan", "HTTP_DDoS", "ICMP_Flood", "Web_Crwling"):
        assert cov.loc[lab, "Difference (Kaggle - PCAP)"] == 0 and cov.loc[lab, "Category"] == "EXACT_MATCH"


def test_no_double_counting():
    cov = report("aggregated_class_verification.csv").set_index("Class")
    per_class = cov.drop(index="TOTAL")["Difference (Kaggle - PCAP)"]
    assert per_class.sum() == cov.loc["TOTAL", "Difference (Kaggle - PCAP)"] == EXPECTED_GAP
    assert cov.loc["Normal", "Difference (Kaggle - PCAP)"] != EXPECTED_GAP
    assert "Normal 28,481 - Brute_Force 24" in cov.loc["TOTAL", "Explanation"]


def test_coverage_explanation_documented():
    cov = report("aggregated_class_verification.csv").set_index("Class")
    assert "21-row baseline slice" in cov.loc["Normal", "Explanation"]
    assert cov.loc["Web_Crwling", "Explanation"].startswith("All 28 Kaggle rows are reproduced")
    assert "24 more flows than Kaggle" in cov.loc["Brute_Force", "Explanation"]
    md = (dataset()["out"] / "processing_report.md").read_text(encoding="utf-8")
    assert "Capture reconciliation" in md and "28,481" in md and "FAIL 0, WARN 0" in md


def test_capture_reconciliation_report():
    cap = report("capture_reconciliation.csv").set_index("PCAP file")
    assert cap.loc["W-B-02.pcap_Flow.csv", "Status"] == "Reconciled"
    assert cap.loc["N-0.pcap_Flow.csv", "Status"] == "Expected truncated baseline"
    for f in ("App-01.pcap_Flow.csv", "App-02.pcap_Flow.csv", "Scan-1.pcap_Flow.csv", "W-B-01.pcap_Flow.csv"):
        assert cap.loc[f, "Status"] == "Exact match", f
    assert cap.loc["W-B-01.pcap_Flow.csv", "Difference"] == 0
    assert cap.loc["W-B-02.pcap_Flow.csv", "Difference"] == 24
    assert cap.loc["W-B-02.pcap_Flow.csv", "Kaggle - Extracted"] == -24
    assert cap.loc["N-0.pcap_Flow.csv", "Difference"] == 28_481
    assert cap.loc["W-B-02.pcap_Flow.csv", "Final labels"] == "88,526 Brute_Force"
    assert cap.loc["W-B-01.pcap_Flow.csv", "Message"] == (
        "W-B-01: 28 extracted rows assigned Web_Crwling (100%); matches the 28 Kaggle Web_Crwling rows.")
    assert cap.loc["N-0.pcap_Flow.csv", "Message"] == (
        "N-0: All 21 extracted rows assigned Normal (100%). Kaggle contains 28,502 Normal rows in total; the "
        "28,481-row difference reflects aggregated background traffic across capture sessions that is not present "
        "in the distributed 21-row N-0 PCAP slice.")
    assert cap.loc["W-B-02.pcap_Flow.csv", "Message"] == (
        "W-B-02: 88,526 extracted rows assigned Brute_Force (100%). Kaggle reference contains 88,502 Brute_Force "
        "rows; the 24-row difference is an expected PCAP extraction variation: 8 extra copies of reference flows "
        "+ 17 attack-session fragments not in the reference - 1 reference row(s) not reproduced.")
    assert cap["Extracted rows"].sum() == EXPECTED_TOTAL


def test_validation_has_no_failures_or_warnings():
    checks = report("validation_checks.csv")
    bad = checks[checks["Status"].isin(["FAIL", "WARN"])]
    assert bad.empty, bad.to_string()
    assert set(checks["Category"]) >= {"schema", "labels", "flow_count", "timestamps", "integrity", "coverage"}
    data = dataset()
    assert {p.name: sha256(p) for p in (data["base"] / IN_DIR).glob("*.csv")} == data["inputs_before"]
    assert sha256(data["base"] / "MSCAD.csv") == data["ref_before"]


def _results_with(counts_by_file):
    return [{"filename": f, "status": "OK", "validated_class_counts": {lab: c.get(lab, 0) for lab in KAGGLE_COUNTS}}
            for f, c in counts_by_file.items()]


def test_genuine_errors_are_still_detected():
    good = {f: dict(d) for f, d in EXPECTED_DISTRIBUTION.items()}
    table, checks = pm.reconcile_coverage(_results_with(good), KAGGLE_COUNTS)
    assert all(c["Status"] == "PASS" for c in checks)

    mislabelled = {f: dict(d) for f, d in EXPECTED_DISTRIBUTION.items()}
    mislabelled["App-01.pcap_Flow.csv"] = {"HTTP_DDoS": 640, "Normal": 1}
    table, checks = pm.reconcile_coverage(_results_with(mislabelled), KAGGLE_COUNTS)
    cats = table.set_index("Class")["Category"]
    assert cats["HTTP_DDoS"] == cats["Normal"] == "LABELLING_OR_FLOW_COUNT_MISMATCH"
    assert any(c["Status"] == "FAIL" for c in checks)

    missing = {f: dict(d) for f, d in EXPECTED_DISTRIBUTION.items()}
    missing["Scan-1.pcap_Flow.csv"] = {"Port_Scan": 11_000}
    table, checks = pm.reconcile_coverage(_results_with(missing), KAGGLE_COUNTS)
    assert any(c["Check"] == "raw PCAP total equals the verified total" and c["Status"] == "FAIL" for c in checks)

    other_reference = dict(KAGGLE_COUNTS, Web_Crwling=30)
    table, _ = pm.reconcile_coverage(_results_with(good), other_reference)
    assert table.set_index("Class").loc["Web_Crwling", "Category"] == "REFERENCE_MISMATCH"


def test_capture_reconciliation_detects_errors():
    good = {f: dict(d) for f, d in EXPECTED_DISTRIBUTION.items()}
    wb02_stats = {"extra_copies_by_label": {"Brute_Force": 8, "Normal": 0},
                  "one_to_one_by_label": {"Brute_Force": 88_501, "Normal": 0}, "session_rule_rows": 17}

    def results(dist, stats=wb02_stats):
        res = _results_with(dist)
        for r in res:
            if r["filename"] == "W-B-02.pcap_Flow.csv":
                r["labelling"] = stats
        return res

    table, checks = pm.reconcile_captures(results(good), KAGGLE_COUNTS)
    assert all(c["Status"] == "PASS" for c in checks), checks
    forced = dict(good, **{"W-B-02.pcap_Flow.csv": {"Brute_Force": 88_502, "Normal": 24}})
    table, checks = pm.reconcile_captures(results(forced), KAGGLE_COUNTS)
    assert table.set_index("PCAP file").loc["W-B-02.pcap_Flow.csv", "Status"] == "Labelling mismatch"
    wrong_breakdown = dict(wb02_stats, session_rule_rows=16)
    table, checks = pm.reconcile_captures(results(good, wrong_breakdown), KAGGLE_COUNTS)
    assert table.set_index("PCAP file").loc["W-B-02.pcap_Flow.csv", "Status"] == "Unexpected difference"
    short_w01 = dict(good, **{"W-B-01.pcap_Flow.csv": {"Web_Crwling": 25}})
    table, _ = pm.reconcile_captures(results(short_w01), KAGGLE_COUNTS)
    row = table.set_index("PCAP file").loc["W-B-01.pcap_Flow.csv"]
    assert row["Status"] == "Labelling mismatch" and "damaged GUI-extracted" not in row["Message"]
    # the damaged GUI-extracted W-B-01 file (26 flows) fails, with an explicit explanation
    gui_w01 = dict(good, **{"W-B-01.pcap_Flow.csv": {"Web_Crwling": 26}})
    table, checks = pm.reconcile_captures(results(gui_w01), KAGGLE_COUNTS)
    row = table.set_index("PCAP file").loc["W-B-01.pcap_Flow.csv"]
    assert row["Status"] == "Labelling mismatch"
    assert "damaged GUI-extracted W-B-01 file" in row["Message"] and "CSV_REEXTRACTED" in row["Message"]
    assert any(c["File"] == "W-B-01.pcap_Flow.csv" and c["Status"] == "FAIL" for c in checks)


# =============================================================================
# Malformed input lines
# =============================================================================


def test_no_input_repairs_in_reextracted_data():
    out = dataset()["out"]
    assert len(pd.read_csv(out / "input_repairs.csv")) == 0
    prov = pd.read_csv(out / "_provenance" / "W-B-01.pcap_Flow.provenance.csv", keep_default_na=False)
    assert (prov["Input_Repair"] == "").all()


def test_damaged_gui_wb01_line_is_realigned():
    """The GUI-extracted W-B-01 file lost the Flow ID and the start of the Src IP of one line; the safety net
    realigns that line in memory with the features in the right columns (the file itself is not modified)."""
    tmp = Path(tempfile.mkdtemp(prefix="mscad_gui_w01_"))
    try:
        rng = np.random.default_rng(7)
        part = _rows([(i, 10 * i) for i in range(1, 27)])
        meta = random_meta(rng, 26)
        meta.loc[1, ["Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol"]] = \
            ["192.168.159.131", "5353", "224.0.0.251", "5353", "17"]
        path = tmp / "W-B-01.pcap_Flow.csv"
        write_capture(path, part, rng, meta, corrupt_row=1)
        before = sha256(path)
        frame, repairs = pm.read_capture_csv(path)
        assert sha256(path) == before
        assert len(frame) == 26 and len(repairs) == 1
        rep_ = repairs[0]
        assert rep_["Src IP as found"] == "9.131" and not rep_["Src IP valid"]
        assert rep_["Fields found"] == 83 and rep_["Header fields"] == 84
        frame = pm.normalize_columns(frame)
        row = frame[frame["Dst IP"].astype(str).str.strip() == "224.0.0.251"].iloc[0]
        assert (str(row["Src Port"]), str(row["Dst Port"]), str(row["Protocol"])) == ("5353", "5353", "17")
        assert float(row["Flow Duration"]) == 2.0 and float(row["Flow IAT Mean"]) == 20.0, "features misaligned"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_unrepairable_malformed_lines_fail():
    tmp = Path(tempfile.mkdtemp(prefix="mscad_malformed_"))
    try:
        rng = np.random.default_rng(1)
        part = _rows([(1, 10), (2, 20), (3, 30)])
        write_capture(tmp / "good.csv", part, rng)
        frame, repairs = pm.read_capture_csv(tmp / "good.csv")
        assert len(frame) == 3 and repairs == []
        lines = (tmp / "good.csv").read_text().splitlines()
        fields = lines[1].split(",")
        cases = {
            "missing_middle_field": ",".join(fields[:5] + fields[6:]),   # Protocol lost
            "extra_field": lines[1] + ",X",
        }
        for name, bad in cases.items():
            (tmp / f"{name}.csv").write_text("\n".join([lines[0], bad] + lines[2:]) + "\n")
            try:
                pm.read_capture_csv(tmp / f"{name}.csv")
            except pm.SchemaError as exc:
                assert "cannot be repaired" in str(exc), name
            else:
                raise AssertionError(f"{name}: malformed line accepted")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# =============================================================================
# CICFlowMeter extraction artefacts
# =============================================================================


def test_flag_extraction_artefacts_rules():
    # rows shaped like the real W-B-02/App-01 values (see docs/cicflowmeter_extraction_audit.md)
    meta = pd.DataFrame({
        "Src IP": ["8.0.6.4", "10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.1",
                   "10.0.0.1", "8.6.0.1"],
        "Dst IP": ["8.6.0.1"] + ["10.0.0.2"] * 9,
        "Protocol": ["0", "6", "6", "6", "6", "6", "6", "0", "17", "0"],
    })
    parsed = pd.DataFrame({
        "Tot Fwd Pkts": [10, 1, 0, 1, 7, 2, 1, 4, 1, 3], "Tot Bwd Pkts": [1, 1, 2, 2, 5, 2, 0, 0, 1, 0],
        "SYN Flag Cnt": [0, 0, 0, 0, 1, 0, 0, 0, 0, 0], "FIN Flag Cnt": [0, 0, 1, 1, 1, 1, 0, 0, 0, 0],
        "RST Flag Cnt": [0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
    }, dtype=float)
    flags = list(pm.flag_extraction_artefacts(meta, parsed))
    assert flags == ["arp_misread_as_ipv4",       # both ARP "addresses"
                     "tcp_fin_tail_candidate",    # 2 packets, no SYN, FIN not counted (most W-B-02 tails)
                     "tcp_fin_tail_candidate",    # 2 packets counted backward, FIN counted (App-01 tails)
                     "tcp_fin_tail_candidate",    # 3 packets, no SYN
                     "",                          # full TCP connection
                     "",                          # 4 packets: not a tail candidate
                     "",                          # a reset, not a tail
                     "non_tcp_udp_protocol_0",    # ICMP/IGMP/fragments
                     "",                          # UDP is never a TCP tail
                     "non_tcp_udp_protocol_0"]    # only one ARP address: an ordinary protocol-0 row


def test_artefacts_flagged_in_provenance_without_changing_rows():
    out = dataset()["out"]
    art = pd.read_csv(out / "extraction_artefacts.csv").set_index(["Filename", "Flag"])["Rows"]
    assert art[("App-02.pcap_Flow.csv", "arp_misread_as_ipv4")] == 1
    assert art[("W-B-01.pcap_Flow.csv", "non_tcp_udp_protocol_0")] == 1
    assert art[("W-B-02.pcap_Flow.csv", "tcp_fin_tail_candidate")] == TAIL_ROWS.stop - TAIL_ROWS.start
    assert art.drop(index=[("App-02.pcap_Flow.csv", "arp_misread_as_ipv4"),
                           ("W-B-01.pcap_Flow.csv", "non_tcp_udp_protocol_0"),
                           ("W-B-02.pcap_Flow.csv", "tcp_fin_tail_candidate")]).sum() == 0
    prov = pd.read_csv(out / "_provenance" / "App-02.pcap_Flow.provenance.csv", keep_default_na=False)
    flagged = prov.index[prov["Extraction_Artefact"] == "arp_misread_as_ipv4"]
    assert len(flagged) == 1
    row = outputs()["App-02.pcap_Flow.csv"].iloc[flagged[0]]
    assert (row["Src IP"], row["Dst IP"], row["Label"]) == ("8.0.6.4", "8.6.0.1", "ICMP_Flood"), "row kept and labelled"
    summary = report("processing_summary.csv").set_index("Filename")
    assert summary.loc["W-B-02.pcap_Flow.csv", "Artefact: tcp_fin_tail_candidate"] == 10
    md = (out / "processing_report.md").read_text(encoding="utf-8")
    assert "CICFlowMeter extraction artefacts" in md and "arp_misread_as_ipv4" in md


# =============================================================================
# H. Output integrity
# =============================================================================


def test_outputs_readable_and_complete():
    out = dataset()["out"]
    for fname in EXPECTED_DISTRIBUTION:
        df = pd.read_csv(out / fname)  # default parsing must also succeed
        assert df.shape == (EXPECTED_ROWS[fname], 73), fname
        assert df["Label"].notna().all()
    assert {"processing_summary.csv", "aggregated_class_verification.csv", "validation_checks.csv",
            "processing_report.md", "run_metadata.json"} <= {p.name for p in out.iterdir()}


# =============================================================================
# Real outputs (run on the machine that has D:\mscad)
# =============================================================================

REAL_OUTPUT_DIR = Path(os.environ.get("MSCAD_OUTPUT_DIR", r"D:\mscad\CSV_73Cols"))


def test_real_outputs_if_available():
    files = [REAL_OUTPUT_DIR / f for f in EXPECTED_DISTRIBUTION]
    if not all(p.is_file() for p in files):
        raise unittest.SkipTest(f"real outputs not found in {REAL_OUTPUT_DIR} (run the pipeline on the MSCAD data "
                                "first, or set MSCAD_OUTPUT_DIR)")
    for fname, path in zip(EXPECTED_DISTRIBUTION, files):
        df = read_output(path)
        assert list(df.columns) == pm.FINAL_COLUMNS, fname
        assert len(df) == EXPECTED_ROWS[fname], f"{fname}: {len(df)} rows"
        assert {k: int(v) for k, v in df["Label"].value_counts().items()} == EXPECTED_DISTRIBUTION[fname], fname
        assert pm.parse_timestamps(df["Timestamp"])[0].dropna().is_monotonic_increasing, fname
    checks = pd.read_csv(REAL_OUTPUT_DIR / "validation_checks.csv")
    assert not (checks["Status"].isin(["FAIL", "WARN"])).any(), checks[checks["Status"].isin(["FAIL", "WARN"])].to_string()
    cap = pd.read_csv(REAL_OUTPUT_DIR / "capture_reconciliation.csv").set_index("PCAP file")
    assert cap.loc["W-B-01.pcap_Flow.csv", "Status"] == "Exact match"
    assert cap.loc["W-B-02.pcap_Flow.csv", "Status"] == "Reconciled"
    assert cap.loc["N-0.pcap_Flow.csv", "Status"] == "Expected truncated baseline"
    art = pd.read_csv(REAL_OUTPUT_DIR / "extraction_artefacts.csv")
    arp = art[art["Flag"] == "arp_misread_as_ipv4"].set_index("Filename")["Rows"]
    # Stage C audit: misread ARP rows App-01 1, App-02 1, Scan-1 2, W-B-02 1, N-0 0, W-B-01 0
    assert arp.to_dict() == {"App-01.pcap_Flow.csv": 1, "App-02.pcap_Flow.csv": 1, "N-0.pcap_Flow.csv": 0,
                             "Scan-1.pcap_Flow.csv": 2, "W-B-01.pcap_Flow.csv": 0, "W-B-02.pcap_Flow.csv": 1}


if __name__ == "__main__":
    failures = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except unittest.SkipTest as exc:
                print(f"SKIP {name}: {exc}")
            except Exception as exc:  # report every failing test
                failures += 1
                print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    sys.exit(1 if failures else 0)
