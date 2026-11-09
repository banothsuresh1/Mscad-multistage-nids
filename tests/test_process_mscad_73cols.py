#!/usr/bin/env python3
"""End-to-end test of preprocessing/process_mscad_73cols.py on SYNTHETIC data.

The synthetic reference has the real MSCAD shape (128,799 x 67, quoted headers,
exact Kaggle class counts). The six synthetic CICFlowMeter files contain known
numbers of signature matches, ambiguous and prohibited signatures, unmatched
victim/external flows, Infinity/NaN values, a duplicate ``Fwd Header Len.1``
column, a repeated header line, padded headers and an invalid timestamp, so
every count the pipeline reports can be checked exactly.

Run:  python tests/test_process_mscad_73cols.py      (or: pytest tests/)
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "preprocessing"))
import process_mscad_73cols as pm  # noqa: E402

RAW_ORDER = (
    ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp"]
    + pm.FEATURE_COLUMNS[:29]
    + ["Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags"]
    + pm.FEATURE_COLUMNS[31:52]
    + ["Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg", "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg"]
    + pm.FEATURE_COLUMNS[52:56]
    + ["Init Fwd Win Byts", "Init Bwd Win Byts", "Fwd Act Data Pkts", "Fwd Seg Size Min"]
    + pm.FEATURE_COLUMNS[58:]
    + ["Label"]
)
assert len(RAW_ORDER) == 84 and set(pm.FEATURE_COLUMNS) <= set(RAW_ORDER)

rng = np.random.default_rng(7)


def make_reference() -> pd.DataFrame:
    n = sum(pm.EXPECTED_CLASS_COUNTS.values())
    labels = np.concatenate([[lab] * c for lab, c in pm.EXPECTED_CLASS_COUNTS.items()])
    ref = pd.DataFrame({c: rng.random(n).round(6) * 1000 for c in pm.FEATURE_COLUMNS})
    for c in pm.SIGNATURE_COLUMNS:  # integer-valued, effectively unique signatures
        ref[c] = rng.integers(0, 10**12, n)
    ref["Label"] = labels
    idx = {lab: np.flatnonzero(labels == lab) for lab in pm.LABEL_ENCODING}
    # 5 ambiguous signatures: Normal rows copy Brute_Force signatures.
    for k in range(5):
        ref.loc[idx["Normal"][k], pm.SIGNATURE_COLUMNS] = ref.loc[idx["Brute_Force"][k], pm.SIGNATURE_COLUMNS].values
    # 3 repeated signatures with a single label (Port_Scan).
    for k in range(3):
        ref.loc[idx["Port_Scan"][100 + k], pm.SIGNATURE_COLUMNS] = ref.loc[idx["Port_Scan"][k], pm.SIGNATURE_COLUMNS].values
    return ref, idx


def victim_ip():
    return f"192.168.159.{rng.integers(1, 255)}"


def external_ip():
    return f"10.0.{rng.integers(0, 255)}.{rng.integers(1, 255)}"


def raw_rows(ref: pd.DataFrame, rows, src_fn, dst_fn) -> pd.DataFrame:
    part = ref.loc[rows, pm.FEATURE_COLUMNS].reset_index(drop=True)
    n = len(part)
    part.insert(0, "Src IP", [src_fn() for _ in range(n)])
    part.insert(1, "Dst IP", [dst_fn() for _ in range(n)])
    return part


def unmatched_rows(n, src_fn, dst_fn) -> pd.DataFrame:
    part = pd.DataFrame({c: rng.random(n) * 1000 for c in pm.FEATURE_COLUMNS})
    for c in pm.SIGNATURE_COLUMNS:
        part[c] = rng.integers(10**13, 10**14, n)  # never in the reference
    part.insert(0, "Src IP", [src_fn() for _ in range(n)])
    part.insert(1, "Dst IP", [dst_fn() for _ in range(n)])
    return part


def finish_raw(df: pd.DataFrame) -> pd.DataFrame:
    n = len(df)
    df = df.sample(frac=1.0, random_state=int(rng.integers(0, 10**6))).reset_index(drop=True)
    secs = rng.integers(0, 86_000, n)
    df["Timestamp"] = [(pd.Timestamp("2021-03-15") + pd.Timedelta(seconds=int(s))).strftime("%d/%m/%Y %H:%M:%S") for s in secs]
    df["Src Port"] = rng.integers(1024, 65535, n).astype(str)
    df["Dst Port"] = "80"
    df["Protocol"] = "6"
    df["Flow ID"] = df["Src IP"] + "-" + df["Dst IP"]
    for c in pm.DROP_COLUMNS[1:]:
        df[c] = 0
    df["Label"] = "No Label"
    df["Flow Duration"] = df["Flow Duration"].astype(float)  # written as "123.0": format must not matter
    return df[RAW_ORDER]


def build_dataset(base: Path) -> dict:
    ref, idx = make_reference()
    (base / "CSV").mkdir(parents=True)
    quoted = ref.copy()
    quoted.columns = [f"'{c}'" for c in quoted.columns]
    quoted.to_csv(base / "MSCAD.csv", index=False)

    expected = {}
    normal_pool = iter(idx["Normal"][10:])

    def take_normal(k):
        return [next(normal_pool) for _ in range(k)]

    plan = {
        "App-01.pcap_Flow.csv": ("HTTP_DDoS", idx["HTTP_DDoS"]),
        "App-02.pcap_Flow.csv": ("ICMP_Flood", idx["ICMP_Flood"]),
        "Scan-1.pcap_Flow.csv": ("Port_Scan", idx["Port_Scan"][:2000]),
        "W-B-01.pcap_Flow.csv": ("Web_Crwling", idx["Web_Crwling"]),
        "W-B-02.pcap_Flow.csv": ("Brute_Force", idx["Brute_Force"][5:3005]),
    }
    for fname, (attack, attack_rows) in plan.items():
        parts = [
            raw_rows(ref, attack_rows, external_ip, victim_ip),          # confirmed attack
            raw_rows(ref, take_normal(30), external_ip, external_ip),    # confirmed Normal
            raw_rows(ref, take_normal(4), victim_ip, external_ip),       # confirmed Normal, IP rule disagrees
            unmatched_rows(20, external_ip, victim_ip),                  # fallback -> attack
            unmatched_rows(10, external_ip, external_ip),                # fallback -> Normal
        ]
        sig_attack, sig_normal, fb_attack, fb_normal = len(attack_rows), 34, 20, 10
        ambiguous = rejected = 0
        if fname == "W-B-02.pcap_Flow.csv":   # signatures shared by Brute_Force and Normal
            parts.append(raw_rows(ref, idx["Brute_Force"][:2], external_ip, victim_ip))
            ambiguous, fb_attack = 2, fb_attack + 2
        if fname == "App-01.pcap_Flow.csv":   # Port_Scan signature is prohibited here
            parts.append(raw_rows(ref, idx["Port_Scan"][500:501], external_ip, victim_ip))
            rejected, fb_attack = 1, fb_attack + 1
        df = pd.concat(parts, ignore_index=True)
        df.loc[:2, "Flow Byts/s"] = np.inf
        df.loc[3, "Flow Pkts/s"] = -np.inf
        df.loc[4, "Flow Byts/s"] = np.nan
        df = finish_raw(df)
        expected[fname] = dict(sig_attack=sig_attack, sig_normal=sig_normal, fb_attack=fb_attack,
                               fb_normal=fb_normal, ambiguous=ambiguous, rejected=rejected, rows=len(df))

        text = df.astype(object).where(df.notna(), "")
        text = text.astype(str).replace({"inf": "Infinity", "-inf": "-Infinity"})
        if fname == "Scan-1.pcap_Flow.csv":
            text.loc[7, "Timestamp"] = "not-a-time"
            header_line = pd.DataFrame([RAW_ORDER], columns=RAW_ORDER)
            text = pd.concat([text.iloc[:50], header_line, text.iloc[50:]], ignore_index=True)
            expected[fname]["dropped"] = 1
        if fname == "W-B-02.pcap_Flow.csv":
            text.insert(text.columns.get_loc("Bwd Header Len"), "Fwd Header Len.1", text["Fwd Header Len"])
            text.columns = [c if c != "Fwd Header Len.1" else "Fwd Header Len" for c in text.columns]
        if fname == "App-02.pcap_Flow.csv":
            text.columns = [f" {c} " for c in text.columns]
        text.to_csv(base / "CSV" / fname, index=False)

    normal = raw_rows(ref, take_normal(40), external_ip, external_ip)
    other = unmatched_rows(15, victim_ip, external_ip)
    df = pd.concat([normal, other], ignore_index=True)
    df = finish_raw(df)
    df.astype(str).to_csv(base / "CSV" / "N-0.pcap_Flow.csv", index=False)
    expected["N-0.pcap_Flow.csv"] = dict(sig_normal=40, baseline=15, rows=len(df))
    return expected


def run_pipeline(base: Path, *extra) -> int:
    pm.LOG.handlers.clear()
    return pm.main(["--base-dir", str(base), *extra])


def test_end_to_end():
    base = Path(tempfile.mkdtemp(prefix="mscad_synth_"))
    try:
        expected = build_dataset(base)
        before = {p.name: pm.sha256_of(p) for p in (base / "CSV").glob("*.csv")}
        ref_hash = pm.sha256_of(base / "MSCAD.csv")

        assert run_pipeline(base) == 0
        out_dir = base / "CSV_73Cols"
        outputs = sorted(p.name for p in out_dir.glob("*.csv") if p.name in pm.INPUT_FILES)
        assert outputs == sorted(pm.INPUT_FILES)

        summary = pd.read_csv(out_dir / "processing_summary.csv").set_index("Filename")
        for fname, exp in expected.items():
            out = pd.read_csv(out_dir / fname, dtype=str, keep_default_na=False)
            assert list(out.columns) == pm.FINAL_COLUMNS and out.shape[1] == 73
            row = summary.loc[fname]
            prov = pd.read_csv(out_dir / "_provenance" / fname.replace(".csv", ".provenance.csv"))
            if fname == "N-0.pcap_Flow.csv":
                assert set(out["Label"]) == {"Normal"}
                assert row["Signature Matches"] == exp["sig_normal"]
                assert row["Baseline-Rule Rows"] == exp["baseline"]
                continue
            attack = pm.INPUT_FILES[fname]
            assert row["Signature Matches"] == exp["sig_attack"] + exp["sig_normal"], fname
            assert row["Ambiguous Matches"] == exp["ambiguous"], fname
            assert row["Constraint-Rejected Matches"] == exp["rejected"], fname
            assert row["Fallback Attack Rows"] == exp["fb_attack"], fname
            assert row["Fallback Normal Rows"] == exp["fb_normal"], fname
            assert row["Attack Rows"] == exp["sig_attack"] + exp["fb_attack"], fname
            assert row["Normal Rows"] == exp["sig_normal"] + exp["fb_normal"], fname
            assert row["Attack Rows (Kaggle signature)"] == exp["sig_attack"], fname
            assert row["Output Rows"] == exp["rows"], fname
            assert row["Invalid Numeric Values"] == 5, fname  # 3 Infinity + 1 -Infinity + 1 NaN
            # Signature labels are never overwritten by the IP rule.
            disagree = prov[(prov.Label_Source == "kaggle_signature") & (prov.IP_Rule_Label != prov.Label)]
            assert len(disagree) == 4 and set(disagree.Label) == {"Normal"}, fname
            assert set(out["Label"]) == {attack, "Normal"}
            assert (pd.to_numeric(out["Flow Byts/s"]) >= 0).all()

        scan = summary.loc["Scan-1.pcap_Flow.csv"]
        assert scan["Dropped Rows"] == 1 and scan["Invalid Timestamps"] == 1
        scan_out = pd.read_csv(out_dir / "Scan-1.pcap_Flow.csv", dtype=str, keep_default_na=False)
        assert scan_out["Timestamp"].iloc[-1] == "not-a-time"
        assert "verified identical" in summary.loc["W-B-02.pcap_Flow.csv", "Duplicate Column Handling"]

        checks = pd.read_csv(out_dir / "validation_checks.csv")
        fails = checks[checks.Status == "FAIL"]
        assert fails.empty, fails.to_string()
        warns = checks[checks.Status == "WARN"]
        assert list(warns.File) == ["Scan-1.pcap_Flow.csv"]  # the deliberately invalid timestamp

        after = {p.name: pm.sha256_of(p) for p in (base / "CSV").glob("*.csv")}
        assert before == after and ref_hash == pm.sha256_of(base / "MSCAD.csv")

        agg = pd.read_csv(out_dir / "aggregated_class_verification.csv").set_index("Class")
        assert agg.loc["HTTP_DDoS", "From Kaggle Signature"] == 641
        assert agg.loc["HTTP_DDoS", "Kaggle Rows Recovered By Signature"] == 641
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_missing_reference_stops_before_writing():
    base = Path(tempfile.mkdtemp(prefix="mscad_noref_"))
    try:
        (base / "CSV").mkdir()
        for f in pm.INPUT_FILES:
            (base / "CSV" / f).write_text("Src IP\n1.1.1.1\n")
        assert run_pipeline(base) == 3
        assert not (base / "CSV_73Cols").exists()
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_differing_duplicate_column_is_not_discarded():
    df = pd.DataFrame([[1, 2, 3], [4, 5, 7]], columns=["Fwd Header Len", "Bwd Header Len", "Fwd Header Len.1"])
    try:
        pm.resolve_duplicate_columns(df, "unit")
    except pm.SchemaError:
        pass
    else:
        raise AssertionError("differing duplicate column was silently dropped")
    same = pd.DataFrame([[1, 2, 1.0], [4, 5, 4.0]], columns=["Fwd Header Len", "Bwd Header Len", "Fwd Header Len.1"])
    out, notes = pm.resolve_duplicate_columns(same, "unit")
    assert list(out.columns) == ["Fwd Header Len", "Bwd Header Len"] and notes


def test_ambiguous_signature_never_labelled():
    ref = pd.DataFrame({c: [1.0, 1.0, 2.0] for c in pm.SIGNATURE_COLUMNS})
    lookup, stats = pm.prepare_signature_lookup(ref, pd.Series(["Normal", "Brute_Force", "Port_Scan"]))
    assert stats["ambiguous_signatures"] == 1
    flows = pd.DataFrame({c: [1.0, 2.0, 3.0, np.nan] for c in pm.SIGNATURE_COLUMNS})
    res, mstats = pm.match_ground_truth_labels(flows, lookup, {"Brute_Force", "Normal"})
    assert list(res.Signature_Status) == ["ambiguous", "constraint_rejected", "unmatched", "incomplete_signature"]
    assert res.Signature_Label.isna().all()
    assert mstats["unique_valid_matches"] == 0


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
