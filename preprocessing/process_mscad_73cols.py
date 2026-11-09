#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
process_mscad_73cols.py
=======================

MSCAD PCAP -> CICFlowMeter CSV post-processing:
ground-truth label assignment and generation of six independent 73-column CSVs.

Project : Flow-Aware Temporal Pattern Mining for Multi-Stage Network Intrusion Detection

Inputs
------
* Six CICFlowMeter v4.0 flow CSVs (one per MSCAD capture), default ``D:\\mscad\\CSV\\``.
  Each file is processed INDEPENDENTLY. The six files are NEVER concatenated,
  appended or merged.
* The original Kaggle ``MSCAD.csv`` (expected 128,799 rows x 67 columns), used ONLY
  as a read-only ground-truth lookup table. It is opened in read mode only, and its
  SHA-256 is checked before and after the run.

Outputs (default ``D:\\mscad\\CSV_73Cols\\``)
---------------------------------------------
* The six processed CSVs, keeping their original filenames:
  6 metadata + 66 Kaggle-compatible features + ``Label`` = 73 columns.
* ``processing_summary.csv``          per-file statistics
* ``class_counts_per_file.csv``       per-file class counts, split by label source
* ``aggregated_class_verification.csv`` totals compared with the Kaggle class counts
* ``invalid_values_report.csv``       invalid numeric values per file and feature
* ``schema_report.csv``               schema checks of the raw inputs
* ``validation_checks.csv``           checks run after independently reloading the outputs
* ``processing_report.md``            readable report
* ``run_metadata.json``               paths, hashes, configuration, library versions
* ``processing_log.txt``              full log
* ``_provenance/<file>.provenance.csv``  per-row label provenance (same row order as output)
* ``_diagnostics/<file>.flagged_signatures.csv``  ambiguous and constraint-rejected signatures

Label provenance -- READ THIS BEFORE USING THE LABELS
-----------------------------------------------------
Every output row gets exactly one label source, recorded in the provenance file:

* ``kaggle_signature`` -- the flow's 12-feature signature occurs in MSCAD.csv, every
  reference row with that signature has the same label, and that label is permitted
  for the capture. This is the only CONFIRMED reference label.
* ``baseline_rule``    -- N-0 (normal baseline capture) rows without a confirmed
  signature are labelled Normal because of what the capture is.
* ``ip_fallback``      -- all other rows: a TESTBED HEURISTIC. If Src IP or Dst IP is in
  the victim subnet 192.168.159.0/24 the row gets the capture's attack label,
  otherwise Normal. These labels are NOT independently verified ground truth.

Ambiguous signatures (one signature, several reference labels) and signatures whose
single reference label is not permitted for the capture are never used as labels.
They are flagged, written to ``_diagnostics``, and those rows fall through to the
heuristic above.

Invalid numeric values
----------------------
``Infinity``, ``-Infinity``, ``inf``, ``NaN``, empty strings and unparseable strings in
the 66 feature columns become NaN and are counted per file and feature. With the
default ``--imputation zero`` they are then replaced by 0.0. A constant is used on
purpose: imputing with a median or mean computed now, before any train/test split,
would leak information from future test data into training. In CICFlowMeter the
usual cause is a rate (``Flow Byts/s``, ``Flow Pkts/s``) of a zero-duration flow,
which is undefined. Use ``--imputation nan`` to keep NaN in the CSVs and decide later.
No rows are dropped for invalid values. The only rows ever dropped are repeated
CSV header lines inside a data file, which are not flows; any such drop is reported.

Timestamps
----------
``Timestamp`` is parsed temporarily (``%d/%m/%Y %H:%M:%S``) to sort each file
chronologically with a stable sort, so flows with the same second keep their
original order. The original timestamp strings are written unchanged. Rows whose
timestamp cannot be parsed are kept, reported, and placed at the end.

Usage
-----
    python process_mscad_73cols.py
    python process_mscad_73cols.py --base-dir D:\\mscad
    python process_mscad_73cols.py --reference D:\\mscad\\MSCAD.csv --imputation nan

Exit code 0 means every file was processed and every validation check passed.
Differences from the expected Kaggle class counts are reported but are not
treated as failures.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import logging
import platform
import re
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

# =============================================================================
# CONFIGURATION
# =============================================================================

BASE_DIR = Path(r"D:\mscad")
INPUT_SUBDIR = "CSV"
OUTPUT_SUBDIR = "CSV_73Cols"

# Set to an explicit path (e.g. Path(r"D:\mscad\MSCAD.csv")) to skip auto-discovery.
REFERENCE_CSV_PATH: Path | None = None
EXPECTED_REFERENCE_SHAPE = (128_799, 67)

NORMAL_LABEL = "Normal"

# Input file -> attack label of the capture (Normal for the baseline capture).
INPUT_FILES = {
    "App-01.pcap_Flow.csv": "HTTP_DDoS",    # Scenario 1, Step 2a
    "App-02.pcap_Flow.csv": "ICMP_Flood",   # Scenario 1, Step 2b
    "N-0.pcap_Flow.csv": "Normal",          # Normal baseline
    "Scan-1.pcap_Flow.csv": "Port_Scan",    # Scenario 1, Step 1
    "W-B-01.pcap_Flow.csv": "Web_Crwling",  # Scenario 2, Step 1 (Kaggle spelling)
    "W-B-02.pcap_Flow.csv": "Brute_Force",  # Scenario 2, Step 2
}
BASELINE_FILES = {"N-0.pcap_Flow.csv"}

# Labels a signature match may assign for each capture.
ALLOWED_LABELS = {
    fname: ({NORMAL_LABEL} if attack == NORMAL_LABEL else {attack, NORMAL_LABEL})
    for fname, attack in INPUT_FILES.items()
}

DROP_COLUMNS = [
    "Flow ID",
    "Fwd PSH Flags",
    "Fwd URG Flags",
    "Fwd Byts/b Avg",
    "Fwd Pkts/b Avg",
    "Fwd Blk Rate Avg",
    "Bwd Byts/b Avg",
    "Bwd Pkts/b Avg",
    "Bwd Blk Rate Avg",
    "Init Fwd Win Byts",
    "Fwd Seg Size Min",
]

METADATA_COLUMNS = [
    "Src IP",
    "Src Port",
    "Dst IP",
    "Dst Port",
    "Protocol",
    "Timestamp",
]

FEATURE_COLUMNS = [
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean",
    "Fwd Pkt Len Std",
    "Bwd Pkt Len Max",
    "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean",
    "Bwd Pkt Len Std",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Tot",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Tot",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Bwd PSH Flags",
    "Bwd URG Flags",
    "Fwd Header Len",
    "Bwd Header Len",
    "Fwd Pkts/s",
    "Bwd Pkts/s",
    "Pkt Len Min",
    "Pkt Len Max",
    "Pkt Len Mean",
    "Pkt Len Std",
    "Pkt Len Var",
    "FIN Flag Cnt",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "PSH Flag Cnt",
    "ACK Flag Cnt",
    "URG Flag Cnt",
    "CWE Flag Count",
    "ECE Flag Cnt",
    "Down/Up Ratio",
    "Pkt Size Avg",
    "Fwd Seg Size Avg",
    "Bwd Seg Size Avg",
    "Subflow Fwd Pkts",
    "Subflow Fwd Byts",
    "Subflow Bwd Pkts",
    "Subflow Bwd Byts",
    "Init Bwd Win Byts",
    "Fwd Act Data Pkts",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

TARGET_COLUMN = ["Label"]
LABEL_COLUMN = "Label"

FINAL_COLUMNS = METADATA_COLUMNS + FEATURE_COLUMNS + TARGET_COLUMN

SIGNATURE_COLUMNS = [
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Bwd Pkt Len Max",
    "Fwd IAT Tot",
    "Bwd IAT Tot",
    "Fwd Header Len",
    "Bwd Header Len",
    "Init Bwd Win Byts",
]

# Integer encoding for later ML/DL training. The CSVs keep the text labels.
LABEL_ENCODING = {
    "Brute_Force": 0,
    "Normal": 1,
    "Port_Scan": 2,
    "HTTP_DDoS": 3,
    "ICMP_Flood": 4,
    "Web_Crwling": 5,
}

# Kaggle reference class counts: a validation reference, never a target to force.
EXPECTED_CLASS_COUNTS = {
    "Brute_Force": 88_502,
    "Normal": 28_502,
    "Port_Scan": 11_081,
    "HTTP_DDoS": 641,
    "ICMP_Flood": 45,
    "Web_Crwling": 28,
}

VICTIM_NETWORK = ipaddress.ip_network("192.168.159.0/24")

TIMESTAMP_FORMAT = "%d/%m/%Y %H:%M:%S"
# Tried only for values the primary format cannot parse; each use is reported.
TIMESTAMP_FALLBACK_FORMATS = ["%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M"]

RATE_FEATURES = ["Flow Byts/s", "Flow Pkts/s"]
DEFAULT_IMPUTATION = "zero"  # "zero" or "nan"

# Columns read as text so their exact string form is preserved.
TEXT_COLUMNS = set(METADATA_COLUMNS) | {"Flow ID", LABEL_COLUMN}

MISSING_TOKENS = {"", "nan", "na", "n/a", "null", "none"}
POS_INF_TOKENS = {"inf", "+inf", "infinity", "+infinity"}
NEG_INF_TOKENS = {"-inf", "-infinity"}
READ_NA_TOKENS = ["", "NaN", "nan", "NAN", "NA", "N/A", "n/a", "null", "NULL", "None"]

SOURCE_SIGNATURE = "kaggle_signature"
SOURCE_BASELINE = "baseline_rule"
SOURCE_FALLBACK = "ip_fallback"

STATUS_VALID = "unique_valid"
STATUS_AMBIGUOUS = "ambiguous"
STATUS_REJECTED = "constraint_rejected"
STATUS_UNMATCHED = "unmatched"
STATUS_INCOMPLETE = "incomplete_signature"

PROVENANCE_DIR = "_provenance"
DIAGNOSTICS_DIR = "_diagnostics"

LOG = logging.getLogger("mscad73")


# =============================================================================
# ERRORS AND SMALL HELPERS
# =============================================================================


class PipelineError(Exception):
    """An essential assumption failed. The affected step must stop."""


class SchemaError(PipelineError):
    """An input CSV does not have the expected structure."""


class ReferenceDatasetError(PipelineError):
    """The Kaggle reference dataset is missing, ambiguous or invalid."""


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _as_text(series: pd.Series) -> pd.Series:
    """Stripped text with missing values as "" (works with pandas 1.x-3.x dtypes)."""
    return series.astype(object).where(series.notna(), "").astype(str).str.strip()


def _normalize_name(name) -> str:
    return str(name).strip().strip("'").strip()


def _peek_header(path: Path, encoding: str) -> list[str]:
    with open(path, "r", encoding=encoding, newline="") as fh:
        try:
            return next(csv.reader(fh))
        except StopIteration as exc:
            raise SchemaError(f"{path.name}: file is empty") from exc


def read_flow_csv(path: Path) -> pd.DataFrame:
    """Read a flow CSV without altering text values.

    Text columns (metadata, Flow ID, Label) are read as strings so IPs, ports and
    timestamps keep their exact form. Feature columns are parsed numerically with
    round-trip float precision. Values pandas cannot parse leave a column as text;
    ``parse_numeric_column`` handles those.
    """
    last_error = None
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            header = _peek_header(path, encoding)
            text_raw = [h for h in header if _normalize_name(h) in TEXT_COLUMNS]
            numeric_raw = [h for h in header if _normalize_name(h) not in TEXT_COLUMNS]
            df = pd.read_csv(
                path,
                encoding=encoding,
                dtype={h: str for h in text_raw},
                keep_default_na=False,
                na_values={h: READ_NA_TOKENS for h in numeric_raw},
                float_precision="round_trip",
                low_memory=False,
            )
            if encoding != "utf-8-sig":
                LOG.warning("%s: not valid UTF-8, read as latin-1", path.name)
            return df
        except UnicodeDecodeError as exc:
            last_error = exc
    raise SchemaError(f"{path.name}: cannot decode file ({last_error})")


# =============================================================================
# HEADER NORMALIZATION AND DUPLICATE COLUMNS
# =============================================================================


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace and the literal single quotes used in the Kaggle headers."""
    df.columns = df.columns.str.strip().str.strip("'").str.strip()
    return df


def _values_identical(a: pd.Series, b: pd.Series) -> bool:
    """True if two columns hold the same values (textually or numerically)."""
    sa = _as_text(a).to_numpy(dtype=object)
    sb = _as_text(b).to_numpy(dtype=object)
    if np.array_equal(sa, sb):
        return True
    na = pd.to_numeric(pd.Series(sa), errors="coerce").to_numpy(dtype="float64")
    nb = pd.to_numeric(pd.Series(sb), errors="coerce").to_numpy(dtype="float64")
    both_nan = np.isnan(na) & np.isnan(nb)
    numeric_equal = (na == nb) | both_nan
    # Where both are non-numeric, the text has to match.
    return bool(np.all(numeric_equal & (~both_nan | (sa == sb))))


def resolve_duplicate_columns(df: pd.DataFrame, context: str) -> tuple[pd.DataFrame, list[str]]:
    """Drop a duplicate column only after verifying its values are identical.

    Handles names that become equal after normalization, and pandas-mangled
    duplicates such as ``Fwd Header Len.1``. A duplicate whose values differ
    raises SchemaError instead of being discarded.
    """
    notes: list[str] = []
    cols = list(df.columns)
    drop_positions: set[int] = set()
    first_position: dict[str, int] = {}

    for i, name in enumerate(cols):
        if name not in first_position:
            first_position[name] = i
            continue
        j = first_position[name]
        if _values_identical(df.iloc[:, j], df.iloc[:, i]):
            drop_positions.add(i)
            notes.append(f"duplicate column '{name}' (position {i}) identical to position {j}: dropped")
        else:
            raise SchemaError(f"{context}: duplicate column '{name}' has values that differ from the first copy")

    for i, name in enumerate(cols):
        if i in drop_positions:
            continue
        match = re.fullmatch(r"(.+)\.(\d+)", name)
        if not match or match.group(1) not in first_position:
            continue
        base = match.group(1)
        j = first_position[base]
        if _values_identical(df.iloc[:, j], df.iloc[:, i]):
            drop_positions.add(i)
            notes.append(f"duplicate column '{name}' verified identical to '{base}': dropped")
        else:
            raise SchemaError(
                f"{context}: '{name}' differs from '{base}'. Refusing to discard it; "
                "inspect the CICFlowMeter output"
            )

    if drop_positions:
        keep = [i for i in range(len(cols)) if i not in drop_positions]
        df = df.iloc[:, keep].copy()
    return df, notes


# =============================================================================
# NUMERIC PARSING
# =============================================================================


def _safe_float(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return np.nan


def parse_numeric_column(series: pd.Series) -> tuple[pd.Series, dict]:
    """Convert a column to float64. Infinity and invalid values become NaN.

    Returns the parsed series and counts of missing, +inf, -inf and unparseable
    values. Text is converted with Python ``float`` (correctly rounded), so no
    precision is lost before exact signature matching.
    """
    stats = {"missing": 0, "pos_inf": 0, "neg_inf": 0, "unparseable": 0}
    if pd.api.types.is_numeric_dtype(series) and not pd.api.types.is_bool_dtype(series):
        values = series.to_numpy(dtype="float64", copy=True)
        stats["missing"] = int(np.isnan(values).sum())
    else:
        text = _as_text(series)
        lower = text.str.lower()
        missing = lower.isin(MISSING_TOKENS).to_numpy()
        pos_tok = lower.isin(POS_INF_TOKENS).to_numpy()
        neg_tok = lower.isin(NEG_INF_TOKENS).to_numpy()
        candidate = ~(missing | pos_tok | neg_tok)
        values = np.full(len(series), np.nan, dtype="float64")
        values[pos_tok] = np.inf
        values[neg_tok] = -np.inf
        if candidate.any():
            parsed = np.array([_safe_float(v) for v in text.to_numpy()[candidate]], dtype="float64")
            values[candidate] = parsed
            stats["unparseable"] = int(np.isnan(parsed).sum())
        stats["missing"] = int(missing.sum())
    pos = np.isposinf(values)
    neg = np.isneginf(values)
    stats["pos_inf"] = int(pos.sum())
    stats["neg_inf"] = int(neg.sum())
    values[pos | neg] = np.nan
    return pd.Series(values, index=series.index, name=series.name), stats


def parse_feature_columns(raw: pd.DataFrame) -> tuple[pd.DataFrame, list[dict], set[str]]:
    """Parse the 66 features. Returns parsed values, invalid-value stats and the
    names of the columns that were integers in the input."""
    parsed = {}
    stats_rows = []
    int_columns = set()
    for col in FEATURE_COLUMNS:
        if pd.api.types.is_integer_dtype(raw[col]):
            int_columns.add(col)
        parsed[col], stats = parse_numeric_column(raw[col])
        stats_rows.append({"Feature": col, **stats})
    return pd.DataFrame(parsed, index=raw.index), stats_rows, int_columns


# =============================================================================
# REFERENCE DATASET
# =============================================================================


def _reference_candidate_reason(path: Path) -> str | None:
    """None if the header looks like the 67-column MSCAD reference, else why not."""
    try:
        header = [_normalize_name(h) for h in _peek_header(path, "utf-8-sig")]
    except (UnicodeDecodeError, SchemaError, OSError) as exc:
        return f"unreadable header ({exc})"
    if LABEL_COLUMN not in header:
        return "no Label column"
    missing = [c for c in FEATURE_COLUMNS if c not in header]
    if missing:
        return f"{len(missing)} of the 66 features missing"
    if len(header) != EXPECTED_REFERENCE_SHAPE[1]:
        return f"{len(header)} columns, expected {EXPECTED_REFERENCE_SHAPE[1]}"
    return None


def _count_data_rows(path: Path) -> int:
    return len(pd.read_csv(path, usecols=[0], encoding="utf-8-sig", dtype=str, keep_default_na=False))


def locate_reference_dataset(search_roots: list[Path], exclude_dirs: list[Path]) -> tuple[Path, list[dict]]:
    """Find MSCAD.csv by inspecting the structure and size of every CSV found.

    Stops with ReferenceDatasetError if no candidate matches, or if several
    candidates with different contents match.
    """
    excluded = {d.resolve() for d in exclude_dirs if d.exists()}
    examined: list[dict] = []
    matches: list[Path] = []
    seen: set[Path] = set()

    for root in search_roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if path.suffix.lower() != ".csv" or not path.is_file():
                continue
            rpath = path.resolve()
            if rpath in seen or any(parent in excluded for parent in rpath.parents):
                continue
            seen.add(rpath)
            reason = _reference_candidate_reason(path)
            if reason is None:
                rows = _count_data_rows(path)
                if rows != EXPECTED_REFERENCE_SHAPE[0]:
                    reason = f"{rows} rows, expected {EXPECTED_REFERENCE_SHAPE[0]}"
            examined.append({"path": str(path), "verdict": "MATCH" if reason is None else f"rejected: {reason}"})
            if reason is None:
                matches.append(path)

    for item in examined:
        LOG.info("  reference search: %s -> %s", item["path"], item["verdict"])

    if not matches:
        raise ReferenceDatasetError(
            "No CSV with the MSCAD reference structure (67 columns, 66 features + Label, "
            f"{EXPECTED_REFERENCE_SHAPE[0]} rows) was found under: "
            + ", ".join(str(r) for r in search_roots)
            + ". Pass --reference with the correct path."
        )
    hashes = {p: sha256_of(p) for p in matches}
    if len(set(hashes.values())) > 1:
        raise ReferenceDatasetError(
            "Several different files match the reference structure: "
            + "; ".join(f"{p} (sha256 {h[:12]})" for p, h in hashes.items())
            + ". Pass --reference to choose one."
        )
    chosen = sorted(matches, key=lambda p: (p.name.lower() != "mscad.csv", len(str(p))))[0]
    if len(matches) > 1:
        LOG.info("  %d identical copies of the reference found; using %s", len(matches), chosen)
    return chosen, examined


def validate_reference_dataset(reference_df: pd.DataFrame, path: Path) -> tuple[pd.Series, dict]:
    """Check shape, columns and labels of the reference. Returns normalized labels."""
    info: dict = {"path": str(path), "shape": list(reference_df.shape)}
    if reference_df.columns.duplicated().any():
        dups = reference_df.columns[reference_df.columns.duplicated()].tolist()
        raise ReferenceDatasetError(f"reference has duplicate columns after normalization: {dups}")
    if tuple(reference_df.shape) != EXPECTED_REFERENCE_SHAPE:
        raise ReferenceDatasetError(f"reference shape {reference_df.shape}, expected {EXPECTED_REFERENCE_SHAPE}")
    expected_cols = set(FEATURE_COLUMNS) | {LABEL_COLUMN}
    missing = sorted(expected_cols - set(reference_df.columns))
    extra = sorted(set(reference_df.columns) - expected_cols)
    if missing or extra:
        raise ReferenceDatasetError(f"reference columns differ: missing={missing}, extra={extra}")
    feature_order = [c for c in reference_df.columns if c != LABEL_COLUMN]
    info["feature_order_matches_schema"] = feature_order == FEATURE_COLUMNS
    info["label_is_last_column"] = reference_df.columns[-1] == LABEL_COLUMN

    labels = reference_df[LABEL_COLUMN].astype(str).str.strip().str.strip("'").str.strip()
    if (labels == "").any():
        raise ReferenceDatasetError(f"reference has {(labels == '').sum()} empty labels")
    unknown = sorted(set(labels.unique()) - set(LABEL_ENCODING))
    if unknown:
        raise ReferenceDatasetError(f"reference contains labels outside the six classes: {unknown}")

    counts = labels.value_counts()
    info["class_counts"] = {lab: int(counts.get(lab, 0)) for lab in LABEL_ENCODING}
    info["class_counts_match_expected"] = info["class_counts"] == EXPECTED_CLASS_COUNTS
    if not info["class_counts_match_expected"]:
        LOG.warning("Reference class counts differ from the expected Kaggle counts: %s", info["class_counts"])

    invalid = {}
    for col in FEATURE_COLUMNS:
        _, stats = parse_numeric_column(reference_df[col])
        n = sum(stats.values())
        if n:
            invalid[col] = stats
    info["reference_invalid_numeric_values"] = invalid
    return labels, info


def prepare_signature_lookup(reference_df: pd.DataFrame, labels: pd.Series) -> tuple[pd.DataFrame, dict]:
    """Build one row per distinct 12-feature signature with its per-label counts.

    A signature seen with more than one label is marked ambiguous. Nothing is
    deduplicated by keeping the first label.
    """
    keys = {}
    for col in SIGNATURE_COLUMNS:
        keys[col], _ = parse_numeric_column(reference_df[col])
    keys = pd.DataFrame(keys)
    complete = keys.notna().all(axis=1)
    keys = keys + 0.0  # -0.0 -> 0.0
    keys["__label"] = labels.to_numpy()
    keys = keys[complete]

    counts = keys.groupby(SIGNATURE_COLUMNS + ["__label"], sort=False).size()
    wide = counts.unstack("__label", fill_value=0)
    for lab in LABEL_ENCODING:
        if lab not in wide.columns:
            wide[lab] = 0
    wide = wide[list(LABEL_ENCODING)].astype("int64")

    present = wide.to_numpy() > 0
    label_names = np.array(list(LABEL_ENCODING))
    n_labels = present.sum(axis=1)
    label_sets = ["|".join(label_names[row]) for row in present]
    unique_label = np.where(n_labels == 1, label_names[present.argmax(axis=1)], None)

    wide.columns = [f"__ref_n_{lab}" for lab in LABEL_ENCODING]
    lookup = wide.reset_index()
    lookup["__n_labels"] = n_labels
    lookup["__ref_labels"] = label_sets
    lookup["__unique_label"] = unique_label
    lookup["__ref_rows"] = wide.to_numpy().sum(axis=1)

    ambiguous = lookup["__n_labels"] > 1
    stats = {
        "reference_rows": int(len(reference_df)),
        "reference_rows_with_incomplete_signature": int((~complete).sum()),
        "distinct_signatures": int(len(lookup)),
        "ambiguous_signatures": int(ambiguous.sum()),
        "reference_rows_in_ambiguous_signatures": int(lookup.loc[ambiguous, "__ref_rows"].sum()),
        "reference_rows_in_ambiguous_signatures_by_label": {
            lab: int(lookup.loc[ambiguous, f"__ref_n_{lab}"].sum()) for lab in LABEL_ENCODING
        },
        "signatures_repeated_with_one_label": int(((lookup["__ref_rows"] > 1) & ~ambiguous).sum()),
    }
    return lookup, stats


# =============================================================================
# LABEL ASSIGNMENT
# =============================================================================


def match_ground_truth_labels(
    signatures: pd.DataFrame, lookup: pd.DataFrame, allowed_labels: set[str]
) -> tuple[pd.DataFrame, dict]:
    """Stage 1: exact 12-feature signature match against the reference.

    Returns one row per flow (same order as ``signatures``) with signature status,
    the confirmed label (only for STATUS_VALID), the reference label set and
    per-label reference counts.
    """
    n = len(signatures)
    keys = signatures[SIGNATURE_COLUMNS].reset_index(drop=True)
    complete = keys.notna().all(axis=1).to_numpy()
    keys = keys + 0.0
    keys["__row"] = np.arange(n)

    merged = keys.loc[complete].merge(lookup, on=SIGNATURE_COLUMNS, how="left", sort=False, validate="many_to_one")
    found = merged["__n_labels"].notna().to_numpy()
    rows = merged["__row"].to_numpy()

    status = np.full(n, STATUS_INCOMPLETE, dtype=object)
    status[complete] = STATUS_UNMATCHED
    sig_label = np.full(n, None, dtype=object)
    ref_labels = np.full(n, "", dtype=object)
    ref_rows = np.zeros(n, dtype="int64")
    ambiguous_prohibited = np.zeros(n, dtype=bool)

    fm = merged.loc[found]
    frows = rows[found]
    n_labels = fm["__n_labels"].to_numpy(dtype="int64")
    unique = fm["__unique_label"].to_numpy(dtype=object)
    allowed = np.array([u in allowed_labels for u in unique], dtype=bool)
    is_amb = n_labels > 1
    is_single = n_labels == 1

    status[frows[is_amb]] = STATUS_AMBIGUOUS
    status[frows[is_single & ~allowed]] = STATUS_REJECTED
    status[frows[is_single & allowed]] = STATUS_VALID
    sig_label[frows[is_single & allowed]] = unique[is_single & allowed]
    ref_labels[frows] = fm["__ref_labels"].to_numpy(dtype=object)
    ref_rows[frows] = fm["__ref_rows"].to_numpy(dtype="int64")
    prohibited_cols = [f"__ref_n_{lab}" for lab in LABEL_ENCODING if lab not in allowed_labels]
    if prohibited_cols:
        has_prohibited = (fm[prohibited_cols].to_numpy() > 0).any(axis=1)
        ambiguous_prohibited[frows[is_amb & has_prohibited]] = True

    result = pd.DataFrame(
        {
            "Signature_Status": status,
            "Signature_Label": sig_label,
            "Ref_Labels": ref_labels,
            "Ref_Row_Count": ref_rows,
            "Ambiguous_Includes_Prohibited": ambiguous_prohibited,
        }
    )
    for lab in LABEL_ENCODING:
        col = f"__ref_n_{lab}"
        values = np.zeros(n, dtype="int64")
        values[frows] = fm[col].to_numpy(dtype="int64")
        result[col] = values

    # Reference rows (by label) whose signature appears in this capture.
    distinct_found = fm.drop_duplicates(subset=SIGNATURE_COLUMNS)
    recovered = {lab: int(distinct_found[f"__ref_n_{lab}"].sum()) for lab in LABEL_ENCODING}
    valid_distinct = distinct_found[
        (distinct_found["__n_labels"] == 1) & distinct_found["__unique_label"].isin(allowed_labels)
    ]
    recovered_valid = {lab: int(valid_distinct[f"__ref_n_{lab}"].sum()) for lab in LABEL_ENCODING}

    stats = {
        "total_rows": n,
        "complete_signature_rows": int(complete.sum()),
        "exact_signature_matches": int(found.sum()),
        "unique_label_matches": int(is_single.sum()),
        "unique_valid_matches": int((is_single & allowed).sum()),
        "ambiguous_matches": int(is_amb.sum()),
        "ambiguous_including_prohibited": int(ambiguous_prohibited.sum()),
        "constraint_rejected_matches": int((is_single & ~allowed).sum()),
        "unmatched_rows": int((status == STATUS_UNMATCHED).sum()),
        "incomplete_signature_rows": int((~complete).sum()),
        "reference_rows_recovered_by_label": recovered,
        "reference_rows_recovered_valid_by_label": recovered_valid,
    }
    stats["signature_match_rate"] = 100.0 * stats["unique_valid_matches"] / n if n else 0.0
    stats["exact_match_rate"] = 100.0 * stats["exact_signature_matches"] / n if n else 0.0
    return result, stats


def classify_victim_subnet(ip_series: pd.Series) -> tuple[np.ndarray, np.ndarray]:
    """Return (in_victim_network, valid_ip) arrays, parsing each distinct IP once."""
    text = _as_text(ip_series)
    in_net: dict[str, bool] = {}
    valid: dict[str, bool] = {}
    for ip in pd.unique(text):
        try:
            addr = ipaddress.ip_address(ip)
            valid[ip] = True
            in_net[ip] = addr.version == VICTIM_NETWORK.version and addr in VICTIM_NETWORK
        except ValueError:
            valid[ip] = False
            in_net[ip] = False
    return text.map(in_net).to_numpy(dtype=bool), text.map(valid).to_numpy(dtype=bool)


def apply_ip_fallback(
    meta: pd.DataFrame, labels: np.ndarray, unresolved_mask: np.ndarray, attack_label: str
) -> tuple[np.ndarray, pd.DataFrame, dict]:
    """Stage 2 (HEURISTIC): label unresolved rows from the victim subnet.

    Rows with a valid unambiguous signature label are never changed. The IP rule
    is also computed for every row so its agreement with the confirmed signature
    labels can be measured.
    """
    src_in, src_valid = classify_victim_subnet(meta["Src IP"])
    dst_in, dst_valid = classify_victim_subnet(meta["Dst IP"])
    rule_label = np.where(src_in | dst_in, attack_label, NORMAL_LABEL).astype(object)
    invalid_ip = ~(src_valid & dst_valid)

    new_labels = labels.copy()
    new_labels[unresolved_mask] = rule_label[unresolved_mask]

    info = pd.DataFrame(
        {
            "IP_Rule_Label": rule_label,
            "Src_In_Victim_Net": src_in,
            "Dst_In_Victim_Net": dst_in,
            "IP_Invalid": invalid_ip,
        }
    )
    stats = {
        "fallback_rows": int(unresolved_mask.sum()),
        "fallback_attack_rows": int((unresolved_mask & (rule_label == attack_label)).sum())
        if attack_label != NORMAL_LABEL
        else 0,
        "fallback_normal_rows": int((unresolved_mask & (rule_label == NORMAL_LABEL)).sum()),
        "fallback_invalid_ip_rows": int((unresolved_mask & invalid_ip).sum()),
        "invalid_ip_rows_total": int(invalid_ip.sum()),
    }
    return new_labels, info, stats


# =============================================================================
# CLEANING, SORTING, SCHEMA
# =============================================================================


def clean_invalid_numeric_values(
    parsed: pd.DataFrame, raw: pd.DataFrame, int_columns: set[str], strategy: str
) -> tuple[pd.DataFrame, np.ndarray, int]:
    """Stage 3: handle values that were invalid (now NaN) in the 66 features.

    Valid values are not changed. Columns that were integers in the input are
    written from the original integer column, so their formatting is unchanged.
    Returns the cleaned features, the number of modified cells per row, and the
    total number of modified cells.
    """
    invalid_mask = parsed.isna()
    modified_per_row = invalid_mask.sum(axis=1).to_numpy()
    cleaned = {}
    for col in FEATURE_COLUMNS:
        if col in int_columns:
            cleaned[col] = raw[col]
        elif strategy == "zero":
            cleaned[col] = parsed[col].fillna(0.0)
        elif strategy == "nan":
            cleaned[col] = parsed[col]
        else:
            raise PipelineError(f"unknown imputation strategy {strategy!r}")
    total = int(invalid_mask.to_numpy().sum()) if strategy == "zero" else 0
    return pd.DataFrame(cleaned, index=parsed.index), modified_per_row, total


def parse_timestamps(ts: pd.Series) -> tuple[pd.Series, dict]:
    """Parse with the primary format, then the fallbacks, counting each."""
    text = _as_text(ts)
    parsed = pd.to_datetime(text, format=TIMESTAMP_FORMAT, errors="coerce")
    used = {TIMESTAMP_FORMAT: int(parsed.notna().sum())}
    for fmt in TIMESTAMP_FALLBACK_FORMATS:
        todo = parsed.isna() & (text != "")
        if not todo.any():
            break
        extra = pd.to_datetime(text[todo], format=fmt, errors="coerce")
        parsed.loc[todo] = extra
        n = int(extra.notna().sum())
        if n:
            used[fmt] = n
    stats = {
        "formats_used": used,
        "invalid_timestamps": int(parsed.isna().sum()),
        "timestamp_min": str(parsed.min()) if parsed.notna().any() else "",
        "timestamp_max": str(parsed.max()) if parsed.notna().any() else "",
    }
    return parsed, stats


def sort_flows_chronologically(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Stage 4: stable chronological sort of one capture. Timestamp strings are kept."""
    parsed, stats = parse_timestamps(df["Timestamp"])
    order_frame = pd.DataFrame({"ts": parsed.to_numpy(), "pos": np.arange(len(df))})
    order = order_frame.sort_values(["ts", "pos"], na_position="last", kind="mergesort")["pos"].to_numpy()
    return df.iloc[order].reset_index(drop=True), stats


def enforce_final_schema(df: pd.DataFrame) -> pd.DataFrame:
    assert len(FINAL_COLUMNS) == 73
    assert len(set(FINAL_COLUMNS)) == 73
    out = df.loc[:, FINAL_COLUMNS]
    assert list(out.columns) == FINAL_COLUMNS
    assert out.shape[1] == 73
    assert out.columns[-1] == LABEL_COLUMN
    return out


def validate_raw_schema(columns: list[str], filename: str) -> dict:
    """Check the raw CICFlowMeter schema before dropping anything."""
    present = set(columns)
    required = METADATA_COLUMNS + FEATURE_COLUMNS
    known = set(required) | set(DROP_COLUMNS) | {LABEL_COLUMN}
    report = {
        "raw_columns": len(columns),
        "missing_required": [c for c in required if c not in present],
        "missing_drop_columns": [c for c in DROP_COLUMNS if c not in present],
        "unexpected_columns": [c for c in columns if c not in known],
        "has_raw_label": LABEL_COLUMN in present,
    }
    if report["missing_required"]:
        raise SchemaError(f"{filename}: required columns missing: {report['missing_required']}")
    if report["missing_drop_columns"]:
        LOG.warning("%s: expected-to-drop columns not present: %s", filename, report["missing_drop_columns"])
    if report["unexpected_columns"]:
        LOG.warning("%s: unexpected columns (not in output): %s", filename, report["unexpected_columns"])
    return report


# =============================================================================
# PER-FILE PROCESSING
# =============================================================================


def _new_result(filename: str, attack_label: str) -> dict:
    return {"filename": filename, "attack_label": attack_label, "status": "FAILED", "error": ""}


def process_single_file(filename: str, lookup: pd.DataFrame, cfg: argparse.Namespace) -> dict:
    """Process one capture independently and write its output and side files."""
    attack_label = INPUT_FILES[filename]
    allowed = ALLOWED_LABELS[filename]
    is_baseline = filename in BASELINE_FILES
    result = _new_result(filename, attack_label)
    path = cfg.input_dir / filename
    LOG.info("=" * 78)
    LOG.info("Processing %s (attack label %s, permitted %s)", filename, attack_label, sorted(allowed))

    raw = read_flow_csv(path)
    result["input_rows"] = int(len(raw))
    raw = normalize_columns(raw)
    raw, dup_notes = resolve_duplicate_columns(raw, filename)
    result["duplicate_columns"] = dup_notes
    for note in dup_notes:
        LOG.info("  %s", note)
    schema = validate_raw_schema(list(raw.columns), filename)
    result["schema"] = schema

    raw = raw.reset_index(drop=True)
    input_row = np.arange(len(raw))
    header_rows = (raw["Src IP"].astype(str).str.strip() == "Src IP") | (
        raw["Timestamp"].astype(str).str.strip() == "Timestamp"
    )
    header_rows = header_rows.to_numpy()
    result["dropped_rows"] = int(header_rows.sum())
    result["dropped_reason"] = "repeated CSV header line (not a flow)" if header_rows.any() else ""
    result["dropped_input_rows"] = input_row[header_rows].tolist()
    if header_rows.any():
        LOG.warning("  dropping %d repeated header lines at data rows %s", header_rows.sum(), input_row[header_rows][:20])
    raw = raw.loc[~header_rows].reset_index(drop=True)
    input_row = input_row[~header_rows]

    if schema["has_raw_label"]:
        result["raw_label_values"] = {str(k): int(v) for k, v in raw[LABEL_COLUMN].value_counts().head(10).items()}
        LOG.info("  raw CICFlowMeter Label values (replaced): %s", result["raw_label_values"])

    meta = raw[METADATA_COLUMNS].astype(str)

    parsed, invalid_rows, int_columns = parse_feature_columns(raw)
    result["invalid_values"] = [r for r in invalid_rows if r["missing"] + r["pos_inf"] + r["neg_inf"] + r["unparseable"]]
    result["invalid_numeric_values"] = int(sum(r["missing"] + r["pos_inf"] + r["neg_inf"] + r["unparseable"] for r in invalid_rows))

    # Stage 1: signature matching.
    match, mstats = match_ground_truth_labels(parsed[SIGNATURE_COLUMNS], lookup, allowed)
    result["matching"] = mstats
    LOG.info(
        "  signatures: %d rows | exact %d | unique-valid %d (%.2f%%) | ambiguous %d | rejected %d | unmatched %d | incomplete %d",
        mstats["total_rows"], mstats["exact_signature_matches"], mstats["unique_valid_matches"],
        mstats["signature_match_rate"], mstats["ambiguous_matches"], mstats["constraint_rejected_matches"],
        mstats["unmatched_rows"], mstats["incomplete_signature_rows"],
    )

    status = match["Signature_Status"].to_numpy(dtype=object)
    labels = match["Signature_Label"].to_numpy(dtype=object).copy()
    resolved = status == STATUS_VALID
    unresolved = ~resolved
    source = np.where(resolved, SOURCE_SIGNATURE, "").astype(object)

    # Stage 2: baseline rule or IP fallback for unresolved rows only.
    labels, ip_info, fstats = apply_ip_fallback(meta, labels, unresolved, attack_label)
    if is_baseline:
        labels[unresolved] = NORMAL_LABEL
        source[unresolved] = SOURCE_BASELINE
        fstats.update(fallback_rows=0, fallback_attack_rows=0, fallback_normal_rows=0, fallback_invalid_ip_rows=0)
        result["baseline_rule_rows"] = int(unresolved.sum())
    else:
        source[unresolved] = SOURCE_FALLBACK
        result["baseline_rule_rows"] = 0
    result["fallback"] = fstats
    if fstats["invalid_ip_rows_total"]:
        LOG.warning("  %d rows have a missing or invalid IP address", fstats["invalid_ip_rows_total"])

    sig_rows = resolved
    if sig_rows.any():
        agree = ip_info["IP_Rule_Label"].to_numpy(dtype=object)[sig_rows] == labels[sig_rows]
        result["ip_rule_agreement_on_signature_rows"] = 100.0 * agree.mean()
    else:
        result["ip_rule_agreement_on_signature_rows"] = None

    if any(lab is None or lab == "" for lab in labels):
        raise PipelineError(f"{filename}: rows left without a label (internal error)")
    bad = sorted(set(labels) - allowed)
    if bad:
        raise PipelineError(f"{filename}: labels outside the permitted set were produced: {bad}")

    # Stage 3: invalid numeric values.
    cleaned, modified_per_row, modified_cells = clean_invalid_numeric_values(parsed, raw, int_columns, cfg.imputation)
    result["imputed_cells"] = modified_cells
    result["rows_with_invalid_values"] = int((modified_per_row > 0).sum())

    out = pd.concat([meta.reset_index(drop=True), cleaned.reset_index(drop=True)], axis=1)
    out[LABEL_COLUMN] = labels
    provenance = pd.DataFrame(
        {
            "input_row": input_row,
            "input_csv_line": input_row + 2,
            "Label_Source": source,
            "Label_Confidence": np.where(source == SOURCE_SIGNATURE, "confirmed_reference", "heuristic"),
            "Signature_Status": status,
            "Ref_Labels": match["Ref_Labels"].to_numpy(),
            "Ref_Row_Count": match["Ref_Row_Count"].to_numpy(),
            "Ambiguous_Includes_Prohibited": match["Ambiguous_Includes_Prohibited"].to_numpy(),
            "IP_Rule_Label": ip_info["IP_Rule_Label"].to_numpy(),
            "Src_In_Victim_Net": ip_info["Src_In_Victim_Net"].to_numpy(),
            "Dst_In_Victim_Net": ip_info["Dst_In_Victim_Net"].to_numpy(),
            "IP_Invalid": ip_info["IP_Invalid"].to_numpy(),
            "Invalid_Feature_Values": modified_per_row,
        }
    )
    prov_cols = list(provenance.columns)
    combined = pd.concat([out, provenance.add_prefix("__p_")], axis=1)

    # Stage 4: chronological sort (per file only).
    combined, ts_stats = sort_flows_chronologically(combined)
    result["timestamps"] = ts_stats
    if ts_stats["invalid_timestamps"]:
        LOG.warning("  %d rows have an unparseable timestamp (kept, placed last)", ts_stats["invalid_timestamps"])

    final = enforce_final_schema(combined)
    prov_out = combined[[f"__p_{c}" for c in prov_cols]].copy()
    prov_out.columns = prov_cols
    prov_out.insert(0, "output_row", np.arange(len(prov_out)))
    prov_out.insert(1, "Label", final[LABEL_COLUMN].to_numpy())
    prov_out.insert(2, "Timestamp", final["Timestamp"].to_numpy())

    out_path = cfg.output_dir / filename
    _guard_output_path(out_path, cfg)
    final.to_csv(out_path, index=False, encoding="utf-8")
    prov_path = cfg.output_dir / PROVENANCE_DIR / filename.replace(".csv", ".provenance.csv")
    prov_out.to_csv(prov_path, index=False, encoding="utf-8")

    flagged = match["Signature_Status"].isin([STATUS_AMBIGUOUS, STATUS_REJECTED]).to_numpy()
    if flagged.any():
        diag = pd.concat(
            [parsed[SIGNATURE_COLUMNS].reset_index(drop=True), match.reset_index(drop=True)], axis=1
        ).loc[flagged]
        group_cols = SIGNATURE_COLUMNS + ["Signature_Status", "Ref_Labels"] + [f"__ref_n_{l}" for l in LABEL_ENCODING]
        diag = diag.groupby(group_cols, dropna=False, sort=False).size().rename("rows_in_capture").reset_index()
        diag = diag.rename(columns={f"__ref_n_{l}": f"ref_rows_{l}" for l in LABEL_ENCODING})
        diag.to_csv(cfg.output_dir / DIAGNOSTICS_DIR / filename.replace(".csv", ".flagged_signatures.csv"),
                    index=False, encoding="utf-8")

    result["output_rows"] = int(len(final))
    result["output_columns"] = int(final.shape[1])
    counts = final[LABEL_COLUMN].value_counts()
    result["class_counts"] = {lab: int(counts.get(lab, 0)) for lab in LABEL_ENCODING}
    by_source = pd.crosstab(final[LABEL_COLUMN], prov_out["Label_Source"])
    result["class_counts_by_source"] = {
        lab: {src: int(by_source.loc[lab, src]) if (lab in by_source.index and src in by_source.columns) else 0
              for src in (SOURCE_SIGNATURE, SOURCE_FALLBACK, SOURCE_BASELINE)}
        for lab in LABEL_ENCODING
    }
    result["status"] = "OK"
    LOG.info("  wrote %s (%d rows x %d columns); classes %s", out_path, len(final), final.shape[1],
             {k: v for k, v in result["class_counts"].items() if v})
    return result


def _guard_output_path(path: Path, cfg: argparse.Namespace) -> None:
    """Never write over an input file or the reference."""
    rp = path.resolve()
    protected = {(cfg.input_dir / f).resolve() for f in INPUT_FILES}
    if cfg.reference_path is not None:
        protected.add(Path(cfg.reference_path).resolve())
    if rp in protected:
        raise PipelineError(f"refusing to write to protected path {rp}")


# =============================================================================
# INDEPENDENT VALIDATION OF THE WRITTEN OUTPUTS
# =============================================================================


def validate_outputs(results: list[dict], cfg: argparse.Namespace) -> list[dict]:
    """Reload every output from disk and check it against the inputs."""
    checks: list[dict] = []

    def add(file, check, ok, detail="", severity="FAIL"):
        checks.append({"File": file, "Check": check, "Status": "PASS" if ok else severity, "Detail": detail})

    schemas = {}
    for res in results:
        fname = res["filename"]
        if res["status"] != "OK":
            add(fname, "file processed", False, res.get("error", ""))
            continue
        out = pd.read_csv(cfg.output_dir / fname, dtype=str, keep_default_na=False, encoding="utf-8")
        prov = pd.read_csv(cfg.output_dir / PROVENANCE_DIR / fname.replace(".csv", ".provenance.csv"),
                           dtype=str, keep_default_na=False, encoding="utf-8")
        schemas[fname] = list(out.columns)

        # Schema.
        add(fname, "exactly 73 columns", out.shape[1] == 73, f"{out.shape[1]} columns")
        add(fname, "columns in specified order", list(out.columns) == FINAL_COLUMNS)
        add(fname, "Label is the final column", out.columns[-1] == LABEL_COLUMN)
        unwanted = [c for c in out.columns if c in DROP_COLUMNS or c not in FINAL_COLUMNS]
        add(fname, "no unwanted columns", not unwanted, ", ".join(unwanted))

        # Labels.
        labels = out[LABEL_COLUMN]
        add(fname, "no missing labels", bool((labels.str.strip() != "").all()), f"{(labels.str.strip() == '').sum()} empty")
        unknown = sorted(set(labels) - set(LABEL_ENCODING))
        add(fname, "only the six permitted label names", not unknown, ", ".join(unknown))
        outside = sorted(set(labels) - ALLOWED_LABELS[fname])
        add(fname, "only the capture's attack class and Normal", not outside,
            f"allowed {sorted(ALLOWED_LABELS[fname])}; found {sorted(set(labels))}")
        if fname in BASELINE_FILES:
            add(fname, "baseline contains only Normal", set(labels) <= {NORMAL_LABEL})
        add(fname, "provenance aligned with output", len(prov) == len(out) and (prov["Label"].to_numpy() == labels.to_numpy()).all()
            and (prov["Timestamp"].to_numpy() == out["Timestamp"].to_numpy()).all())

        # Temporal.
        parsed, ts_stats = parse_timestamps(out["Timestamp"])
        n_invalid = ts_stats["invalid_timestamps"]
        add(fname, "timestamps parse", n_invalid == 0, f"{n_invalid} unparseable", severity="WARN")
        valid = parsed.notna().to_numpy()
        invalid_at_end = (not valid.any()) or bool(valid[: valid.sum()].all())
        mono = parsed[valid].is_monotonic_increasing
        add(fname, "chronologically sorted", bool(mono and invalid_at_end))

        # Integrity against the raw input, reloaded independently.
        raw = read_flow_csv(cfg.input_dir / fname)
        raw = normalize_columns(raw)
        raw, _ = resolve_duplicate_columns(raw, fname)
        in_rows = prov["input_row"].astype(int).to_numpy()
        expected_rows = len(raw) - res["dropped_rows"]
        add(fname, "row count reconciled", len(out) == expected_rows,
            f"input {len(raw)} - dropped {res['dropped_rows']} = {expected_rows}; output {len(out)}")
        kept = np.setdiff1d(np.arange(len(raw)), np.array(res["dropped_input_rows"], dtype=int))
        add(fname, "every kept input row appears exactly once (no duplicated or fabricated rows)",
            len(np.unique(in_rows)) == len(in_rows) and np.array_equal(np.sort(in_rows), kept))
        raw_meta = raw.loc[in_rows, METADATA_COLUMNS].astype(str).to_numpy()
        same_meta = raw_meta == out[METADATA_COLUMNS].to_numpy()
        add(fname, "metadata and timestamp strings preserved exactly", bool(same_meta.all()),
            f"{(~same_meta).sum()} cells differ")

        mismatched = 0
        changed_invalid = 0
        for col in FEATURE_COLUMNS:
            raw_vals, _ = parse_numeric_column(raw.loc[in_rows, col].reset_index(drop=True))
            out_vals, _ = parse_numeric_column(out[col])
            rv, ov = raw_vals.to_numpy(), out_vals.to_numpy()
            raw_valid = ~np.isnan(rv)
            mismatched += int((raw_valid & ~(rv == ov)).sum())
            changed_invalid += int((~raw_valid & ~np.isnan(ov)).sum())
        add(fname, "valid feature values unchanged", mismatched == 0, f"{mismatched} valid cells changed")
        add(fname, "only invalid values were imputed", changed_invalid == res["imputed_cells"],
            f"{changed_invalid} imputed cells; expected {res['imputed_cells']}")
        n_dups = int(out.duplicated().sum())
        checks.append({"File": fname, "Check": "exact duplicate rows in output (information)", "Status": "INFO",
                       "Detail": f"{n_dups} rows identical to an earlier row (each traced to a distinct input row)"})

        counts = labels.value_counts()
        res["validated_class_counts"] = {lab: int(counts.get(lab, 0)) for lab in LABEL_ENCODING}

    if schemas:
        first = next(iter(schemas.values()))
        add("ALL", "all outputs share an identical schema", all(s == first for s in schemas.values()))
    add("ALL", "six output files generated", sum(r["status"] == "OK" for r in results) == len(INPUT_FILES),
        f"{sum(r['status'] == 'OK' for r in results)} of {len(INPUT_FILES)}")
    return checks


# =============================================================================
# REPORTS
# =============================================================================


def _summary_row(res: dict) -> dict:
    m = res.get("matching", {})
    f = res.get("fallback", {})
    c = res.get("class_counts", {})
    attack = res["attack_label"]
    by_src = res.get("class_counts_by_source", {})
    agree = res.get("ip_rule_agreement_on_signature_rows")
    schema = res.get("schema", {})
    notes = []
    if schema.get("missing_drop_columns"):
        notes.append("missing drop columns: " + ", ".join(schema["missing_drop_columns"]))
    if schema.get("unexpected_columns"):
        notes.append("unexpected columns: " + ", ".join(schema["unexpected_columns"]))
    return {
        "Filename": res["filename"],
        "Status": res["status"],
        "Capture Attack Label": attack,
        "Input Rows": res.get("input_rows", ""),
        "Output Rows": res.get("output_rows", ""),
        "Output Columns": res.get("output_columns", ""),
        "Signature Matches": m.get("unique_valid_matches", ""),
        "Signature Match Rate (%)": round(m["signature_match_rate"], 4) if m else "",
        "Exact Signature Matches (any label set)": m.get("exact_signature_matches", ""),
        "Exact Match Rate (%)": round(m["exact_match_rate"], 4) if m else "",
        "Ambiguous Matches": m.get("ambiguous_matches", ""),
        "Ambiguous Incl. Prohibited Label": m.get("ambiguous_including_prohibited", ""),
        "Constraint-Rejected Matches": m.get("constraint_rejected_matches", ""),
        "Unmatched Rows": m.get("unmatched_rows", ""),
        "Incomplete Signature Rows": m.get("incomplete_signature_rows", ""),
        "Fallback Matches": f.get("fallback_rows", ""),
        "Fallback Attack Rows": f.get("fallback_attack_rows", ""),
        "Fallback Normal Rows": f.get("fallback_normal_rows", ""),
        "Fallback Invalid-IP Rows": f.get("fallback_invalid_ip_rows", ""),
        "Baseline-Rule Rows": res.get("baseline_rule_rows", ""),
        "Attack Rows": c.get(attack, "") if attack != NORMAL_LABEL else 0 if c else "",
        "Normal Rows": c.get(NORMAL_LABEL, ""),
        "Attack Rows (Kaggle signature)": by_src.get(attack, {}).get(SOURCE_SIGNATURE, "") if attack != NORMAL_LABEL else 0,
        "Attack Rows (IP fallback)": by_src.get(attack, {}).get(SOURCE_FALLBACK, "") if attack != NORMAL_LABEL else 0,
        "Normal Rows (Kaggle signature)": by_src.get(NORMAL_LABEL, {}).get(SOURCE_SIGNATURE, ""),
        "Normal Rows (IP fallback)": by_src.get(NORMAL_LABEL, {}).get(SOURCE_FALLBACK, ""),
        "Normal Rows (baseline rule)": by_src.get(NORMAL_LABEL, {}).get(SOURCE_BASELINE, ""),
        "IP-Rule Agreement on Signature Rows (%)": round(agree, 2) if agree is not None else "",
        "Invalid Numeric Values": res.get("invalid_numeric_values", ""),
        "Rows With Invalid Values": res.get("rows_with_invalid_values", ""),
        "Imputed Cells": res.get("imputed_cells", ""),
        "Invalid Timestamps": res.get("timestamps", {}).get("invalid_timestamps", ""),
        "Timestamp Min": res.get("timestamps", {}).get("timestamp_min", ""),
        "Timestamp Max": res.get("timestamps", {}).get("timestamp_max", ""),
        "Dropped Rows": res.get("dropped_rows", ""),
        "Dropped Rows Reason": res.get("dropped_reason", "") or ("none" if res["status"] == "OK" else ""),
        "Duplicate Column Handling": "; ".join(res.get("duplicate_columns", [])),
        "Schema Notes": "; ".join(notes),
        "Error": res.get("error", ""),
    }


def _aggregate(results: list[dict]) -> pd.DataFrame:
    rows = []
    for lab, expected in EXPECTED_CLASS_COUNTS.items():
        actual = sum(r.get("validated_class_counts", r.get("class_counts", {})).get(lab, 0) for r in results if r["status"] == "OK")
        sig = sum(r.get("class_counts_by_source", {}).get(lab, {}).get(SOURCE_SIGNATURE, 0) for r in results)
        fb = sum(r.get("class_counts_by_source", {}).get(lab, {}).get(SOURCE_FALLBACK, 0) for r in results)
        bl = sum(r.get("class_counts_by_source", {}).get(lab, {}).get(SOURCE_BASELINE, 0) for r in results)
        recovered = sum(r.get("matching", {}).get("reference_rows_recovered_valid_by_label", {}).get(lab, 0)
                        for r in results if lab in ALLOWED_LABELS[r["filename"]])
        diff = actual - expected
        rows.append({
            "Class": lab,
            "Class ID": LABEL_ENCODING[lab],
            "Actual": actual,
            "Expected (Kaggle)": expected,
            "Difference": diff,
            "Deviation (%)": round(100.0 * diff / expected, 4) if expected else "",
            "Status": "MATCH" if diff == 0 else "MISMATCH",
            "From Kaggle Signature": sig,
            "From IP Fallback (heuristic)": fb,
            "From Baseline Rule": bl,
            "Kaggle Rows Recovered By Signature": recovered,
            "Explanation": _explain(lab, actual, expected, sig, fb, bl, recovered),
        })
    total_actual = sum(r["Actual"] for r in rows)
    total_expected = sum(EXPECTED_CLASS_COUNTS.values())
    rows.append({
        "Class": "TOTAL", "Class ID": "", "Actual": total_actual, "Expected (Kaggle)": total_expected,
        "Difference": total_actual - total_expected,
        "Deviation (%)": round(100.0 * (total_actual - total_expected) / total_expected, 4),
        "Status": "MATCH" if total_actual == total_expected else "MISMATCH",
        "From Kaggle Signature": sum(r["From Kaggle Signature"] for r in rows),
        "From IP Fallback (heuristic)": sum(r["From IP Fallback (heuristic)"] for r in rows),
        "From Baseline Rule": sum(r["From Baseline Rule"] for r in rows),
        "Kaggle Rows Recovered By Signature": sum(r["Kaggle Rows Recovered By Signature"] for r in rows),
        "Explanation": "",
    })
    return pd.DataFrame(rows)


def _explain(lab, actual, expected, sig, fb, bl, recovered) -> str:
    parts = [f"{sig:,} rows confirmed by Kaggle signature"]
    if fb:
        parts.append(f"{fb:,} from the IP-fallback heuristic")
    if bl:
        parts.append(f"{bl:,} from the N-0 baseline rule")
    text = "; ".join(parts) + "."
    text += f" {recovered:,} of {expected:,} Kaggle '{lab}' reference rows have a uniquely-labelled signature in the permitted capture(s)"
    if lab == NORMAL_LABEL:
        text += " (Normal can be recovered by several captures, so this may double count)"
    text += "."
    diff = actual - expected
    if diff > 0:
        text += f" Excess of {diff:,}: "
        text += ("rows labelled by the heuristic or rule, or flows CICFlowMeter split differently than the Kaggle extraction."
                 if (fb or bl) else "repeated signatures: several extracted flows share one reference signature.")
    elif diff < 0:
        text += (f" Shortfall of {-diff:,}: these reference flows were not reproduced with identical signatures"
                 " (different CICFlowMeter version/timeouts, ambiguous signatures, or the class is partly labelled"
                 " differently by the fallback).")
    return text


def generate_verification_report(results, checks, ref_info, lookup_stats, cfg, run_meta) -> pd.DataFrame:
    out = cfg.output_dir
    summary = pd.DataFrame([_summary_row(r) for r in results])
    summary.to_csv(out / "processing_summary.csv", index=False, encoding="utf-8")

    class_rows = []
    for r in results:
        if r["status"] != "OK":
            continue
        for lab in LABEL_ENCODING:
            src = r["class_counts_by_source"][lab]
            class_rows.append({
                "Filename": r["filename"], "Class": lab, "Class ID": LABEL_ENCODING[lab],
                "Count": r["class_counts"][lab],
                "From Kaggle Signature": src[SOURCE_SIGNATURE],
                "From IP Fallback (heuristic)": src[SOURCE_FALLBACK],
                "From Baseline Rule": src[SOURCE_BASELINE],
                "Permitted In Capture": lab in ALLOWED_LABELS[r["filename"]],
            })
    pd.DataFrame(class_rows).to_csv(out / "class_counts_per_file.csv", index=False, encoding="utf-8")

    aggregate = _aggregate(results)
    aggregate.to_csv(out / "aggregated_class_verification.csv", index=False, encoding="utf-8")

    inv_rows = []
    for r in results:
        for item in r.get("invalid_values", []):
            inv_rows.append({
                "Filename": r["filename"], **item,
                "Total": item["missing"] + item["pos_inf"] + item["neg_inf"] + item["unparseable"],
                "Action": "set to NaN then imputed with 0.0" if cfg.imputation == "zero" else "set to NaN (kept)",
            })
    pd.DataFrame(inv_rows, columns=["Filename", "Feature", "missing", "pos_inf", "neg_inf", "unparseable", "Total", "Action"]) \
        .to_csv(out / "invalid_values_report.csv", index=False, encoding="utf-8")

    schema_rows = []
    for r in results:
        s = r.get("schema", {})
        schema_rows.append({
            "Filename": r["filename"], "Raw Columns (after duplicate handling)": s.get("raw_columns", ""),
            "Missing Required": "; ".join(s.get("missing_required", [])),
            "Missing Drop Columns": "; ".join(s.get("missing_drop_columns", [])),
            "Unexpected Columns": "; ".join(s.get("unexpected_columns", [])),
            "Duplicate Columns": "; ".join(r.get("duplicate_columns", [])),
            "Raw Label Values (replaced)": json.dumps(r.get("raw_label_values", {})),
        })
    pd.DataFrame(schema_rows).to_csv(out / "schema_report.csv", index=False, encoding="utf-8")

    pd.DataFrame(checks).to_csv(out / "validation_checks.csv", index=False, encoding="utf-8")

    with open(out / "run_metadata.json", "w", encoding="utf-8") as fh:
        json.dump({**run_meta, "reference": ref_info, "signature_lookup": lookup_stats,
                   "per_file": results}, fh, indent=2, default=str)

    _write_markdown_report(summary, aggregate, checks, ref_info, lookup_stats, results, cfg, run_meta)
    return aggregate


def _md_table(df: pd.DataFrame) -> str:
    cols = list(df.columns)
    lines = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    for _, row in df.iterrows():
        lines.append("| " + " | ".join(str(v).replace("|", "/") for v in row.tolist()) + " |")
    return "\n".join(lines)


def _write_markdown_report(summary, aggregate, checks, ref_info, lookup_stats, results, cfg, run_meta):
    failed = [c for c in checks if c["Status"] == "FAIL"]
    warned = [c for c in checks if c["Status"] == "WARN"]
    key_cols = ["Filename", "Status", "Input Rows", "Output Rows", "Output Columns", "Signature Matches",
                "Signature Match Rate (%)", "Ambiguous Matches", "Constraint-Rejected Matches", "Unmatched Rows",
                "Fallback Matches", "Fallback Attack Rows", "Fallback Normal Rows", "Baseline-Rule Rows",
                "Attack Rows", "Normal Rows", "Invalid Numeric Values", "Invalid Timestamps", "Dropped Rows"]
    lines = [
        "# MSCAD 73-column processing report",
        "",
        f"Run: {run_meta['run_started']} | Python {run_meta['python']} | pandas {run_meta['pandas']} | numpy {run_meta['numpy']}",
        "",
        f"* Reference dataset (read-only): `{ref_info['path']}`, shape {tuple(ref_info['shape'])}, sha256 `{run_meta['reference_sha256']}`",
        f"* Input directory: `{cfg.input_dir}`",
        f"* Output directory: `{cfg.output_dir}`",
        f"* Imputation of invalid feature values: `{cfg.imputation}`",
        "",
        "## Label provenance",
        "",
        "* **kaggle_signature**: confirmed. The 12-feature signature exists in MSCAD.csv with one label, permitted for the capture.",
        "* **baseline_rule**: N-0 rows without a confirmed signature are labelled Normal by capture definition.",
        "* **ip_fallback**: HEURISTIC, not verified ground truth. Victim subnet 192.168.159.0/24 in Src or Dst IP gives the capture's attack label, otherwise Normal.",
        "",
        "Per-row provenance is in `_provenance/`.",
        "",
        "## Reference signature lookup",
        "",
        "```",
        json.dumps(lookup_stats, indent=2),
        "```",
        "",
        "## Per-file summary",
        "",
        _md_table(summary[key_cols]),
        "",
        "## Aggregated class counts vs Kaggle",
        "",
        _md_table(aggregate.drop(columns=["Explanation"])),
        "",
    ]
    for _, row in aggregate.iterrows():
        if row["Explanation"]:
            lines.append(f"* **{row['Class']}**: {row['Explanation']}")
    lines += ["", "## Validation", "",
              f"{sum(c['Status'] == 'PASS' for c in checks)} passed, {len(failed)} failed, {len(warned)} warnings.", ""]
    for c in failed + warned:
        lines.append(f"* {c['Status']} {c['File']}: {c['Check']} ({c['Detail']})")
    lines.append("")
    with open(cfg.output_dir / "processing_report.md", "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# =============================================================================
# MAIN
# =============================================================================


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MSCAD CICFlowMeter CSVs -> six labelled 73-column CSVs")
    p.add_argument("--base-dir", type=Path, default=BASE_DIR, help=f"project directory (default {BASE_DIR})")
    p.add_argument("--input-dir", type=Path, default=None, help="default <base-dir>/CSV")
    p.add_argument("--output-dir", type=Path, default=None, help="default <base-dir>/CSV_73Cols")
    p.add_argument("--reference", type=Path, default=REFERENCE_CSV_PATH, help="path to the Kaggle MSCAD.csv")
    p.add_argument("--search-root", type=Path, action="append", default=[],
                   help="extra directory to search for the reference (repeatable)")
    p.add_argument("--imputation", choices=["zero", "nan"], default=DEFAULT_IMPUTATION,
                   help="how to handle invalid feature values after converting them to NaN")
    args = p.parse_args(argv)
    args.input_dir = args.input_dir or args.base_dir / INPUT_SUBDIR
    args.output_dir = args.output_dir or args.base_dir / OUTPUT_SUBDIR
    return args


def _setup_logging(output_dir: Path | None = None) -> None:
    LOG.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S")
    if not LOG.handlers:
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(fmt)
        LOG.addHandler(console)
    if output_dir is not None:
        fh = logging.FileHandler(output_dir / "processing_log.txt", mode="w", encoding="utf-8")
        fh.setFormatter(fmt)
        LOG.addHandler(fh)


def _print_tables(results, aggregate, checks) -> None:
    pd.set_option("display.width", 250)
    pd.set_option("display.max_columns", 50)
    summary = pd.DataFrame([_summary_row(r) for r in results])
    LOG.info("\nPER-FILE SUMMARY\n%s", summary[[
        "Filename", "Status", "Input Rows", "Output Rows", "Output Columns", "Signature Matches",
        "Signature Match Rate (%)", "Ambiguous Matches", "Constraint-Rejected Matches", "Fallback Matches",
        "Fallback Attack Rows", "Fallback Normal Rows", "Attack Rows", "Normal Rows",
        "Invalid Numeric Values", "Invalid Timestamps", "Dropped Rows"]].to_string(index=False))
    LOG.info("\nAGGREGATED CLASS VERIFICATION\n%s", aggregate.drop(columns=["Explanation"]).to_string(index=False))
    bad = [c for c in checks if c["Status"] in ("FAIL", "WARN")]
    LOG.info("\nVALIDATION: %d PASS, %d FAIL, %d WARN", sum(c["Status"] == "PASS" for c in checks),
             sum(c["Status"] == "FAIL" for c in checks), sum(c["Status"] == "WARN" for c in checks))
    for c in bad:
        LOG.info("  %s %s: %s (%s)", c["Status"], c["File"], c["Check"], c["Detail"])


def main(argv=None) -> int:
    cfg = parse_args(argv)
    _setup_logging()
    run_started = datetime.now().isoformat(timespec="seconds")
    LOG.info("MSCAD 73-column pipeline | input %s | output %s", cfg.input_dir, cfg.output_dir)

    # Pre-flight checks.
    if not cfg.input_dir.is_dir():
        LOG.error("Input directory not found: %s", cfg.input_dir)
        return 2
    if cfg.output_dir.resolve() == cfg.input_dir.resolve():
        LOG.error("Output directory must differ from the input directory")
        return 2
    missing_inputs = [f for f in INPUT_FILES if not (cfg.input_dir / f).is_file()]
    if missing_inputs:
        LOG.error("Missing input files in %s: %s", cfg.input_dir, missing_inputs)
        return 2
    others = sorted(p.name for p in cfg.input_dir.glob("*.csv") if p.name not in INPUT_FILES)
    if others:
        LOG.warning("Other CSV files in the input directory are ignored: %s", others)

    # Locate and validate the reference before writing anything.
    try:
        if cfg.reference is not None:
            ref_path = Path(cfg.reference)
            if not ref_path.is_file():
                raise ReferenceDatasetError(f"--reference file not found: {ref_path}")
            examined = [{"path": str(ref_path), "verdict": "given explicitly"}]
        else:
            roots = [cfg.base_dir] + list(cfg.search_root)
            if cfg.base_dir.parent.is_dir():
                roots += [d for d in sorted(cfg.base_dir.parent.iterdir())
                          if d.is_dir() and "mscad" in d.name.lower() and d.resolve() != cfg.base_dir.resolve()]
            LOG.info("Searching for the Kaggle reference under: %s", [str(r) for r in roots])
            ref_path, examined = locate_reference_dataset(roots, [cfg.input_dir, cfg.output_dir])
        cfg.reference_path = ref_path
        LOG.info("Reference dataset: %s", ref_path)
        ref_sha_before = sha256_of(ref_path)
        reference = normalize_columns(read_flow_csv(ref_path))
        ref_labels, ref_info = validate_reference_dataset(reference, ref_path)
        ref_info["search"] = examined
        LOG.info("Reference validated: shape %s, class counts %s (match expected: %s)",
                 reference.shape, ref_info["class_counts"], ref_info["class_counts_match_expected"])
        lookup, lookup_stats = prepare_signature_lookup(reference, ref_labels)
        LOG.info("Signature lookup: %s", lookup_stats)
        del reference
    except (PipelineError, OSError) as exc:
        LOG.error("STOPPED: %s", exc)
        return 3

    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    (cfg.output_dir / PROVENANCE_DIR).mkdir(exist_ok=True)
    (cfg.output_dir / DIAGNOSTICS_DIR).mkdir(exist_ok=True)
    _setup_logging(cfg.output_dir)
    for stale in (cfg.output_dir / DIAGNOSTICS_DIR).glob("*.flagged_signatures.csv"):
        stale.unlink()

    input_sha_before = {f: sha256_of(cfg.input_dir / f) for f in INPUT_FILES}

    # Each capture is processed on its own; nothing is concatenated across files.
    results = []
    for fname in INPUT_FILES:
        try:
            results.append(process_single_file(fname, lookup, cfg))
        except Exception as exc:  # one failed capture must not stop the others
            LOG.exception("FAILED %s: %s", fname, exc)
            res = _new_result(fname, INPUT_FILES[fname])
            res["error"] = f"{type(exc).__name__}: {exc}"
            results.append(res)

    LOG.info("=" * 78)
    LOG.info("Independent validation of the written outputs")
    checks = validate_outputs(results, cfg)

    input_sha_after = {f: sha256_of(cfg.input_dir / f) for f in INPUT_FILES}
    ref_sha_after = sha256_of(ref_path)
    for f in INPUT_FILES:
        checks.append({"File": f, "Check": "input file unmodified (sha256)",
                       "Status": "PASS" if input_sha_before[f] == input_sha_after[f] else "FAIL",
                       "Detail": input_sha_after[f]})
    checks.append({"File": str(ref_path.name), "Check": "reference dataset unmodified (sha256)",
                   "Status": "PASS" if ref_sha_before == ref_sha_after else "FAIL", "Detail": ref_sha_after})

    run_meta = {
        "run_started": run_started,
        "python": platform.python_version(),
        "pandas": pd.__version__,
        "numpy": np.__version__,
        "input_dir": str(cfg.input_dir),
        "output_dir": str(cfg.output_dir),
        "imputation": cfg.imputation,
        "reference_sha256": ref_sha_after,
        "input_sha256": input_sha_after,
        "label_encoding": LABEL_ENCODING,
        "victim_network": str(VICTIM_NETWORK),
        "signature_columns": SIGNATURE_COLUMNS,
        "timestamp_format": TIMESTAMP_FORMAT,
    }
    aggregate = generate_verification_report(results, checks, ref_info, lookup_stats, cfg, run_meta)
    _print_tables(results, aggregate, checks)
    LOG.info("Reports written to %s", cfg.output_dir)

    ok = all(r["status"] == "OK" for r in results) and not any(c["Status"] == "FAIL" for c in checks)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
