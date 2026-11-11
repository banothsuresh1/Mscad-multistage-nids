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
* Six CICFlowMeter v4.0 flow CSVs (one per MSCAD capture), default ``D:\\mscad\\CSV_REEXTRACTED\\``:
  the command-line extraction (cfm.bat, Java 8) verified in Stage C to be reproducible. Each file is
  processed INDEPENDENTLY. The six files are NEVER concatenated, appended or merged.
  (The GUI extraction in ``D:\\mscad\\CSV`` is identical for five captures, but its W-B-01 file is damaged:
  2 flows missing and 1 line cut. Using it makes W-B-01 fail with an explicit message.)
* The original Kaggle ``MSCAD.csv`` (expected 128,799 rows x 67 columns), used ONLY
  as a read-only ground-truth lookup table. It is opened in read mode only, and its
  SHA-256 is checked before and after the run.

Outputs (default ``D:\\mscad\\CSV_73Cols\\``)
---------------------------------------------
* The six processed CSVs, keeping their original filenames:
  6 metadata + 66 Kaggle-compatible features + ``Label`` = 73 columns.
* ``processing_summary.csv``          per-file statistics
* ``class_counts_per_file.csv``       per-file class counts, split by label source
* ``aggregated_class_verification.csv`` class-by-class Kaggle-vs-PCAP coverage reconciliation
* ``capture_reconciliation.csv``      per-capture extracted vs Kaggle counts, status and message
* ``input_repairs.csv``               malformed input lines that were realigned (empty if none)
* ``extraction_artefacts.csv``        per-file counts of rows flagged as known CICFlowMeter artefacts
* ``invalid_values_report.csv``       invalid numeric values per file and feature
* ``schema_report.csv``               schema checks of the raw inputs
* ``validation_checks.csv``           checks run after independently reloading the outputs
* ``processing_report.md``            readable report
* ``run_metadata.json``               paths, hashes, configuration, library versions
* ``processing_log.txt``              full log
* ``_provenance/<file>.provenance.csv``  per-row label provenance (same row order as output)
* ``_diagnostics/<file>.signature_collisions.csv``  keys the reference also associates with other classes
* ``_diagnostics/W-B-02.pcap_Flow.unresolved_rows.csv``  only written when W-B-02 rows cannot be labelled

Labelling rules (verified per-capture ground truth), in priority order
---------------------------------------------------------------------
1. Single-class captures are labelled by an authoritative capture rule
   (``capture_rule``): N-0 -> Normal (21), App-01 -> HTTP_DDoS (641),
   App-02 -> ICMP_Flood (45), Scan-1 -> Port_Scan (11,081), W-B-01 -> Web_Crwling (28).
   Signature matches are computed for these files only as diagnostics. A signature
   that the reference associates with another class (a collision) never changes a label.
2. W-B-02 (expected: Brute_Force 88,526) is labelled by exact matching against
   MSCAD.csv: all 66 features (``kaggle_exact_66_features``), otherwise the
   12-feature signature (``kaggle_signature_12``). A flow is verified only when the
   matching reference rows carry exactly one of Brute_Force / Normal. Reference labels
   of other classes on an identical key belong to the other captures and are reported
   as cross-capture collisions.
3. A W-B-02 flow with no reference match gets Brute_Force by the attack-session rule
   (``attack_session_rule``) only if its Src IP, Dst IP, Dst Port and Protocol equal
   those of reference-verified Brute_Force flows and its timestamp lies within their
   first..last timestamp (e.g. a TCP connection CICFlowMeter split into fragments).
4. Ambiguous, prohibited-only or still unmatched W-B-02 flows stop that capture:
   they are written to ``_diagnostics/W-B-02.pcap_Flow.unresolved_rows.csv`` (with the
   reason the session rule did not apply) and no W-B-02 output is written.

Malformed input lines
---------------------
A line with exactly one field fewer than the header, whose values only line up when
an empty leading Flow ID is inserted (integer ports/protocol, valid Dst IP, parseable
timestamp, numeric features), is realigned in memory and listed in
``input_repairs.csv`` (the Src IP is kept as found and flagged if invalid). Any other
malformed line fails its capture. Input files are never modified. The verified re-extracted CSVs contain no
malformed lines; the repair exists only as a safety net (e.g. for the damaged GUI-extracted W-B-01 file,
which is then still reported as a flow-count mismatch, because 2 of its flows are missing).

CICFlowMeter extraction artefacts (flagged, never removed or changed)
----------------------------------------------------------------------
Rows are kept exactly as CICFlowMeter wrote them, so the data stays comparable with the Kaggle release. Each
row's ``Extraction_Artefact`` in ``_provenance/`` names a known artefact of CICFlowMeter 4.0, verified in the
Stage C packet-level audit (empty when none applies):
* ``arp_misread_as_ipv4``      Src/Dst IP 8.0.6.4 / 8.6.0.1: ARP frames read as IPv4 at the wrong offset (the
                               "addresses" are the ARP header bytes 08 00 06 04 and 08 06 00 01).
* ``tcp_fin_tail_candidate``   TCP flow of at most 3 packets without SYN or RST: typically the remainder of a
                               connection after CICFlowMeter closed the main flow at the first FIN. The FIN of
                               the tail itself is often not counted in ``FIN Flag Cnt`` (W-B-02: 44,163 of
                               44,259 tails show 0), so the rule does not require it.
* ``non_tcp_udp_protocol_0``   any other Protocol 0 row: ICMP, IGMP or IP fragments, which CICFlowMeter writes
                               as protocol 0 with ports 0 (e.g. the fragmented FIN scan in Scan-1 is one row).
``extraction_artefacts.csv`` lists the counts per file. Flags are informational and never affect labels.

Kaggle vs PCAP coverage
-----------------------
The six distributed captures yield 100,342 flows; MSCAD.csv has 128,799 rows.
Class by class (each counted once): Normal 28,502 - 21 = 28,481 (N-0 is a 21-row
baseline slice; Kaggle Normal aggregates background traffic across sessions),
Brute_Force 88,502 - 88,526 = -24 (W-B-02: 8 extra copies of reference flows + 17
attack-session fragments - 1 reference row not reproduced); Port_Scan, HTTP_DDoS,
ICMP_Flood and Web_Crwling match exactly. Total 28,481 - 24 = 28,457. ``capture_reconciliation.csv`` states, per capture,
the extracted and Kaggle counts and whether the difference is the documented one;
any other difference fails as a labelling, flow-count or reference mismatch.

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

Exit code 0 means every file was processed and no validation check failed.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
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
INPUT_SUBDIR = "CSV_REEXTRACTED"
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

# Verified per-capture ground truth.
# Single-class captures: every flow gets the capture's class. This rule is authoritative; signature
# matching is computed only as a diagnostic and can never change these labels.
SINGLE_CLASS_CAPTURES = {
    "App-01.pcap_Flow.csv": "HTTP_DDoS",
    "App-02.pcap_Flow.csv": "ICMP_Flood",
    "N-0.pcap_Flow.csv": "Normal",
    "Scan-1.pcap_Flow.csv": "Port_Scan",
    "W-B-01.pcap_Flow.csv": "Web_Crwling",
}
# Mixed-class captures: every flow's label must be established by exact matching against the Kaggle
# reference (Brute_Force and Normal are both possible outcomes, so a key shared by both is ambiguous);
# rows the reference cannot settle stop the capture unless the attack-session rule below verifies them.
MIXED_CLASS_CAPTURES = {
    "W-B-02.pcap_Flow.csv": ("Brute_Force", "Normal"),
}
# Attack-session rule for flows of a mixed capture that match no reference row (e.g. a TCP connection that
# CICFlowMeter split into fragments the Kaggle extraction does not contain). Such a flow gets the attack label
# only if (Src IP, Dst IP, Dst Port, Protocol) equals that of flows verified by the reference with this label
# AND its timestamp lies within the first..last timestamp of those verified flows (inclusive). Otherwise it
# stays unresolved and stops the capture.
SESSION_RULE_LABEL = {
    "W-B-02.pcap_Flow.csv": "Brute_Force",
}
SESSION_KEY_COLUMNS = ["Src IP", "Dst IP", "Dst Port", "Protocol"]

# Labels each capture may contain.
ALLOWED_LABELS = {
    **{fname: {label} for fname, label in SINGLE_CLASS_CAPTURES.items()},
    **{fname: set(labels) for fname, labels in MIXED_CLASS_CAPTURES.items()},
}

# Verified extraction result (rows per capture and label). Used only to VALIDATE the computed output;
# labels are never forced to these numbers.
EXPECTED_CAPTURE_DISTRIBUTION = {
    "N-0.pcap_Flow.csv": {"Normal": 21},
    "App-01.pcap_Flow.csv": {"HTTP_DDoS": 641},
    "App-02.pcap_Flow.csv": {"ICMP_Flood": 45},
    "Scan-1.pcap_Flow.csv": {"Port_Scan": 11_081},
    "W-B-01.pcap_Flow.csv": {"Web_Crwling": 28},
    "W-B-02.pcap_Flow.csv": {"Brute_Force": 88_526},
}
EXPECTED_RAW_TOTAL = 100_342

# Documented differences between a capture and the Kaggle count of its class. A difference is accepted as
# expected only if it equals Kaggle count - verified capture count AND the capture's labels equal the verified
# distribution; anything else fails. (Status shown in capture_reconciliation.csv.)
CAPTURE_VARIATION_STATUS = {
    "W-B-02.pcap_Flow.csv": "Reconciled",
    "N-0.pcap_Flow.csv": "Expected truncated baseline",
}

# Why some Kaggle classes differ from the distributed PCAPs (coverage/extraction, not labelling).
COVERAGE_NOTES = {
    "Normal": ("Kaggle Normal aggregates background traffic across capture sessions; the distributed N-0 PCAP "
               "is a 21-row baseline slice. Missing rows are not fabricated"),
    "Brute_Force": ("W-B-02 yields more flows than Kaggle: extra copies of reference flows and attack-session "
                    "fragments that the Kaggle extraction does not contain"),
}

# Known damaged inputs: (row count that identifies the damaged file, explanation). Used only to explain a
# flow-count mismatch; it never changes the result.
KNOWN_DAMAGED_INPUTS = {
    "W-B-01.pcap_Flow.csv": (26, "this is the damaged GUI-extracted W-B-01 file (D:\\mscad\\CSV): 2 flows are missing "
                                 "and 1 line lost its leading characters. Use the verified command-line extraction "
                                 "(D:\\mscad\\CSV_REEXTRACTED, 28 flows)"),
}

# Known CICFlowMeter 4.0 extraction artefacts (Stage C audit). Flagged per row in _provenance/, never removed.
ARP_MISREAD_ADDRESSES = {"8.0.6.4", "8.6.0.1"}
ARTEFACT_FLAGS = {
    "arp_misread_as_ipv4": "ARP frames read as IPv4 (Src/Dst IP 8.0.6.4 / 8.6.0.1 are ARP header bytes)",
    "tcp_fin_tail_candidate": ("TCP flow of <= 3 packets without SYN or RST: typically the rest of a connection "
                               "after CICFlowMeter closed the main flow at the first FIN"),
    "non_tcp_udp_protocol_0": "ICMP, IGMP or IP fragments, written by CICFlowMeter as protocol 0 with ports 0",
}

assert set(ALLOWED_LABELS) == set(INPUT_FILES) == set(EXPECTED_CAPTURE_DISTRIBUTION)
assert sum(sum(d.values()) for d in EXPECTED_CAPTURE_DISTRIBUTION.values()) == EXPECTED_RAW_TOTAL

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
assert len(FEATURE_COLUMNS) == 66 and FEATURE_COLUMNS[0] == "Flow Duration" and FEATURE_COLUMNS[-1] == "Idle Min"
assert len(FINAL_COLUMNS) == 73 == len(set(FINAL_COLUMNS))

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

# Label sources written to the provenance files.
SOURCE_CAPTURE_RULE = "capture_rule"               # authoritative single-class capture rule
SOURCE_KAGGLE_FULL = "kaggle_exact_66_features"    # unique permitted label, all 66 features identical
SOURCE_KAGGLE_SIG = "kaggle_signature_12"          # unique permitted label, 12-feature signature identical
SOURCE_SESSION_RULE = "attack_session_rule"        # unmatched flow inside a reference-verified attack session
LABEL_SOURCES = (SOURCE_CAPTURE_RULE, SOURCE_KAGGLE_FULL, SOURCE_KAGGLE_SIG, SOURCE_SESSION_RULE)
# Earlier label sources, no longer assigned (kept so existing imports keep working).
SOURCE_SIGNATURE = "kaggle_signature"
SOURCE_BASELINE = "baseline_rule"
SOURCE_FALLBACK = "ip_fallback"

# Per-row outcome of exact reference matching in a mixed-class capture.
MIX_VERIFIED = "verified"
MIX_AMBIGUOUS = "ambiguous"            # several permitted labels share the key
MIX_PROHIBITED = "prohibited_only"     # key exists only with labels not permitted for the capture
MIX_UNMATCHED = "unmatched"            # key not in the reference at any level

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


def _read_csv_frame(source, header: list[str], encoding: str | None = None) -> pd.DataFrame:
    """pandas read with text columns kept as strings and features parsed at round-trip precision."""
    text_raw = [h for h in header if _normalize_name(h) in TEXT_COLUMNS]
    numeric_raw = [h for h in header if _normalize_name(h) not in TEXT_COLUMNS]
    return pd.read_csv(
        source,
        encoding=encoding,
        dtype={h: str for h in text_raw},
        keep_default_na=False,
        na_values={h: READ_NA_TOKENS for h in numeric_raw},
        float_precision="round_trip",
        low_memory=False,
    )


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
            df = _read_csv_frame(path, header, encoding)
            if encoding != "utf-8-sig":
                LOG.warning("%s: not valid UTF-8, read as latin-1", path.name)
            return df
        except UnicodeDecodeError as exc:
            last_error = exc
    raise SchemaError(f"{path.name}: cannot decode file ({last_error})")


def _realign_missing_leading_field(fields: list[str], header: list[str]) -> list[str] | None:
    """Return the line with an empty Flow ID inserted in front, if that makes it fully consistent.

    Accepted only when the header starts with Flow ID, the line has exactly one field fewer than the
    header, and after the shift: ports and protocol are integers, Dst IP is a valid IP address, the
    timestamp parses, and every feature value is numeric (or a recognised missing/Infinity token).
    Src IP is not checked: when the leading field is lost, the start of the Src IP can be lost with it.
    """
    names = [_normalize_name(h) for h in header]
    if not names or names[0] != "Flow ID" or len(fields) != len(header) - 1:
        return None
    candidate = [""] + fields
    position = {}
    for i, name in enumerate(names):
        position.setdefault(name, i)
    value = lambda name: candidate[position[name]].strip()  # noqa: E731
    try:
        if not all(re.fullmatch(r"\d+", value(n)) for n in ("Src Port", "Dst Port", "Protocol")):
            return None
        ipaddress.ip_address(value("Dst IP"))
        if parse_timestamps(pd.Series([value("Timestamp")]))[0].isna().any():
            return None
        for name in FEATURE_COLUMNS:
            v = value(name).lower()
            if v not in MISSING_TOKENS | POS_INF_TOKENS | NEG_INF_TOKENS and np.isnan(_safe_float(v)):
                return None
    except (KeyError, ValueError):
        return None
    return candidate


def read_capture_csv(path: Path) -> tuple[pd.DataFrame, list[dict]]:
    """Read one capture CSV and repair only lines that lack exactly the leading Flow ID field.

    Such a line is otherwise loaded shifted one column to the left (every metadata and feature value in
    the wrong column). It is realigned in memory only when ``_realign_missing_leading_field`` accepts it;
    the input file is never modified. Every repair is returned for the reports. Any other line whose
    field count differs from the header raises SchemaError, so the capture fails visibly.
    """
    rows = None
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            with open(path, "r", encoding=encoding, newline="") as fh:
                rows = list(csv.reader(fh))
            break
        except UnicodeDecodeError:
            continue
    if rows is None:
        raise SchemaError(f"{path.name}: cannot decode file")
    if not rows:
        raise SchemaError(f"{path.name}: file is empty")
    header = rows[0]
    malformed = [i for i, r in enumerate(rows[1:], start=1) if r and len(r) != len(header)]
    if not malformed:
        return read_flow_csv(path), []

    names = [_normalize_name(h) for h in header]
    src_ip_pos = names.index("Src IP") if "Src IP" in names else None
    data_row = {i: k for k, i in enumerate(i for i, r in enumerate(rows[1:], start=1) if r)}
    repairs, problems = [], []
    for i in malformed:
        fixed = _realign_missing_leading_field(rows[i], header)
        if fixed is None:
            problems.append(f"line {i + 1}: {len(rows[i])} fields (header {len(header)})")
            continue
        src_ip = fixed[src_ip_pos].strip() if src_ip_pos is not None else ""
        try:
            ipaddress.ip_address(src_ip)
            src_valid = True
        except ValueError:
            src_valid = False
        repairs.append({
            "CSV line": i + 1,
            "Data row": data_row[i],
            "Fields found": len(rows[i]),
            "Header fields": len(header),
            "Repair": "missing leading Flow ID field: realigned one column to the right",
            "Src IP as found": src_ip,
            "Src IP valid": src_valid,
            "Original line start": " | ".join(rows[i][:6]),
        })
        rows[i] = fixed
    if problems:
        raise SchemaError(f"{path.name}: malformed lines that cannot be repaired safely: " + "; ".join(problems[:10]))

    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="\n").writerows(r for r in rows if r)
    buffer.seek(0)
    return _read_csv_frame(buffer, header), repairs


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
    if feature_order != FEATURE_COLUMNS:
        diffs = [f"position {i}: reference '{r}' vs schema '{e}'"
                 for i, (r, e) in enumerate(zip(feature_order, FEATURE_COLUMNS)) if r != e]
        raise ReferenceDatasetError("reference feature order differs from the 66-feature output schema: "
                                    + "; ".join(diffs[:10]))
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


def prepare_signature_lookup(
    reference_df: pd.DataFrame, labels: pd.Series, columns: list[str] | None = None
) -> tuple[pd.DataFrame, dict]:
    """Build one row per distinct key with its per-label counts.

    The key is the 12-feature signature by default; pass ``columns=FEATURE_COLUMNS`` for the
    stricter exact match on all 66 features.

    A signature seen with more than one label is marked ambiguous. Nothing is
    deduplicated by keeping the first label.
    """
    columns = list(columns or SIGNATURE_COLUMNS)
    keys = {}
    for col in columns:
        keys[col], _ = parse_numeric_column(reference_df[col])
    keys = pd.DataFrame(keys)
    complete = keys.notna().all(axis=1)
    keys = keys + 0.0  # -0.0 -> 0.0
    keys["__label"] = labels.to_numpy()
    keys = keys[complete]

    counts = keys.groupby(columns + ["__label"], sort=False).size()
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
        "key_columns": len(columns),
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
    signatures: pd.DataFrame, lookup: pd.DataFrame, allowed_labels: set[str], columns: list[str] | None = None
) -> tuple[pd.DataFrame, dict]:
    """Exact key match against the reference (12-feature signature unless ``columns`` is given).

    Returns one row per flow (same order as ``signatures``) with signature status,
    the confirmed label (only for STATUS_VALID), the reference label set and
    per-label reference counts.
    """
    columns = list(columns or SIGNATURE_COLUMNS)
    n = len(signatures)
    keys = signatures[columns].reset_index(drop=True)
    complete = keys.notna().all(axis=1).to_numpy()
    keys = keys + 0.0
    keys["__row"] = np.arange(n)

    merged = keys.loc[complete].merge(lookup, on=columns, how="left", sort=False, validate="many_to_one")
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
    distinct_found = fm.drop_duplicates(subset=columns)
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
    """Victim-subnet heuristic (192.168.159.0/24 in Src or Dst IP -> attack label).

    No longer used to assign labels: the per-capture rules in ``assign_capture_labels``
    replaced it. Kept for backward compatibility and ad-hoc diagnostics.
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


class UnresolvedLabelsError(PipelineError):
    """Rows of a mixed-class capture whose label the reference cannot establish."""

    def __init__(self, message: str, rows: pd.DataFrame):
        super().__init__(message)
        self.rows = rows


def resolve_mixed_capture_labels(
    parsed: pd.DataFrame, levels: list[tuple[str, list[str], pd.DataFrame]], allowed_labels: set[str]
) -> tuple[pd.DataFrame, dict]:
    """Label a mixed-class capture from exact Kaggle reference matches only.

    ``levels`` is an ordered list of ``(name, key_columns, lookup)``, strongest key first. For each
    row, the first level at which its key exists in the reference decides the outcome:

    * the reference rows with that key carry exactly one label permitted for the capture -> verified
    * they carry several permitted labels -> ambiguous (never guessed)
    * they carry only labels not permitted for the capture -> prohibited_only

    A row whose key is found at no level is unmatched. A row with a missing/invalid key value at a
    level (for example Infinity in a rate feature) simply moves on to the next level.

    Reference labels outside the permitted set (for example a Port_Scan row identical to a
    brute-force flow) belong to other captures, whose class counts are validated separately; such
    rows are verified on their permitted label and counted as cross-capture collisions.
    Rows whose key occurs more often in the capture than in the reference (for the chosen label)
    are counted as exceeding the reference multiplicity (diagnostic only).
    Returns one row per input row (same order) and statistics.
    """
    n = len(parsed)
    permitted = [lab for lab in LABEL_ENCODING if lab in allowed_labels]
    permitted_arr = np.array(permitted, dtype=object)
    label = np.full(n, None, dtype=object)
    status = np.full(n, MIX_UNMATCHED, dtype=object)
    level_used = np.full(n, "", dtype=object)
    ref_labels = np.full(n, "", dtype=object)
    ref_rows = np.zeros(n, dtype="int64")
    ref_counts = {lab: np.zeros(n, dtype="int64") for lab in LABEL_ENCODING}
    cross = np.zeros(n, dtype=bool)
    over = np.zeros(n, dtype=bool)
    open_rows = np.ones(n, dtype=bool)
    level_stats = {}
    extra_copies = {lab: 0 for lab in permitted}

    for name, columns, lookup in levels:
        match, _ = match_ground_truth_labels(parsed[columns], lookup, set(LABEL_ENCODING), columns=columns)
        total = match["Ref_Row_Count"].to_numpy()
        counts = np.column_stack([match[f"__ref_n_{lab}"].to_numpy() for lab in permitted])
        n_candidates = (counts > 0).sum(axis=1)
        found = total > 0
        here = open_rows & found
        verified = here & (n_candidates == 1)
        ambiguous = here & (n_candidates > 1)
        prohibited = here & (n_candidates == 0)
        chosen = permitted_arr[counts.argmax(axis=1)]

        label[verified] = chosen[verified]
        status[verified] = MIX_VERIFIED
        status[ambiguous] = MIX_AMBIGUOUS
        status[prohibited] = MIX_PROHIBITED
        level_used[here] = name
        ref_labels[here] = match["Ref_Labels"].to_numpy()[here]
        ref_rows[here] = total[here]
        for lab in LABEL_ENCODING:
            ref_counts[lab][here] = match[f"__ref_n_{lab}"].to_numpy()[here]
        cross[verified & (total - counts.sum(axis=1) > 0)] = True

        if verified.any():
            idx = np.flatnonzero(verified)
            keys = parsed[columns].iloc[idx].reset_index(drop=True) + 0.0
            group = keys.groupby(columns, sort=False).ngroup().to_numpy()
            multiplicity = np.bincount(group)[group]
            over[idx[multiplicity > counts.max(axis=1)[idx]]] = True
            # Capture rows beyond the number of reference rows with the same key and label.
            _, first = np.unique(group, return_index=True)
            group_rows = idx[first]
            surplus = np.bincount(group)[group[first]] - counts.max(axis=1)[group_rows]
            for lab in permitted:
                extra_copies[lab] += int(surplus[(chosen[group_rows] == lab) & (surplus > 0)].sum())

        level_stats[name] = {
            "key_columns": len(columns),
            "rows_with_incomplete_key": int((open_rows & parsed[columns].isna().any(axis=1).to_numpy()).sum()),
            "rows_found": int(here.sum()),
            "verified": int(verified.sum()),
            "verified_by_label": {lab: int((verified & (chosen == lab)).sum()) for lab in permitted},
            "ambiguous": int(ambiguous.sum()),
            "prohibited_only": int(prohibited.sum()),
        }
        open_rows &= ~here

    result = pd.DataFrame({
        "Mixed_Status": pd.Series(status, dtype=object),
        "Mixed_Label": pd.Series(label, dtype=object),  # None (not NaN) for rows without a verified label
        "Evidence_Level": pd.Series(level_used, dtype=object),
        "Ref_Labels": pd.Series(ref_labels, dtype=object),
        "Ref_Row_Count": ref_rows,
        "Cross_Capture_Collision": cross,
        "Exceeds_Reference_Multiplicity": over,
        **{f"ref_rows_{lab}": ref_counts[lab] for lab in LABEL_ENCODING},
    })
    verified_all = status == MIX_VERIFIED
    stats = {
        "levels": level_stats,
        "verified": int(verified_all.sum()),
        "verified_by_label": {lab: int((verified_all & (label == lab)).sum()) for lab in permitted},
        "ambiguous": int((status == MIX_AMBIGUOUS).sum()),
        "prohibited_only": int((status == MIX_PROHIBITED).sum()),
        "unmatched": int((status == MIX_UNMATCHED).sum()),
        "cross_capture_collisions_resolved": int(cross.sum()),
        "rows_exceeding_reference_multiplicity": int(over.sum()),
        "extra_copies_by_label": extra_copies,
        "one_to_one_by_label": {lab: int((verified_all & (label == lab)).sum()) - extra_copies[lab] for lab in permitted},
    }
    return result, stats


def apply_attack_session_rule(
    resolved: pd.DataFrame, meta: pd.DataFrame, attack_label: str
) -> tuple[pd.DataFrame, dict]:
    """Verify unmatched flows of a mixed capture against the verified attack sessions.

    An unmatched flow gets ``attack_label`` only if its (Src IP, Dst IP, Dst Port, Protocol) equals that of
    flows the reference verified as ``attack_label`` and its timestamp lies within the first..last timestamp
    of those verified flows (inclusive). Ambiguous and prohibited-only rows are never touched. Returns the
    updated per-row frame (``Evidence_Level`` = SOURCE_SESSION_RULE for the rows labelled here) and stats.
    """
    resolved = resolved.copy()
    key = meta[SESSION_KEY_COLUMNS].astype(str).apply(lambda c: c.str.strip()).agg("|".join, axis=1).to_numpy()
    ts, _ = parse_timestamps(meta["Timestamp"])
    ts = ts.to_numpy()
    verified = ((resolved["Mixed_Status"] == MIX_VERIFIED) & (resolved["Mixed_Label"] == attack_label)).to_numpy()
    unmatched = (resolved["Mixed_Status"] == MIX_UNMATCHED).to_numpy()

    windows = (pd.DataFrame({"key": key[verified], "ts": ts[verified]}).dropna()
               .groupby("key")["ts"].agg(["min", "max", "size"]))
    accepted = np.zeros(len(resolved), dtype=bool)
    reasons = np.full(len(resolved), "", dtype=object)
    for i in np.flatnonzero(unmatched):
        if key[i] not in windows.index:
            reasons[i] = "no verified attack flow with the same Src IP, Dst IP, Dst Port and Protocol"
        elif pd.isna(ts[i]):
            reasons[i] = "unparseable timestamp"
        elif not (windows.at[key[i], "min"] <= ts[i] <= windows.at[key[i], "max"]):
            reasons[i] = "outside the time window of the verified attack flows with this key"
        else:
            accepted[i] = True
    resolved.loc[accepted, "Mixed_Status"] = MIX_VERIFIED
    resolved.loc[accepted, "Mixed_Label"] = attack_label
    resolved.loc[accepted, "Evidence_Level"] = SOURCE_SESSION_RULE
    resolved["Session_Rule_Reason"] = pd.Series(reasons, dtype=object)
    used = sorted(set(key[accepted]))
    stats = {
        "session_rule_rows": int(accepted.sum()),
        "session_rule_rejected": int((unmatched & ~accepted).sum()),
        "session_keys_used": {k: {"verified_flows": int(windows.at[k, "size"]), "first": str(windows.at[k, "min"]),
                                  "last": str(windows.at[k, "max"]), "rows_added": int((key[accepted] == k).sum())}
                              for k in used},
    }
    return resolved, stats


def assign_capture_labels(
    filename: str, parsed: pd.DataFrame, lookup: pd.DataFrame, full_lookup: pd.DataFrame | None = None,
    meta: pd.DataFrame | None = None,
) -> tuple[np.ndarray, pd.DataFrame, dict]:
    """Label one capture with the verified per-capture rules, in priority order.

    1. Single-class capture (``SINGLE_CLASS_CAPTURES``): every row gets the capture's class.
       The 12-feature signature match is computed only as a diagnostic; a signature that the
       reference associates with another class (a collision) never changes the label.
    2. Mixed-class capture (``MIXED_CLASS_CAPTURES``): every row must be verified by exact reference
       matching (66 features when ``full_lookup`` is given, then the 12-feature signature). When ``meta``
       (the metadata columns) is given, unmatched rows may be verified by ``apply_attack_session_rule``.
    3. Any ambiguous, prohibited or still unmatched row in a mixed capture raises UnresolvedLabelsError.

    ``lookup`` is the 12-feature lookup and ``full_lookup`` the 66-feature lookup, both from
    ``prepare_signature_lookup``. Returns labels, per-row provenance and statistics.
    """
    n = len(parsed)
    if filename in SINGLE_CLASS_CAPTURES:
        capture_class = SINGLE_CLASS_CAPTURES[filename]
        diag, dstats = match_ground_truth_labels(parsed[SIGNATURE_COLUMNS], lookup, {capture_class})
        found = diag["Ref_Row_Count"].to_numpy() > 0
        has_class = diag[f"__ref_n_{capture_class}"].to_numpy() > 0
        collision = found & ~has_class
        provenance = pd.DataFrame({
            "Label_Source": np.full(n, SOURCE_CAPTURE_RULE, dtype=object),
            "Match_Status": diag["Signature_Status"].to_numpy(),
            "Ref_Labels": diag["Ref_Labels"].to_numpy(),
            "Ref_Row_Count": diag["Ref_Row_Count"].to_numpy(),
            "Signature_Collision": collision,
        })
        stats = {
            "mode": "single_class",
            "capture_class": capture_class,
            "signature_rows_in_reference": int(found.sum()),
            "signature_rows_reference_includes_capture_class": int((found & has_class).sum()),
            "signature_collisions_overridden": int(collision.sum()),
            "signature_rows_not_in_reference": int((~found).sum()),
            "signature_ambiguous_rows": int(dstats["ambiguous_matches"]),
        }
        return np.full(n, capture_class, dtype=object), provenance, stats

    if filename in MIXED_CLASS_CAPTURES:
        levels = []
        if full_lookup is not None:
            levels.append((SOURCE_KAGGLE_FULL, FEATURE_COLUMNS, full_lookup))
        levels.append((SOURCE_KAGGLE_SIG, SIGNATURE_COLUMNS, lookup))
        resolved, mstats = resolve_mixed_capture_labels(parsed, levels, ALLOWED_LABELS[filename])
        mstats["unmatched_before_session_rule"] = mstats["unmatched"]
        if meta is not None and filename in SESSION_RULE_LABEL and mstats["unmatched"]:
            resolved, sstats = apply_attack_session_rule(resolved, meta.reset_index(drop=True),
                                                         SESSION_RULE_LABEL[filename])
            mstats.update(sstats)
            mstats["unmatched"] = int((resolved["Mixed_Status"] == MIX_UNMATCHED).sum())
        else:
            mstats.update(session_rule_rows=0, session_rule_rejected=0, session_keys_used={})
        unresolved = (resolved["Mixed_Status"] != MIX_VERIFIED).to_numpy()
        if unresolved.any():
            raise UnresolvedLabelsError(
                f"{filename}: {int(unresolved.sum())} rows could not be labelled from the Kaggle reference "
                f"(ambiguous {mstats['ambiguous']}, prohibited-only {mstats['prohibited_only']}, "
                f"unmatched {mstats['unmatched']}).",
                resolved.loc[unresolved],
            )
        provenance = pd.DataFrame({
            "Label_Source": resolved["Evidence_Level"].to_numpy(),
            "Match_Status": resolved["Mixed_Status"].to_numpy(),
            "Ref_Labels": resolved["Ref_Labels"].to_numpy(),
            "Ref_Row_Count": resolved["Ref_Row_Count"].to_numpy(),
            "Signature_Collision": resolved["Cross_Capture_Collision"].to_numpy(),
        })
        return resolved["Mixed_Label"].to_numpy(dtype=object), provenance, {"mode": "mixed_class", **mstats}

    raise PipelineError(f"{filename}: no labelling rule configured")


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


def flag_extraction_artefacts(meta: pd.DataFrame, parsed: pd.DataFrame) -> np.ndarray:
    """One flag per row naming a known CICFlowMeter artefact (see ARTEFACT_FLAGS), or "" when none applies.

    Uses only values written by CICFlowMeter (addresses, protocol, packet and flag counts). Informational:
    flags never change labels, features or row counts."""
    src, dst = meta["Src IP"].str.strip(), meta["Dst IP"].str.strip()
    proto = meta["Protocol"].str.strip()
    num = lambda col: pd.to_numeric(parsed[col], errors="coerce").fillna(0).to_numpy()  # noqa: E731
    packets = num("Tot Fwd Pkts") + num("Tot Bwd Pkts")
    arp = (src.isin(ARP_MISREAD_ADDRESSES) & dst.isin(ARP_MISREAD_ADDRESSES)).to_numpy()
    # no FIN condition: CICFlowMeter often leaves FIN Flag Cnt at 0 for the FIN that closes a tail flow
    tail = (proto == "6").to_numpy() & (num("SYN Flag Cnt") == 0) & (num("RST Flag Cnt") == 0) & (packets <= 3)
    proto0 = (proto == "0").to_numpy() & ~arp
    flags = np.full(len(meta), "", dtype=object)
    flags[proto0] = "non_tcp_udp_protocol_0"
    flags[tail] = "tcp_fin_tail_candidate"
    flags[arp] = "arp_misread_as_ipv4"
    return flags


def process_single_file(
    filename: str, lookup: pd.DataFrame, cfg: argparse.Namespace, full_lookup: pd.DataFrame | None = None
) -> dict:
    """Process one capture independently and write its output and side files.

    ``lookup`` is the 12-feature signature lookup; ``full_lookup`` the optional 66-feature lookup
    used first for mixed-class captures.
    """
    attack_label = INPUT_FILES[filename]
    allowed = ALLOWED_LABELS[filename]
    result = _new_result(filename, attack_label)
    path = cfg.input_dir / filename
    LOG.info("=" * 78)
    mode = "single-class capture rule" if filename in SINGLE_CLASS_CAPTURES else "exact Kaggle reference matching"
    LOG.info("Processing %s (%s; permitted %s)", filename, mode, sorted(allowed))

    # A failed run must not leave an older output behind.
    for stale in (cfg.output_dir / filename,
                  cfg.output_dir / PROVENANCE_DIR / filename.replace(".csv", ".provenance.csv")):
        if stale.exists():
            _guard_output_path(stale, cfg)
            stale.unlink()

    raw, repairs = read_capture_csv(path)
    result["input_repairs"] = repairs
    for r in repairs:
        LOG.warning("  repaired input line %d (%s); Src IP as found: %r%s", r["CSV line"], r["Repair"],
                    r["Src IP as found"], "" if r["Src IP valid"] else " (not a valid IP address; kept as found)")
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

    # Stages 1-2: verified per-capture labelling (single-class rule, or exact reference matching).
    try:
        labels, label_prov, lstats = assign_capture_labels(filename, parsed, lookup, full_lookup, meta=meta)
    except UnresolvedLabelsError as exc:
        rows = exc.rows
        detail = pd.concat([
            pd.DataFrame({"input_row": input_row[rows.index], "input_csv_line": input_row[rows.index] + 2}),
            meta.loc[rows.index].reset_index(drop=True),
            parsed.loc[rows.index, SIGNATURE_COLUMNS].reset_index(drop=True),
            rows.reset_index(drop=True),
        ], axis=1)
        unresolved_path = cfg.output_dir / DIAGNOSTICS_DIR / filename.replace(".csv", ".unresolved_rows.csv")
        detail.to_csv(unresolved_path, index=False, encoding="utf-8")
        result["unresolved_rows"] = int(len(rows))
        raise PipelineError(
            f"{exc} Unresolved rows written to {unresolved_path}; no output was written for this capture."
        ) from exc
    result["labelling"] = lstats
    if lstats["mode"] == "single_class":
        LOG.info("  capture rule: all %d rows -> %s | signature diagnostics: %d in reference, %d collisions "
                 "overridden, %d not in reference", len(labels), lstats["capture_class"],
                 lstats["signature_rows_in_reference"], lstats["signature_collisions_overridden"],
                 lstats["signature_rows_not_in_reference"])
    else:
        LOG.info("  reference matching: verified %d %s | per level %s | extra copies %s | cross-capture "
                 "collisions %d | attack-session rule %d rows", lstats["verified"], lstats["verified_by_label"],
                 {k: v["verified"] for k, v in lstats["levels"].items()}, lstats["extra_copies_by_label"],
                 lstats["cross_capture_collisions_resolved"], lstats["session_rule_rows"])

    if any(lab is None or lab == "" for lab in labels):
        raise PipelineError(f"{filename}: rows left without a label (internal error)")
    bad = sorted(set(labels) - allowed)
    if bad:
        raise PipelineError(f"{filename}: labels outside the permitted set were produced: {bad}")

    src_in, _ = classify_victim_subnet(meta["Src IP"])
    dst_in, _ = classify_victim_subnet(meta["Dst IP"])
    artefacts = flag_extraction_artefacts(meta, parsed)
    result["extraction_artefacts"] = {k: int((artefacts == k).sum()) for k in ARTEFACT_FLAGS}
    if any(result["extraction_artefacts"].values()):
        LOG.info("  extraction artefacts flagged (kept unchanged): %s",
                 {k: v for k, v in result["extraction_artefacts"].items() if v})

    # Stage 3: invalid numeric values.
    cleaned, modified_per_row, modified_cells = clean_invalid_numeric_values(parsed, raw, int_columns, cfg.imputation)
    result["imputed_cells"] = modified_cells
    result["rows_with_invalid_values"] = int((modified_per_row > 0).sum())

    out = pd.concat([meta.reset_index(drop=True), cleaned.reset_index(drop=True)], axis=1)
    out[LABEL_COLUMN] = labels
    provenance = pd.concat([
        pd.DataFrame({"input_row": input_row, "input_csv_line": input_row + 2}),
        label_prov.reset_index(drop=True),
        pd.DataFrame({
            "Src_In_Victim_Net": src_in,
            "Dst_In_Victim_Net": dst_in,
            "Invalid_Feature_Values": modified_per_row,
            "Input_Repair": pd.Series(input_row).map({r["Data row"]: r["Repair"] for r in repairs}).fillna("").to_numpy(),
            "Extraction_Artefact": artefacts,
        }),
    ], axis=1)
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

    collisions = label_prov["Signature_Collision"].to_numpy(dtype=bool)
    if collisions.any():
        diag = pd.concat([parsed[SIGNATURE_COLUMNS].reset_index(drop=True), label_prov.reset_index(drop=True)],
                         axis=1).loc[collisions]
        diag = (diag.groupby(SIGNATURE_COLUMNS + ["Ref_Labels", "Ref_Row_Count"], dropna=False, sort=False)
                .size().rename("rows_in_capture").reset_index())
        diag.insert(0, "Resolution", "kept capture label" if filename in SINGLE_CLASS_CAPTURES
                    else "verified on permitted label; other labels belong to other captures")
        diag.to_csv(cfg.output_dir / DIAGNOSTICS_DIR / filename.replace(".csv", ".signature_collisions.csv"),
                    index=False, encoding="utf-8")

    result["output_rows"] = int(len(final))
    result["output_columns"] = int(final.shape[1])
    counts = final[LABEL_COLUMN].value_counts()
    result["class_counts"] = {lab: int(counts.get(lab, 0)) for lab in LABEL_ENCODING}
    by_source = pd.crosstab(final[LABEL_COLUMN], prov_out["Label_Source"])
    result["class_counts_by_source"] = {
        lab: {src: int(by_source.loc[lab, src]) if (lab in by_source.index and src in by_source.columns) else 0
              for src in LABEL_SOURCES}
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


REPORT_CSV_FILES = (
    "processing_summary.csv",
    "class_counts_per_file.csv",
    "aggregated_class_verification.csv",
    "invalid_values_report.csv",
    "schema_report.csv",
    "validation_checks.csv",
    "capture_reconciliation.csv",
    "input_repairs.csv",
    "extraction_artefacts.csv",
)

CHECK_CATEGORIES = {
    "processing": "Processing failures",
    "schema": "Schema errors",
    "labels": "Labelling mismatches",
    "flow_count": "Missing or additional flows",
    "timestamps": "Timestamp parsing/ordering errors",
    "integrity": "Data-integrity errors",
    "coverage": "Kaggle-vs-PCAP coverage",
}


def validate_outputs(results: list[dict], cfg: argparse.Namespace) -> list[dict]:
    """Reload every output from disk and check it against the inputs and the verified expectations."""
    checks: list[dict] = []

    def add(file, check, ok, detail="", severity="FAIL", category="integrity"):
        checks.append({"File": file, "Category": category, "Check": check,
                       "Status": "PASS" if ok else severity, "Detail": detail})

    schemas = {}
    for res in results:
        fname = res["filename"]
        expected = EXPECTED_CAPTURE_DISTRIBUTION[fname]
        if res["status"] != "OK":
            add(fname, "file processed", False, res.get("error", ""), category="processing")
            continue
        out = pd.read_csv(cfg.output_dir / fname, dtype=str, keep_default_na=False, encoding="utf-8")
        prov = pd.read_csv(cfg.output_dir / PROVENANCE_DIR / fname.replace(".csv", ".provenance.csv"),
                           dtype=str, keep_default_na=False, encoding="utf-8")
        schemas[fname] = list(out.columns)

        # Schema.
        add(fname, "exactly 73 columns", out.shape[1] == 73, f"{out.shape[1]} columns", category="schema")
        add(fname, "columns in specified order", list(out.columns) == FINAL_COLUMNS, category="schema")
        add(fname, "no duplicate column names", len(set(out.columns)) == len(out.columns), category="schema")
        add(fname, "Label is the final column", out.columns[-1] == LABEL_COLUMN, category="schema")
        unwanted = [c for c in out.columns if c in DROP_COLUMNS or c not in FINAL_COLUMNS]
        add(fname, "no unwanted or temporary columns", not unwanted, ", ".join(unwanted), category="schema")

        # Labels.
        labels = out[LABEL_COLUMN]
        add(fname, "no missing labels", bool((labels.str.strip() != "").all()),
            f"{(labels.str.strip() == '').sum()} empty", category="labels")
        unknown = sorted(set(labels) - set(LABEL_ENCODING))
        add(fname, "only the six permitted label names", not unknown, ", ".join(unknown), category="labels")
        outside = sorted(set(labels) - ALLOWED_LABELS[fname])
        add(fname, "only the labels permitted for this capture", not outside,
            f"allowed {sorted(ALLOWED_LABELS[fname])}; found {sorted(set(labels))}", category="labels")
        actual = {lab: int(n) for lab, n in labels.value_counts().items()}
        add(fname, "label distribution equals the verified distribution", actual == expected,
            f"expected {expected}; output {actual}", category="labels")
        add(fname, "provenance aligned with output", len(prov) == len(out)
            and bool((prov["Label"].to_numpy() == labels.to_numpy()).all())
            and bool((prov["Timestamp"].to_numpy() == out["Timestamp"].to_numpy()).all()), category="integrity")

        # Flow counts.
        add(fname, "row count equals the verified extracted count", len(out) == sum(expected.values()),
            f"expected {sum(expected.values()):,}; output {len(out):,}", category="flow_count")

        # Temporal.
        parsed, ts_stats = parse_timestamps(out["Timestamp"])
        n_invalid = ts_stats["invalid_timestamps"]
        add(fname, "timestamps parse", n_invalid == 0, f"{n_invalid} unparseable (kept, placed last)",
            severity="WARN", category="timestamps")
        valid = parsed.notna().to_numpy()
        invalid_at_end = (not valid.any()) or bool(valid[: valid.sum()].all())
        mono = parsed[valid].is_monotonic_increasing
        add(fname, "chronologically sorted", bool(mono and invalid_at_end), category="timestamps")

        # Integrity against the raw input, reloaded independently.
        raw, repairs = read_capture_csv(cfg.input_dir / fname)
        raw = normalize_columns(raw)
        for r in repairs:
            checks.append({"File": fname, "Category": "integrity", "Check": "malformed input line realigned (documented)",
                           "Status": "INFO", "Detail": f"CSV line {r['CSV line']}: {r['Repair']}; Src IP as found "
                                                       f"{r['Src IP as found']!r} (valid IP: {r['Src IP valid']})"})
        raw, _ = resolve_duplicate_columns(raw, fname)
        in_rows = prov["input_row"].astype(int).to_numpy()
        expected_rows = len(raw) - res["dropped_rows"]
        add(fname, "row count reconciled with input", len(out) == expected_rows,
            f"input {len(raw)} - dropped {res['dropped_rows']} = {expected_rows}; output {len(out)}",
            category="flow_count")
        kept = np.setdiff1d(np.arange(len(raw)), np.array(res["dropped_input_rows"], dtype=int))
        add(fname, "every kept input row appears exactly once (no duplicated, fabricated or merged rows)",
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
        checks.append({"File": fname, "Category": "integrity", "Check": "exact duplicate rows in output (information)",
                       "Status": "INFO",
                       "Detail": f"{n_dups} rows identical to an earlier row (each traced to a distinct input row)"})

        res["validated_class_counts"] = {lab: int(actual.get(lab, 0)) for lab in LABEL_ENCODING}

    if schemas:
        first = next(iter(schemas.values()))
        add("ALL", "all outputs share an identical schema", all(s == first for s in schemas.values()),
            category="schema")
    n_ok = sum(r["status"] == "OK" for r in results)
    add("ALL", "six output files generated", n_ok == len(INPUT_FILES), f"{n_ok} of {len(INPUT_FILES)}",
        category="processing")
    extra = sorted(p.name for p in cfg.output_dir.glob("*.csv")
                   if p.name not in INPUT_FILES and p.name not in REPORT_CSV_FILES)
    add("ALL", "no extra or merged CSV in the output directory", not extra, ", ".join(extra), category="integrity")
    return checks


def reconcile_coverage(results: list[dict], reference_class_counts: dict) -> tuple[pd.DataFrame, list[dict]]:
    """Explain the Kaggle-vs-PCAP row difference class by class, and check that it is fully accounted for.

    Each class is counted once. A difference is an expected coverage gap only when the Kaggle count
    and the PCAP output count of that class both equal their verified values; anything else is a
    reference, labelling or flow-count mismatch and fails.
    """
    expected_pcap = {lab: sum(d.get(lab, 0) for d in EXPECTED_CAPTURE_DISTRIBUTION.values()) for lab in LABEL_ENCODING}
    rows, checks = [], []
    for lab in LABEL_ENCODING:
        kaggle = int(reference_class_counts.get(lab, 0))
        per_file = {r["filename"]: r.get("validated_class_counts", {}).get(lab, 0)
                    for r in results if r["status"] == "OK"}
        pcap = int(sum(per_file.values()))
        gap = kaggle - pcap
        documented_gap = EXPECTED_CLASS_COUNTS[lab] - expected_pcap[lab]
        if kaggle != EXPECTED_CLASS_COUNTS[lab]:
            category = "REFERENCE_MISMATCH"
        elif pcap != expected_pcap[lab]:
            category = "LABELLING_OR_FLOW_COUNT_MISMATCH"
        elif gap == 0:
            category = "EXACT_MATCH"
        else:
            category = "EXPECTED_VARIATION"
        sources = ", ".join(f"{f.replace('.pcap_Flow.csv', '')}: {n:,}" for f, n in per_file.items() if n) or "none"
        if category == "EXACT_MATCH":
            explanation = f"All {kaggle:,} Kaggle rows are reproduced by the distributed captures ({sources})."
        elif category == "EXPECTED_VARIATION":
            difference = (f"{gap:,} Kaggle rows have no flow in the distributed PCAPs. " if gap > 0 else
                          f"The distributed captures yield {-gap:,} more flows than Kaggle lists. ")
            explanation = (f"Kaggle has {kaggle:,} rows; the distributed captures yield {pcap:,} ({sources}). "
                           + difference + COVERAGE_NOTES.get(lab, "") + ".")
        else:
            explanation = (f"Kaggle {kaggle:,} (verified {EXPECTED_CLASS_COUNTS[lab]:,}); PCAP output {pcap:,} "
                           f"(verified {expected_pcap[lab]:,}). This difference is not an expected coverage gap.")
        rows.append({
            "Class": lab, "Class ID": LABEL_ENCODING[lab],
            "Kaggle Rows": kaggle, "PCAP Output Rows": pcap, "Difference (Kaggle - PCAP)": gap,
            "Verified Kaggle Rows": EXPECTED_CLASS_COUNTS[lab], "Verified PCAP Rows": expected_pcap[lab],
            "Documented Coverage Gap": documented_gap, "Category": category, "Explanation": explanation,
        })
        checks.append({"File": "ALL", "Category": "coverage", "Check": f"{lab}: Kaggle-vs-PCAP difference accounted for",
                       "Status": "PASS" if category in ("EXACT_MATCH", "EXPECTED_VARIATION") else "FAIL",
                       "Detail": f"{category}: Kaggle {kaggle:,} - PCAP {pcap:,} = {gap:,}"})

    table = pd.DataFrame(rows)
    kaggle_total = int(table["Kaggle Rows"].sum())
    pcap_total = int(table["PCAP Output Rows"].sum())
    total_gap = kaggle_total - pcap_total
    documented_total = int(table["Documented Coverage Gap"].sum())
    positive = [f"{r['Class']} {r['Difference (Kaggle - PCAP)']:,}" for r in rows if r["Difference (Kaggle - PCAP)"] > 0]
    negative = [f"{r['Class']} {-r['Difference (Kaggle - PCAP)']:,}" for r in rows if r["Difference (Kaggle - PCAP)"] < 0]
    gap_parts = " + ".join(positive) + "".join(f" - {n}" for n in negative)
    gap_parts = gap_parts if positive else gap_parts.lstrip(" ")
    total_category = ("EXPECTED_VARIATION" if all(r["Category"] in ("EXACT_MATCH", "EXPECTED_VARIATION")
                                                      for r in rows) else "MISMATCH")
    table = pd.concat([table, pd.DataFrame([{
        "Class": "TOTAL", "Class ID": "", "Kaggle Rows": kaggle_total, "PCAP Output Rows": pcap_total,
        "Difference (Kaggle - PCAP)": total_gap, "Verified Kaggle Rows": sum(EXPECTED_CLASS_COUNTS.values()),
        "Verified PCAP Rows": EXPECTED_RAW_TOTAL, "Documented Coverage Gap": documented_total,
        "Category": total_category,
        "Explanation": (f"Total difference {total_gap:,} = {gap_parts or '0'}; each class is counted once."),
    }])], ignore_index=True)

    checks += [
        {"File": "ALL", "Category": "flow_count", "Check": "raw PCAP total equals the verified total",
         "Status": "PASS" if pcap_total == EXPECTED_RAW_TOTAL else "FAIL",
         "Detail": f"expected {EXPECTED_RAW_TOTAL:,}; output {pcap_total:,}"},
        {"File": "ALL", "Category": "coverage", "Check": "Kaggle reference total equals the verified total",
         "Status": "PASS" if kaggle_total == sum(EXPECTED_CLASS_COUNTS.values()) else "FAIL",
         "Detail": f"expected {sum(EXPECTED_CLASS_COUNTS.values()):,}; reference {kaggle_total:,}"},
        {"File": "ALL", "Category": "coverage",
         "Check": "total difference equals the sum of documented class gaps (no double counting)",
         "Status": "PASS" if total_gap == documented_total == int(table["Difference (Kaggle - PCAP)"].iloc[:-1].sum())
         else "FAIL",
         "Detail": f"{total_gap:,} = {gap_parts or '0'}; documented {documented_total:,}"},
    ]
    return table, checks


def _capture_class(fname: str) -> str:
    """The class whose Kaggle count a capture is compared with."""
    if fname in SINGLE_CLASS_CAPTURES:
        return SINGLE_CLASS_CAPTURES[fname]
    return SESSION_RULE_LABEL.get(fname, MIXED_CLASS_CAPTURES[fname][0])


def reconcile_captures(results: list[dict], reference_class_counts: dict) -> tuple[pd.DataFrame, list[dict]]:
    """Per-capture comparison of extracted rows with the Kaggle count of the capture's class.

    A difference is accepted only when the capture's labels equal the verified distribution, the Kaggle
    count equals its verified value, and the difference equals the documented one (Kaggle count minus
    verified capture count) with a status in CAPTURE_VARIATION_STATUS. For a mixed capture the difference
    must also equal its computed breakdown (extra copies + attack-session rows - reference rows not reproduced).
    """
    by_file = {r["filename"]: r for r in results}
    rows, checks = [], []
    for fname in INPUT_FILES:
        res = by_file.get(fname, {})
        short = fname.split(".pcap")[0]
        cls = _capture_class(fname)
        expected = EXPECTED_CAPTURE_DISTRIBUTION[fname]
        ok_run = res.get("status") == "OK"
        counts = {k: v for k, v in res.get("validated_class_counts", {}).items() if v} if ok_run else {}
        n = sum(counts.values())
        kaggle = int(reference_class_counts.get(cls, 0))
        diff = kaggle - counts.get(cls, 0)
        documented = EXPECTED_CLASS_COUNTS[cls] - expected.get(cls, 0)
        share_text = "100%" if n and counts.get(cls, 0) == n else (f"{100.0 * counts.get(cls, 0) / n:.2f}%" if n else "0%")
        lab = res.get("labelling", {})
        breakdown_ok, breakdown = True, ""
        if fname in MIXED_CLASS_CAPTURES and ok_run:
            extra = lab.get("extra_copies_by_label", {}).get(cls, 0)
            session = lab.get("session_rule_rows", 0)
            not_reproduced = kaggle - lab.get("one_to_one_by_label", {}).get(cls, 0)
            breakdown_ok = extra + session - not_reproduced == -diff
            breakdown = (f"{extra:,} extra copies of reference flows + {session:,} attack-session fragments not in "
                         f"the reference - {not_reproduced:,} reference row(s) not reproduced")

        if not ok_run:
            status, passed = "FAILED", False
            message = f"{short}: not processed ({res.get('error', 'no result')})."
        elif counts != expected:
            status, passed = "Labelling mismatch", False
            message = f"{short}: labels {counts} differ from the verified distribution {expected}."
            damaged = KNOWN_DAMAGED_INPUTS.get(fname)
            if damaged and n == damaged[0]:
                message += f" {n:,} rows: {damaged[1]}."
        elif kaggle != EXPECTED_CLASS_COUNTS[cls]:
            status, passed = "Reference mismatch", False
            message = f"{short}: Kaggle {cls} count {kaggle:,} differs from the verified {EXPECTED_CLASS_COUNTS[cls]:,}."
        elif diff != documented or not breakdown_ok:
            status, passed = "Unexpected difference", False
            message = (f"{short}: Kaggle {kaggle:,} {cls} vs {n:,} extracted; difference {diff:,} is not the "
                       f"documented {documented:,}" + (f" or does not equal its breakdown ({breakdown})" if breakdown else "")
                       + ".")
        elif diff == 0:
            status, passed = "Exact match", True
            message = f"{short}: {n:,} extracted rows assigned {cls} ({share_text}); matches the {kaggle:,} Kaggle {cls} rows."
        elif fname not in CAPTURE_VARIATION_STATUS:
            status, passed = "Unexpected difference", False
            message = f"{short}: Kaggle {kaggle:,} {cls} vs {n:,} extracted; no documented variation for this capture."
        else:
            status, passed = CAPTURE_VARIATION_STATUS[fname], True
            if cls == NORMAL_LABEL:
                message = (f"{short}: All {n:,} extracted rows assigned Normal ({share_text}). Kaggle contains "
                           f"{kaggle:,} Normal rows in total; the {diff:,}-row difference reflects aggregated "
                           f"background traffic across capture sessions that is not present in the distributed "
                           f"{n:,}-row {short} PCAP slice.")
            elif fname in MIXED_CLASS_CAPTURES:
                message = (f"{short}: {n:,} extracted rows assigned {cls} ({share_text}). Kaggle reference contains "
                           f"{kaggle:,} {cls} rows; the {abs(diff):,}-row difference is an expected PCAP extraction "
                           f"variation: {breakdown}.")
            else:
                message = (f"{short}: {n:,} extracted rows assigned {cls} ({share_text}). Kaggle reference contains "
                           f"{kaggle:,} {cls} rows; the {abs(diff):,}-row difference is an expected PCAP extraction "
                           f"variation.")
        repairs = res.get("input_repairs", [])
        if ok_run and repairs:
            message += f" {len(repairs)} malformed input line(s) were realigned before labelling (see input_repairs.csv)."
        rows.append({
            "PCAP file": fname,
            "Extracted rows": n if ok_run else res.get("input_rows", ""),
            "Kaggle reference rows": f"{kaggle:,} {cls}",
            "Final labels": " + ".join(f"{v:,} {k}" for k, v in counts.items()) or "-",
            "Kaggle - Extracted": diff if ok_run else "",
            "Difference": abs(diff) if ok_run else "",
            "Status": status,
            "Message": message,
        })
        checks.append({"File": fname, "Category": "coverage", "Check": "capture reconciled with the Kaggle reference",
                       "Status": "PASS" if passed else "FAIL", "Detail": f"{status}: {message}"})
    return pd.DataFrame(rows), checks


# =============================================================================
# REPORTS
# =============================================================================


def _distribution_text(dist: dict) -> str:
    return "; ".join(f"{k}: {v:,}" for k, v in dist.items() if v)


def _summary_row(res: dict) -> dict:
    fname = res["filename"]
    lab = res.get("labelling", {})
    counts = res.get("class_counts", {})
    expected = EXPECTED_CAPTURE_DISTRIBUTION[fname]
    by_src = res.get("class_counts_by_source", {})
    ok = res["status"] == "OK"

    def from_source(src):
        return sum(v.get(src, 0) for v in by_src.values()) if ok else ""

    schema = res.get("schema", {})
    notes = []
    if schema.get("missing_drop_columns"):
        notes.append("missing drop columns: " + ", ".join(schema["missing_drop_columns"]))
    if schema.get("unexpected_columns"):
        notes.append("unexpected columns: " + ", ".join(schema["unexpected_columns"]))
    single = fname in SINGLE_CLASS_CAPTURES
    return {
        "Filename": fname,
        "Status": res["status"],
        "Labelling Mode": "single-class capture rule" if single else "exact Kaggle reference matching",
        "Permitted Labels": ", ".join(sorted(ALLOWED_LABELS[fname])),
        "Input Rows": res.get("input_rows", ""),
        "Output Rows": res.get("output_rows", ""),
        "Expected Rows": sum(expected.values()),
        "Output Columns": res.get("output_columns", ""),
        "Label Distribution": _distribution_text(counts),
        "Expected Distribution": _distribution_text(expected),
        "Distribution Matches Expected": ({k: v for k, v in counts.items() if v} == expected) if ok else False,
        "Capture-Rule Rows": from_source(SOURCE_CAPTURE_RULE),
        "Verified By Exact 66-Feature Match": from_source(SOURCE_KAGGLE_FULL),
        "Verified By 12-Feature Signature": from_source(SOURCE_KAGGLE_SIG),
        "Verified By Attack-Session Rule": from_source(SOURCE_SESSION_RULE),
        "Extra Copies Of Reference Flows": "" if single else sum(lab.get("extra_copies_by_label", {}).values()),
        "Signature Collisions Overridden By Capture Rule": lab.get("signature_collisions_overridden", "") if single else "",
        "Cross-Capture Collisions Resolved": "" if single else lab.get("cross_capture_collisions_resolved", ""),
        "Rows Exceeding Reference Multiplicity": "" if single else lab.get("rows_exceeding_reference_multiplicity", ""),
        "Unresolved Rows": res.get("unresolved_rows", 0 if ok else ""),
        "Repaired Input Lines": len(res.get("input_repairs", [])),
        **{f"Artefact: {k}": res.get("extraction_artefacts", {}).get(k, "") for k in ARTEFACT_FLAGS},
        "Invalid Numeric Values": res.get("invalid_numeric_values", ""),
        "Rows With Invalid Values": res.get("rows_with_invalid_values", ""),
        "Imputed Cells": res.get("imputed_cells", ""),
        "Invalid Timestamps": res.get("timestamps", {}).get("invalid_timestamps", ""),
        "Timestamp Min": res.get("timestamps", {}).get("timestamp_min", ""),
        "Timestamp Max": res.get("timestamps", {}).get("timestamp_max", ""),
        "Dropped Rows": res.get("dropped_rows", ""),
        "Dropped Rows Reason": res.get("dropped_reason", "") or ("none" if ok else ""),
        "Duplicate Column Handling": "; ".join(res.get("duplicate_columns", [])),
        "Schema Notes": "; ".join(notes),
        "Error": res.get("error", ""),
    }


def generate_verification_report(results, checks, ref_info, lookup_stats, cfg, run_meta,
                                 coverage: pd.DataFrame, captures: pd.DataFrame | None = None) -> pd.DataFrame:
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
                "Expected Count": EXPECTED_CAPTURE_DISTRIBUTION[r["filename"]].get(lab, 0),
                "From Capture Rule": src[SOURCE_CAPTURE_RULE],
                "From Exact 66-Feature Match": src[SOURCE_KAGGLE_FULL],
                "From 12-Feature Signature": src[SOURCE_KAGGLE_SIG],
                "From Attack-Session Rule": src[SOURCE_SESSION_RULE],
                "Permitted In Capture": lab in ALLOWED_LABELS[r["filename"]],
            })
    pd.DataFrame(class_rows).to_csv(out / "class_counts_per_file.csv", index=False, encoding="utf-8")

    coverage.to_csv(out / "aggregated_class_verification.csv", index=False, encoding="utf-8")
    if captures is None:
        captures = pd.DataFrame()
    captures.to_csv(out / "capture_reconciliation.csv", index=False, encoding="utf-8")
    repair_rows = [{"Filename": r["filename"], **rep_} for r in results for rep_ in r.get("input_repairs", [])]
    pd.DataFrame(repair_rows, columns=["Filename", "CSV line", "Data row", "Fields found", "Header fields", "Repair",
                                       "Src IP as found", "Src IP valid", "Original line start"]) \
        .to_csv(out / "input_repairs.csv", index=False, encoding="utf-8")
    artefact_rows = [{"Filename": r["filename"], "Flag": k, "Rows": r.get("extraction_artefacts", {}).get(k, 0),
                      "Output Rows": r.get("output_rows", ""), "Meaning": meaning}
                     for r in results if r["status"] == "OK" for k, meaning in ARTEFACT_FLAGS.items()]
    pd.DataFrame(artefact_rows, columns=["Filename", "Flag", "Rows", "Output Rows", "Meaning"]) \
        .to_csv(out / "extraction_artefacts.csv", index=False, encoding="utf-8")

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
                   "coverage": coverage.to_dict(orient="records"),
                   "captures": captures.to_dict(orient="records"), "per_file": results}, fh, indent=2, default=str)

    _write_markdown_report(summary, coverage, checks, ref_info, lookup_stats, cfg, run_meta, captures)
    return coverage


def _md_table(df: pd.DataFrame) -> str:
    cols = list(df.columns)
    lines = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    for _, row in df.iterrows():
        lines.append("| " + " | ".join(str(v).replace("|", "/") for v in row.tolist()) + " |")
    return "\n".join(lines)


def _status_counts(checks) -> dict:
    return {s: sum(c["Status"] == s for c in checks) for s in ("PASS", "FAIL", "WARN", "INFO")}


def _write_markdown_report(summary, coverage, checks, ref_info, lookup_stats, cfg, run_meta, captures=None):
    counts = _status_counts(checks)
    key_cols = ["Filename", "Status", "Labelling Mode", "Input Rows", "Output Rows", "Expected Rows",
                "Output Columns", "Label Distribution", "Distribution Matches Expected", "Capture-Rule Rows",
                "Verified By Exact 66-Feature Match", "Verified By 12-Feature Signature",
                "Verified By Attack-Session Rule", "Signature Collisions Overridden By Capture Rule",
                "Unresolved Rows", "Repaired Input Lines", "Invalid Numeric Values", "Invalid Timestamps", "Dropped Rows"]
    category_rows = []
    for key, title in CHECK_CATEGORIES.items():
        group = [c for c in checks if c.get("Category") == key]
        category_rows.append({"Category": title, "Checks": len(group),
                              **{s: sum(c["Status"] == s for c in group) for s in ("PASS", "FAIL", "WARN", "INFO")}})
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
        f"**Validation: PASS {counts['PASS']}, FAIL {counts['FAIL']}, WARN {counts['WARN']}, INFO {counts['INFO']}**",
        "",
        "## Labelling rules (priority order)",
        "",
        "1. **capture_rule**: single-class captures (N-0, App-01, App-02, Scan-1, W-B-01). Every flow gets the "
        "capture's class; signature matches are diagnostics only and never change these labels.",
        "2. **kaggle_exact_66_features / kaggle_signature_12**: W-B-02, the only mixed capture. A flow is "
        "verified when all 66 features (otherwise the 12-feature signature) match Kaggle reference rows carrying "
        "exactly one of the permitted labels (Brute_Force, Normal).",
        "3. **attack_session_rule**: a W-B-02 flow with no reference match gets Brute_Force only if its Src IP, "
        "Dst IP, Dst Port and Protocol equal those of reference-verified Brute_Force flows and its timestamp lies "
        "within their first..last timestamp.",
        "4. Ambiguous, prohibited-only or still unmatched W-B-02 flows stop that capture; they are listed in "
        "`_diagnostics/W-B-02.pcap_Flow.unresolved_rows.csv` and nothing is guessed.",
        "",
        "Input lines that lack exactly their leading Flow ID field are realigned one column before processing "
        "(listed in `input_repairs.csv`); any other malformed line fails its capture.",
        "",
        "## CICFlowMeter extraction artefacts (flagged in `_provenance/`, rows kept unchanged)",
        "",
        _md_table(pd.DataFrame([{"Filename": r["Filename"], **{k: r.get(f"Artefact: {k}", "") for k in ARTEFACT_FLAGS}}
                                for _, r in summary.iterrows()])),
        "",
        *[f"* `{k}`: {v}" for k, v in ARTEFACT_FLAGS.items()],
        "",
        "Per-row label source: `_provenance/`.",
        "",
        "## Per-file summary",
        "",
        _md_table(summary[key_cols]),
        "",
        "## Capture reconciliation (extracted PCAP rows vs Kaggle reference)",
        "",
        _md_table(captures.drop(columns=["Message"])) if captures is not None and not captures.empty else "_not available_",
        "",
        *[f"* {m}" for m in (captures["Message"] if captures is not None and not captures.empty else [])],
        "",
        "## Kaggle vs PCAP coverage (each class counted once)",
        "",
        _md_table(coverage.drop(columns=["Explanation"])),
        "",
    ]
    for _, row in coverage.iterrows():
        lines.append(f"* **{row['Class']}** ({row['Category']}): {row['Explanation']}")
    lines += [
        "",
        "## Validation by category",
        "",
        _md_table(pd.DataFrame(category_rows)),
        "",
    ]
    for c in checks:
        if c["Status"] in ("FAIL", "WARN"):
            lines.append(f"* {c['Status']} [{CHECK_CATEGORIES.get(c.get('Category'), '')}] {c['File']}: "
                         f"{c['Check']} ({c['Detail']})")
    lines += ["", "## Reference lookups", "", "```", json.dumps(lookup_stats, indent=2), "```", ""]
    with open(cfg.output_dir / "processing_report.md", "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# =============================================================================
# MAIN
# =============================================================================


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MSCAD CICFlowMeter CSVs -> six labelled 73-column CSVs")
    p.add_argument("--base-dir", type=Path, default=BASE_DIR, help=f"project directory (default {BASE_DIR})")
    p.add_argument("--input-dir", type=Path, default=None, help=f"default <base-dir>/{INPUT_SUBDIR}")
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


def _print_tables(results, coverage, checks, captures=None) -> None:
    pd.set_option("display.width", 250)
    pd.set_option("display.max_columns", 50)
    pd.set_option("display.max_colwidth", 60)
    summary = pd.DataFrame([_summary_row(r) for r in results])
    LOG.info("\nPER-FILE SUMMARY\n%s", summary[[
        "Filename", "Status", "Input Rows", "Output Rows", "Expected Rows", "Output Columns", "Label Distribution",
        "Distribution Matches Expected", "Capture-Rule Rows", "Verified By Exact 66-Feature Match",
        "Verified By 12-Feature Signature", "Verified By Attack-Session Rule", "Unresolved Rows",
        "Repaired Input Lines", "Invalid Timestamps", "Dropped Rows"]].to_string(index=False))
    if captures is not None and not captures.empty:
        LOG.info("\nCAPTURE RECONCILIATION\n%s", captures.drop(columns=["Message"]).to_string(index=False))
        for message in captures["Message"]:
            LOG.info("  %s", message)
    LOG.info("\nKAGGLE vs PCAP COVERAGE\n%s", coverage.drop(columns=["Explanation"]).to_string(index=False))
    for _, row in coverage.iterrows():
        LOG.info("  %s: %s", row["Class"], row["Explanation"])
    counts = _status_counts(checks)
    LOG.info("\nVALIDATION: %d PASS, %d FAIL, %d WARN, %d INFO", counts["PASS"], counts["FAIL"], counts["WARN"],
             counts["INFO"])
    for c in checks:
        if c["Status"] in ("FAIL", "WARN"):
            LOG.info("  %s [%s] %s: %s (%s)", c["Status"], c.get("Category"), c["File"], c["Check"], c["Detail"])


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
        lookup, sig_stats = prepare_signature_lookup(reference, ref_labels)
        full_lookup, full_stats = prepare_signature_lookup(reference, ref_labels, columns=FEATURE_COLUMNS)
        lookup_stats = {"signature_12": sig_stats, "exact_66_features": full_stats}
        LOG.info("12-feature signature lookup: %s", sig_stats)
        LOG.info("66-feature exact lookup: %s", full_stats)
        del reference
    except (PipelineError, OSError) as exc:
        LOG.error("STOPPED: %s", exc)
        return 3

    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    (cfg.output_dir / PROVENANCE_DIR).mkdir(exist_ok=True)
    (cfg.output_dir / DIAGNOSTICS_DIR).mkdir(exist_ok=True)
    _setup_logging(cfg.output_dir)
    for stale in (cfg.output_dir / DIAGNOSTICS_DIR).glob("*.csv"):
        stale.unlink()

    input_sha_before = {f: sha256_of(cfg.input_dir / f) for f in INPUT_FILES}

    # Each capture is processed on its own; nothing is concatenated across files.
    results = []
    for fname in INPUT_FILES:
        try:
            results.append(process_single_file(fname, lookup, cfg, full_lookup=full_lookup))
        except Exception as exc:  # one failed capture must not stop the others
            LOG.exception("FAILED %s: %s", fname, exc)
            res = _new_result(fname, INPUT_FILES[fname])
            res["error"] = f"{type(exc).__name__}: {exc}"
            results.append(res)

    LOG.info("=" * 78)
    LOG.info("Independent validation of the written outputs")
    checks = validate_outputs(results, cfg)
    coverage, coverage_checks = reconcile_coverage(results, ref_info["class_counts"])
    captures, capture_checks = reconcile_captures(results, ref_info["class_counts"])
    checks += coverage_checks + capture_checks

    input_sha_after = {f: sha256_of(cfg.input_dir / f) for f in INPUT_FILES}
    ref_sha_after = sha256_of(ref_path)
    for f in INPUT_FILES:
        checks.append({"File": f, "Category": "integrity", "Check": "input file unmodified (sha256)",
                       "Status": "PASS" if input_sha_before[f] == input_sha_after[f] else "FAIL",
                       "Detail": input_sha_after[f]})
    checks.append({"File": str(ref_path.name), "Category": "integrity", "Check": "reference dataset unmodified (sha256)",
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
        "single_class_captures": SINGLE_CLASS_CAPTURES,
        "mixed_class_captures": {k: list(v) for k, v in MIXED_CLASS_CAPTURES.items()},
        "expected_capture_distribution": EXPECTED_CAPTURE_DISTRIBUTION,
        "signature_columns": SIGNATURE_COLUMNS,
        "timestamp_format": TIMESTAMP_FORMAT,
    }
    coverage = generate_verification_report(results, checks, ref_info, lookup_stats, cfg, run_meta, coverage, captures)
    _print_tables(results, coverage, checks, captures)
    LOG.info("Reports written to %s", cfg.output_dir)

    ok = all(r["status"] == "OK" for r in results) and not any(c["Status"] == "FAIL" for c in checks)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
