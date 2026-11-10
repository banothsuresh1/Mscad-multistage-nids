# Mscad-multistage-nids
Flow-Aware Temporal Pattern Mining for Multi-Stage Network Intrusion Detection on the MSCAD dataset using deep learning (AE, CNN-LSTM, BiLSTM) and sequential pattern mining.

## Preprocessing: six labelled 73-column flow CSVs

`preprocessing/process_mscad_73cols.py` turns the six CICFlowMeter v4.0 CSVs extracted from the MSCAD
captures into six **independent** 73-column CSVs (6 metadata + 66 Kaggle features + `Label`), using the
original Kaggle `MSCAD.csv` (128,799 x 67) as a read-only label lookup. The six captures are never merged.

```
D:\mscad\
├── MSCAD.csv                      # Kaggle reference (found automatically, never modified)
├── CSV\                           # App-01, App-02, N-0, Scan-1, W-B-01, W-B-02 .pcap_Flow.csv
└── CSV_73Cols\                    # created by the script
```

Run on Windows (Python 3.9+, pandas, numpy) from the repository folder:

```
cd /d D:\mscad\Mscad-multistage-nids
python preprocessing\process_mscad_73cols.py
```

Options: `--base-dir`, `--input-dir`, `--output-dir`, `--reference <path to MSCAD.csv>`,
`--imputation zero|nan` (how invalid feature values such as `Infinity` are handled; default `zero`).

Label assignment (verified per-capture ground truth, in priority order):

1. **Single-class captures, authoritative capture rule**: N-0 → Normal (21), App-01 → HTTP_DDoS (641),
   App-02 → ICMP_Flood (45), Scan-1 → Port_Scan (11,081), W-B-01 → Web_Crwling (26). Signature matches are
   diagnostics only and never change these labels.
2. **W-B-02, exact Kaggle reference matching** (expected Brute_Force 88,526): each flow must match `MSCAD.csv`
   rows on all 66 features or on 12 signature features, and those rows must carry exactly one permitted label.
3. **W-B-02 attack-session rule**: a flow with no reference match gets Brute_Force only if its Src IP, Dst IP,
   Dst Port and Protocol equal those of reference-verified Brute_Force flows and it falls inside their time
   window (e.g. connections CICFlowMeter split into fragments).
4. **Unresolved W-B-02 flows** (ambiguous, prohibited-only or still unmatched) stop that capture. They are
   listed in `_diagnostics/W-B-02.pcap_Flow.unresolved_rows.csv` and nothing is guessed.

A malformed input line that lacks exactly its leading Flow ID field is realigned in memory and listed in
`input_repairs.csv`; any other malformed line fails its capture. Input files are never modified.

Kaggle (128,799 rows) vs the distributed PCAPs (100,340 flows): the 28,459-row difference is
Normal 28,481 (N-0 is a 21-row baseline slice) + Web_Crwling 2 (W-B-01 yields 26 of 28) − Brute_Force 24
(W-B-02 yields 8 extra copies + 17 split-connection fragments − 1 reference row not reproduced), each class
counted once. `capture_reconciliation.csv` shows extracted and Kaggle counts per capture. No rows are added.

Each row's label source is recorded in `CSV_73Cols/_provenance/`. Reports: `processing_summary.csv`,
`aggregated_class_verification.csv`, `capture_reconciliation.csv`, `input_repairs.csv`,
`class_counts_per_file.csv`, `invalid_values_report.csv`,
`schema_report.csv`, `validation_checks.csv`, `processing_report.md`.

Tests (synthetic full-scale data; the real-output check runs when `D:\mscad\CSV_73Cols` exists):
`pytest -q tests\test_process_mscad_73cols.py`
