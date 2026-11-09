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

Run on Windows (Python 3.9+, pandas, numpy):

```
copy preprocessing\process_mscad_73cols.py D:\mscad\
python D:\mscad\process_mscad_73cols.py
```

Options: `--base-dir`, `--input-dir`, `--output-dir`, `--reference <path to MSCAD.csv>`,
`--imputation zero|nan` (how invalid feature values such as `Infinity` are handled; default `zero`).

Label assignment, per capture:

1. **Kaggle signature (confirmed)**: exact match on 12 flow features against `MSCAD.csv`. Used only when
   the signature maps to one label and that label is permitted for the capture. Ambiguous and prohibited
   signatures are flagged in `_diagnostics/` and never used.
2. **N-0 baseline rule**: other N-0 rows are Normal.
3. **IP fallback (heuristic, not verified ground truth)**: other rows get the capture's attack label if
   Src or Dst IP is in 192.168.159.0/24, otherwise Normal.

Each row's label source is recorded in `CSV_73Cols/_provenance/`. Reports: `processing_summary.csv`,
`aggregated_class_verification.csv`, `class_counts_per_file.csv`, `invalid_values_report.csv`,
`schema_report.csv`, `validation_checks.csv`, `processing_report.md`.

Synthetic end-to-end test (no real data needed): `python tests/test_process_mscad_73cols.py`
