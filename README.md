# Mscad-multistage-nids
Flow-Aware Temporal Pattern Mining for Multi-Stage Network Intrusion Detection on the MSCAD dataset using deep learning (AE, CNN-LSTM, BiLSTM) and sequential pattern mining.

## Preprocessing: six labelled 73-column flow CSVs

`preprocessing/process_mscad_73cols.py` turns the six CICFlowMeter v4.0 CSVs extracted from the MSCAD
captures into six **independent** 73-column CSVs (6 metadata + 66 Kaggle features + `Label`), using the
original Kaggle `MSCAD.csv` (128,799 x 67) as a read-only label lookup. The six captures are never merged.

```
D:\mscad\
├── MSCAD.csv                      # Kaggle reference (found automatically, never modified)
├── CSV\                           # original GUI extraction (kept; its W-B-01 file is damaged, not used)
├── CSV_REEXTRACTED\               # input: App-01, App-02, N-0, Scan-1, W-B-01, W-B-02 .pcap_Flow.csv
└── CSV_73Cols\                    # created by the script
```

Run on Windows (Python 3.9+, pandas, numpy) from the repository folder:

```
cd /d D:\mscad\Mscad-multistage-nids
python preprocessing\process_mscad_73cols.py
```

The inputs are the command-line CICFlowMeter 4.0 extractions (`cfm.bat`, Java 8) that the Stage C audit
showed to be reproducible and identical to the GUI extraction for five captures; the GUI-extracted W-B-01
file lost 2 flows and part of a line, so with it W-B-01 fails with an explicit message.

Options: `--base-dir`, `--input-dir`, `--output-dir`, `--reference <path to MSCAD.csv>`,
`--imputation zero|nan` (how invalid feature values such as `Infinity` are handled; default `zero`).

Label assignment (verified per-capture ground truth, in priority order):

1. **Single-class captures, authoritative capture rule**: N-0 → Normal (21), App-01 → HTTP_DDoS (641),
   App-02 → ICMP_Flood (45), Scan-1 → Port_Scan (11,081), W-B-01 → Web_Crwling (28). Signature matches are
   diagnostics only and never change these labels.
2. **W-B-02, exact Kaggle reference matching** (expected Brute_Force 88,526): each flow must match `MSCAD.csv`
   rows on all 66 features or on 12 signature features, and those rows must carry exactly one permitted label.
3. **W-B-02 attack-session rule**: a flow with no reference match gets Brute_Force only if its Src IP, Dst IP,
   Dst Port and Protocol equal those of reference-verified Brute_Force flows and it falls inside their time
   window (e.g. connections CICFlowMeter split into fragments).
4. **Unresolved W-B-02 flows** (ambiguous, prohibited-only or still unmatched) stop that capture. They are
   listed in `_diagnostics/W-B-02.pcap_Flow.unresolved_rows.csv` and nothing is guessed.

A malformed input line that lacks exactly its leading Flow ID field is realigned in memory and listed in
`input_repairs.csv` (a safety net; the re-extracted CSVs contain none); any other malformed line fails its
capture. Input files are never modified.

Kaggle (128,799 rows) vs the distributed PCAPs (100,342 flows): the 28,457-row difference is
Normal 28,481 (N-0 is a 21-row baseline slice) − Brute_Force 24 (W-B-02 yields 8 extra copies + 17
split-connection fragments − 1 reference row not reproduced), each class counted once; Port_Scan, HTTP_DDoS,
ICMP_Flood and Web_Crwling match exactly. `capture_reconciliation.csv` shows extracted and Kaggle counts per
capture. No rows are added.

Known CICFlowMeter 4.0 extraction artefacts are **flagged, never removed** (so the data stays comparable with
Kaggle): `Extraction_Artefact` in `_provenance/` and per-file counts in `extraction_artefacts.csv`:
`arp_misread_as_ipv4` (ARP frames read as IPv4; addresses 8.0.6.4 / 8.6.0.1), `tcp_fin_tail_candidate`
(TCP flow without SYN, with FIN, ≤ 3 packets: the rest of a connection after CICFlowMeter closed the main flow
at the first FIN) and `non_tcp_udp_protocol_0` (ICMP, IGMP or IP fragments, written as protocol 0).
See `docs/cicflowmeter_extraction_audit.md`.

Each row's label source is recorded in `CSV_73Cols/_provenance/`. Reports: `processing_summary.csv`,
`aggregated_class_verification.csv`, `capture_reconciliation.csv`, `input_repairs.csv`, `extraction_artefacts.csv`,
`class_counts_per_file.csv`, `invalid_values_report.csv`,
`schema_report.csv`, `validation_checks.csv`, `processing_report.md`.

Building the input folder and auditing the extraction (`tools/`, see `docs/cicflowmeter_extraction_audit.md`):
`audit_pcapng.py` and `convert_mscad_pcapng_to_pcap.py` (PCAPNG → PCAP, verified), `compare_pcap_sets.py`,
`stage_c_cicflowmeter_audit.py` (controlled CICFlowMeter runs with packet accounting), `csv_damage_forensics.py`
and `build_csv_reextracted.py` (checks the Java 8 runs and copies them into `D:\mscad\CSV_REEXTRACTED`).

Tests (synthetic full-scale data; the real-output check runs when `D:\mscad\CSV_73Cols` exists):
`pytest -q tests\test_process_mscad_73cols.py`
