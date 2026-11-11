# CICFlowMeter extraction audit of the MSCAD captures (Stages A–C)

This note records how the six MSCAD flow CSVs used by `preprocessing/process_mscad_73cols.py` were produced
and verified, and which properties of CICFlowMeter 4.0 shape the flow records. The tools are in `tools/`.
Statements marked *(inferred)* follow from the counts but were not traced to the CICFlowMeter source code.

## 1. Captures (Stages A and B)

The six original PCAPNG captures were audited read-only (`tools/audit_pcapng.py`) and converted to classic
libpcap with `editcap -F pcap`, without filtering, truncation or time shifting
(`tools/convert_mscad_pcapng_to_pcap.py`). Each conversion was verified packet by packet (count, timestamps
to the microsecond, lengths, bytes). The converted files are also packet-identical to the earlier copies in
`D:\mscad\PCAPS` that the original CSVs were made from (`tools/compare_pcap_sets.py`).

| Capture | Packets | SHA-256 of the converted `.pcap` |
|---|---:|---|
| N-0 | 214 | `2129ef0734db645da144bc6afc70a4114e3aecc0f072256ef6b2ca97b50ccfee` |
| Scan-1 | 38,860 | `eef09faffc73e545a2effd4673446e2800f7477ff7b688f77632e6b7aa9b0936` |
| App-01 | 3,217 | `9bc8ebcda86282f9ffcda4138607275cb1b8b3315761e6b203a6c9a3f10e68f4` |
| App-02 | 315,670 | `73eb10020bc9495d16ac932078daf4036dae6e32e25ae423e6192fc7b001e210` |
| W-B-01 | 3,104 | `ca3086118944088e9e2d44d657bc437638a724ff88981535a5820226f459dd0c` |
| W-B-02 | 648,673 | `11d944a013d7632c159a1b55b71e4c44c1010154c514ea24d0fdf257ddff7dd1` |

## 2. Controlled extraction (Stage C)

`tools/stage_c_cicflowmeter_audit.py` runs the installation's own command-line launcher (`cfm.bat`, main class
`cic.cs.unb.ca.ifm.Cmd`, jnetpcap) twice per capture into new folders, then compares the two runs, compares
them with the original CSV, and accounts for every packet per bidirectional 5-tuple (tshark).

* CICFlowMeter 4.0, flow timeout 120,000,000 µs and activity timeout 5,000,000 µs (constants in `Cmd.class`).
* Java 8u202 (via `JAVA_HOME`). Java 21 produces identical values but writes `am`/`pm` instead of `AM`/`PM`.
* The original CSVs (`D:\mscad\CSV`) were made with the CICFlowMeter GUI (`FlowOfflinePane`).

| Capture | Fresh extraction | Original GUI CSV | Kaggle | Result |
|---|---:|---:|---:|---|
| N-0 | 21 | 21 | 21 (Normal: 28,502 in total) | identical |
| App-01 | 641 | 641 | 641 | identical |
| App-02 | 45 | 45 | 45 | identical |
| Scan-1 | 11,081 | 11,081 | 11,081 | identical |
| W-B-01 | 28 | **26** | 28 | **GUI file damaged** |
| W-B-02 | 88,526 | 88,526 | 88,502 | identical |
| **Total** | **100,342** | 100,340 | 128,799 | |

"Identical" means: the same rows, every feature value equal, timestamps equal as times, and run 1 equal to
run 2. The GUI writes rows in a different order than the command line for every capture except App-02; the
order does not change any row.

**W-B-01.** The GUI file has 25 rows identical to the fresh extraction, one row whose line lost its Flow ID and
the start of its Src IP (an mDNS flow from 192.168.159.131; all 76 remaining values match after realignment),
and lacks two flows (an ICMP flow and an LLMNR flow). Since the input packets are identical, the damage
happened when the GUI wrote the file. The pipeline therefore uses the command-line extraction
(`D:\mscad\CSV_REEXTRACTED`, built by `tools/build_csv_reextracted.py`).

## 3. How CICFlowMeter 4.0 turns packets into rows

All packet differences below were accounted for exactly, capture by capture.

| Behaviour | Evidence |
|---|---|
| Only IPv4 is processed; IPv6 and non-IP frames are discarded. | `Discarded` = IPv6 + ARP/LLDP in every capture (e.g. W-B-02: 14 = 12 IPv6 + 2 ARP). |
| Flows with a single packet are never written. | Unanswered probes, isolated broadcasts and trailing ACKs have no row. |
| A TCP flow ends at the **first FIN**. The packets after it start a new flow. | Every connection in App-01 and W-B-02 becomes a main flow (SYN … FIN) plus a 2-packet flow (ACK, FIN); the last ACK forms a 1-packet flow that is not written. |
| ICMP, IGMP and IP fragments without a transport header are written as protocol 0 with ports 0. | App-02's ICMP flood is 34 protocol-0 rows; Scan-1 has IGMP and ICMP protocol-0 rows. |
| Some ARP frames are read as IPv4 at the wrong offset. | Rows between "8.0.6.4" and "8.6.0.1": bytes `08 00 06 04` (ARP protocol type and address sizes) and `08 06 00 01` (ARP ethertype and hardware type). `Valid` = IPv4 + those ARP frames (App-01: 3,186 = 3,180 + 6; App-02: 315,378 = 315,372 + 6; W-B-02: 648,659 = 648,657 + 2). |

### 3.1 Consequences per capture

* **App-01 / W-B-02 (HTTP_DDoS / Brute_Force): one connection, two rows.** W-B-02 contains 44,258 HTTP
  responses and 88,518 TCP rows; App-01 312 responses and 624 TCP rows. About half of these rows are 2-packet
  "tail" flows created by the FIN rule above, not separate attack actions. In W-B-02, 44,163 IPv4 packets
  are in no row: one trailing ACK per connection.
* **Scan-1 (Port_Scan).** The FIN scan was sent as IP fragments (4,014 probes, each split into a 50-byte and a
  38-byte fragment; consistent with nmap `-f`). CICFlowMeter put all 8,028 fragments into **one** protocol-0
  row lasting 1.66 s. The 3,988 RST/ACK replies and 1,115 unanswered UDP probes are single-packet flows and
  produce no row. The 584 ICMP "port unreachable" replies to the UDP scan are not in the protocol-0 row
  between the two hosts either *(inferred: jnetpcap reads the UDP header embedded in the ICMP error, so each
  reply becomes a separate single-packet flow)*.
* **Rows from misread ARP frames:** App-01 1, App-02 1, Scan-1 2 (two flows of 11 and 8 frames, split by the
  120 s flow timeout), W-B-02 1, N-0 0, W-B-01 0 (its single misread frame forms no row).
* **N-0:** 14 packets without a row: 2 ARP, 8 IPv6, 2 trailing ACKs, 2 single-packet UDP flows.

### 3.2 How the pipeline handles these artefacts

Rows are kept exactly as CICFlowMeter wrote them, so the data stays comparable with the Kaggle release and
with other work on MSCAD. Each row's `Extraction_Artefact` in `CSV_73Cols/_provenance/` names the artefact
(`arp_misread_as_ipv4`, `tcp_fin_tail_candidate`, `non_tcp_udp_protocol_0`); `extraction_artefacts.csv`
counts them per file. `tcp_fin_tail_candidate` is a rule on the written values (TCP, no SYN, at least one FIN,
at most 3 packets) and is a candidate flag, not a packet-level proof. Whether to exclude or merge flagged rows
is a modelling decision; for sequence mining, a tail flow follows its main flow within milliseconds and can be
merged on the 5-tuple.

## 4. Related work

The same first-FIN termination artefact ("TCP appendix" flows) was reported for CIC-IDS2017 by Engelen,
Rimmer and Joosen, *Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study*, IEEE Security
and Privacy Workshops 2021. Check the reference before citing it.

## 5. Reproducing

```
python tools\audit_pcapng.py
python tools\convert_mscad_pcapng_to_pcap.py
python tools\compare_pcap_sets.py
python tools\stage_c_cicflowmeter_audit.py --capture <N-0|App-01|App-02|Scan-1|W-B-01|W-B-02> --cfm-home "C:\cicflowmeter\CICFlowMeter-4.0" --audit-dir D:\mscad\CICFlowMeter_AUDIT\<capture>_java8
python tools\build_csv_reextracted.py --execute
python preprocessing\process_mscad_73cols.py
```

Run the Stage C audit in a plain Command Prompt so that `cfm.bat` uses Java 8 through `JAVA_HOME`.
