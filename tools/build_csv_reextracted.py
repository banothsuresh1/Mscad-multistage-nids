r"""Build D:\mscad\CSV_REEXTRACTED from the Stage C command-line extractions (cfm.bat, Java 8).

For each of the six captures it takes run1\<capture>.pcap_Flow.csv from the Stage C audit folder
(default D:\mscad\CICFlowMeter_AUDIT\<capture>_java8) and checks, before anything is copied:
  * run1 and run2 exist and have identical content (byte-identical, or the same rows),
  * the expected number of flows (N-0 21, App-01 641, App-02 45, Scan-1 11,081, W-B-01 28, W-B-02 88,526),
  * every line has the same number of fields as the header (no malformed lines),
  * timestamps end in upper-case AM/PM, as written by Java 8 (Java 21 writes am/pm).

Without --execute it only checks and prints the plan (nothing is written).
With --execute it copies the six files into a NEW folder (refuses if the folder exists and is not empty),
verifies each copy's SHA-256 and writes manifest.tsv and manifest.json there (not .csv, so the pipeline
sees only the six flow CSVs in that folder).
It never writes anywhere else and never touches D:\mscad\CSV, the PCAPs or the audit folders.

Usage:
    python build_csv_reextracted.py                       (check only)
    python build_csv_reextracted.py --execute             (check, then copy)
    python build_csv_reextracted.py --run-dir App-02=D:\mscad\CICFlowMeter_AUDIT\App-02_java8 --execute
"""
import argparse
import csv
import hashlib
import io
import json
import shutil
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

EXPECTED_FLOWS = {"N-0": 21, "App-01": 641, "App-02": 45, "Scan-1": 11_081, "W-B-01": 28, "W-B-02": 88_526}
STAGE_B_SHA256 = {
    "N-0":    "2129ef0734db645da144bc6afc70a4114e3aecc0f072256ef6b2ca97b50ccfee",
    "Scan-1": "eef09faffc73e545a2effd4673446e2800f7477ff7b688f77632e6b7aa9b0936",
    "App-01": "9bc8ebcda86282f9ffcda4138607275cb1b8b3315761e6b203a6c9a3f10e68f4",
    "App-02": "73eb10020bc9495d16ac932078daf4036dae6e32e25ae423e6192fc7b001e210",
    "W-B-01": "ca3086118944088e9e2d44d657bc437638a724ff88981535a5820226f459dd0c",
    "W-B-02": "11d944a013d7632c159a1b55b71e4c44c1010154c514ea24d0fdf257ddff7dd1",
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def read_rows(path):
    text = Path(path).read_text(encoding="utf-8-sig")
    rows = [r for r in csv.reader(io.StringIO(text)) if r]
    return [h.strip() for h in rows[0]], rows[1:]


def check_capture(cap, run_dir):
    """Return (ok, info dict, list of problems)."""
    problems, info = [], {"capture": cap, "audit_folder": str(run_dir)}
    name = f"{cap}.pcap_Flow.csv"
    r1, r2 = run_dir / "run1" / name, run_dir / "run2" / name
    for p in (r1, r2):
        if not p.is_file():
            problems.append(f"missing {p}")
    if problems:
        return False, info, problems
    info["source"] = str(r1)
    info["sha256"] = sha256(r1)
    info["run2_sha256"] = sha256(r2)
    header, rows = read_rows(r1)
    _, rows2 = read_rows(r2)
    info["columns"] = len(header)
    info["flows"] = len(rows)
    bad = [i + 2 for i, r in enumerate(rows) if len(r) != len(header)]
    if info["sha256"] == info["run2_sha256"]:
        info["run1_vs_run2"] = "byte-identical"
    elif Counter(map(tuple, rows)) == Counter(map(tuple, rows2)):
        info["run1_vs_run2"] = "same rows (different byte order)"
    else:
        info["run1_vs_run2"] = "DIFFERENT"
        problems.append("run1 and run2 differ: the extraction is not reproducible")
    if len(rows) != EXPECTED_FLOWS[cap]:
        problems.append(f"{len(rows):,} flows, expected {EXPECTED_FLOWS[cap]:,}")
    if bad:
        problems.append(f"{len(bad)} malformed line(s), e.g. lines {bad[:5]}")
    if len(header) != 84:
        problems.append(f"{len(header)} columns, expected 84 (CICFlowMeter 4.0)")
    if "Timestamp" in header:
        ts = header.index("Timestamp")
        endings = Counter(r[ts].strip()[-2:] for r in rows if len(r) > ts)
        info["timestamp_endings"] = dict(endings)
        if set(endings) - {"AM", "PM"}:
            problems.append(f"timestamps end in {dict(endings)}: not the Java 8 format (upper-case AM/PM); "
                            "re-run this capture's Stage C audit in a plain Command Prompt (Java 8)")
    else:
        problems.append("no Timestamp column")
    summary = run_dir / "stage_c_summary.json"
    if summary.is_file():
        try:
            data = json.loads(summary.read_text(encoding="utf-8"))
            info["java"] = (data.get("java") or {}).get("version", "").splitlines()[0:1]
            cmd = " ".join(str(r.get("command", "")) for r in (data.get("extraction") or {}).get("runs", []))
            info["extraction_command"] = cmd
        except (ValueError, AttributeError) as exc:
            info["java"] = f"summary unreadable: {exc}"
    return not problems, info, problems


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit-root", type=Path, default=Path(r"D:\mscad\CICFlowMeter_AUDIT"))
    ap.add_argument("--dest", type=Path, default=Path(r"D:\mscad\CSV_REEXTRACTED"))
    ap.add_argument("--run-dir", action="append", default=[], metavar="CAPTURE=FOLDER",
                    help=r"audit folder of one capture (default <audit-root>\<capture>_java8)")
    ap.add_argument("--execute", action="store_true", help="copy the files (default: check only)")
    args = ap.parse_args(argv)

    run_dirs = {cap: args.audit_root / f"{cap}_java8" for cap in EXPECTED_FLOWS}
    for item in args.run_dir:
        cap, _, folder = item.partition("=")
        if cap not in run_dirs or not folder:
            print(f"STOP: --run-dir {item!r}: expected CAPTURE=FOLDER with CAPTURE one of {list(run_dirs)}")
            return 2
        run_dirs[cap] = Path(folder)

    protected = Path(r"D:\mscad\CSV").resolve()
    if args.dest.resolve() == protected:
        print(f"STOP: {args.dest} is the original GUI extraction folder; choose a new folder.")
        return 2

    print(f"Destination: {args.dest}   mode: {'EXECUTE (copy)' if args.execute else 'check only (nothing written)'}\n")
    results, all_ok = [], True
    for cap, run_dir in run_dirs.items():
        ok, info, problems = check_capture(cap, run_dir)
        all_ok &= ok
        results.append(info)
        flows = info.get("flows")
        print(f"{cap:<7} {'OK  ' if ok else 'FAIL'} {run_dir}")
        if flows is not None:
            print(f"        {flows:,} flows (expected {EXPECTED_FLOWS[cap]:,}), {info.get('columns')} columns, "
                  f"run1 vs run2: {info.get('run1_vs_run2')}, timestamps {info.get('timestamp_endings')}")
            print(f"        sha256 {info.get('sha256')}   java: {info.get('java', 'not recorded')}")
        for p in problems:
            print(f"        PROBLEM: {p}")

    if not all_ok:
        print("\nSTOP: at least one capture failed the checks above; nothing was copied.")
        return 1
    if not args.execute:
        print(f"\nAll six captures passed. Run again with --execute to copy them into {args.dest}.")
        return 0
    if args.dest.exists() and any(args.dest.iterdir()):
        print(f"\nSTOP: {args.dest} exists and is not empty; nothing will be overwritten.")
        return 2
    args.dest.mkdir(parents=True, exist_ok=True)
    for info in results:
        target = args.dest / Path(info["source"]).name
        shutil.copy2(info["source"], target)
        copied = sha256(target)
        if copied != info["sha256"]:
            print(f"STOP: copy of {info['capture']} has SHA-256 {copied}, source {info['sha256']}")
            return 1
        info["copied_to"] = str(target)
        print(f"copied {info['source']} -> {target} (sha256 verified)")
    stamp = datetime.now().isoformat(timespec="seconds")
    with open(args.dest / "manifest.tsv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, delimiter="\t")
        w.writerow(["capture", "file", "flows", "sha256", "source", "run1_vs_run2", "timestamp_endings", "java",
                    "stage_b_pcap_sha256"])
        for i in results:
            w.writerow([i["capture"], Path(i["copied_to"]).name, i["flows"], i["sha256"], i["source"],
                        i["run1_vs_run2"], json.dumps(i["timestamp_endings"]), " ".join(i.get("java") or []),
                        STAGE_B_SHA256[i["capture"]]])
    (args.dest / "manifest.json").write_text(json.dumps(
        {"created": stamp, "tool": "CICFlowMeter 4.0 command line (cfm.bat), Java 8; verified in Stage C",
         "flow_timeout_us": 120_000_000, "activity_timeout_us": 5_000_000, "files": results,
         "stage_b_pcap_sha256": STAGE_B_SHA256}, indent=2), encoding="utf-8")
    print(f"\nDone: 6 files, manifest.tsv and manifest.json in {args.dest}. Total flows "
          f"{sum(i['flows'] for i in results):,} (expected {sum(EXPECTED_FLOWS.values()):,}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
