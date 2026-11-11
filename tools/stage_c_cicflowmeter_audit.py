r"""STAGE C - controlled CICFlowMeter extraction validation for ONE capture (--capture is required).

Phases (stops at the first phase that cannot be completed safely):
  1. Environment audit (read-only): CICFlowMeter installation(s), JAR, hard-coded flow/activity timeouts read
     from the JAR's bytecode, launcher, jnetpcap native library, the Java that cfm.bat will use (JAVA_HOME
     first, then PATH), and the existing extraction CSV.
  2. Capture inspection (read-only): capinfos, tshark protocol hierarchy, per-packet table, malformed packets,
     packets CICFlowMeter cannot turn into flows. The PCAP must match its Stage B SHA-256.
  3. Controlled extraction: only with exactly one usable installation. Runs the installation's own cfm.bat
     twice into NEW folders <audit-dir>\run1 and \run2 (refuses if <audit-dir> is not empty).
  4. Flow-level verification: counts, timestamps, protocols, forward/backward packets, durations, packet
     accounting per bidirectional 5-tuple, and a trace of every IPv4 packet that is in no flow.
  5. Comparison (timestamps compared as times): run1 vs run2, new vs existing CSV, row order, and an analysis
     of malformed lines in the existing CSV against the new extraction.

The console shows a compact version (long lists are cut); the COMPLETE output is saved to
<audit-dir>\stage_c_report.txt, next to stage_c_summary.json.

--reuse-runs: analyse run1/run2 already extracted into <audit-dir> by an earlier run of this script, without
extracting again. Writes only stage_c_report_reanalysis.txt and stage_c_summary_reanalysis.json there
(refuses if either exists); nothing else is touched.

Nothing outside <audit-dir> is written. No configuration is changed.

Usage (plain Command Prompt, so cfm.bat uses Java 8 via JAVA_HOME):
    python tools\stage_c_cicflowmeter_audit.py --capture W-B-01 --cfm-home "C:\cicflowmeter\CICFlowMeter-4.0"
"""
import argparse
import csv
import hashlib
import io
import json
import os
import re
import shutil
import statistics
import struct
import subprocess
import sys
import time
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

IS_WINDOWS = os.name == "nt"
# Stage B verified converted captures: packet count and SHA-256 of D:\mscad\PCAP_Converted\<name>.pcap
CAPTURES = {
    "N-0":    (214,     "2129ef0734db645da144bc6afc70a4114e3aecc0f072256ef6b2ca97b50ccfee"),
    "Scan-1": (38_860,  "eef09faffc73e545a2effd4673446e2800f7477ff7b688f77632e6b7aa9b0936"),
    "App-01": (3_217,   "9bc8ebcda86282f9ffcda4138607275cb1b8b3315761e6b203a6c9a3f10e68f4"),
    "App-02": (315_670, "73eb10020bc9495d16ac932078daf4036dae6e32e25ae423e6192fc7b001e210"),
    "W-B-01": (3_104,   "ca3086118944088e9e2d44d657bc437638a724ff88981535a5820226f459dd0c"),
    "W-B-02": (648_673, "11d944a013d7632c159a1b55b71e4c44c1010154c514ea24d0fdf257ddff7dd1"),
}
TS_FORMATS = ["%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M"]
FWD_COLS = ["Tot Fwd Pkts", "Total Fwd Packet", "Total Fwd Packets", "Tot Fwd Packets"]
BWD_COLS = ["Tot Bwd Pkts", "Total Bwd packets", "Total Bwd Packets", "Tot Bwd Packets"]
PROTO_NAMES = {"0": "non-TCP/UDP (0)", "1": "ICMP", "2": "IGMP", "6": "TCP", "17": "UDP", "58": "ICMPv6"}
SEARCH_SKIP = {"windows", "$recycle.bin", "system volume information", "appdata", "programdata", "node_modules",
               ".git", "__pycache__", "anaconda3", "miniconda3", "site-packages", "winsxs"}


class Stop(Exception):
    pass


class Tee:
    """Everything printed goes to the console AND to an in-memory copy that is saved as the report file.
    detail() lines go only to the report (used for long lists)."""
    def __init__(self, stream):
        self.stream, self.buf = stream, io.StringIO()

    def write(self, s):
        self.buf.write(s)
        try:
            self.stream.write(s)
        except UnicodeEncodeError:
            self.stream.write(s.encode("ascii", "replace").decode("ascii"))

    def flush(self):
        self.stream.flush()


TEE = None
CONSOLE_LIMIT = 40     # long lists: this many lines on the console, everything in the report


def detail(line):
    """Report-only line (falls back to the console when no report is being collected)."""
    if TEE is not None:
        TEE.buf.write(line + "\n")
    else:
        print(line)


def listing(lines, limit=CONSOLE_LIMIT, what="lines"):
    """Print the first `limit` lines on the console; all lines go to the report."""
    for i, line in enumerate(lines):
        (print if i < limit else detail)(line)
    if len(lines) > limit:
        print(f"    ... {len(lines) - limit:,} more {what} (complete list in the report file)")


TCP_FLAG_BITS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"),
                 (0x40, "ECE"), (0x80, "CWR")]


def flag_names(hexflags):
    try:
        v = int(hexflags, 16)
    except (TypeError, ValueError):
        return hexflags or "-"
    return "/".join(n for b, n in TCP_FLAG_BITS if v & b) or "none"


def section(title):
    print("\n" + "=" * 100 + f"\n{title}\n" + "=" * 100)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, cwd=None, timeout=1800):
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or "", time.time() - t0
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, "", f"{type(exc).__name__}: {exc}", time.time() - t0


def find_tool(name, explicit=None):
    if explicit:
        return Path(explicit)
    for c in (shutil.which(name), rf"C:\Program Files\Wireshark\{name}.exe"):
        if c and Path(c).is_file():
            return Path(c)
    return None


# ---------------------------------------------------------------------------------------------------------------
# Phase 1 helpers
# ---------------------------------------------------------------------------------------------------------------

def search_installations(roots, max_depth):
    """Directories that look like a Java CICFlowMeter distribution (bin/cfm[.bat] + lib/*.jar)."""
    found = set()
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            continue
        base_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            d = Path(dirpath)
            dirnames[:] = [x for x in dirnames if x.lower() not in SEARCH_SKIP]
            if len(d.parts) - base_depth >= max_depth:
                dirnames[:] = []
            names = {f.lower() for f in filenames}
            if d.name.lower() == "bin" and ("cfm.bat" in names or "cfm" in names):
                home = d.parent
                if (home / "lib").is_dir() and any(j.suffix == ".jar" for j in (home / "lib").iterdir()):
                    found.add(home.resolve())
    return sorted(found)


def class_long_constants(data):
    """Return the CONSTANT_Long values of a .class file's constant pool."""
    if data[:4] != b"\xca\xfe\xba\xbe":
        return []
    count = struct.unpack(">H", data[8:10])[0]
    pos, i, longs = 10, 1, []
    sizes = {1: None, 3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4,
             19: 2, 20: 2}
    while i < count and pos < len(data):
        tag = data[pos]
        pos += 1
        if tag == 1:
            ln = struct.unpack(">H", data[pos:pos + 2])[0]
            pos += 2 + ln
        elif tag in sizes:
            if tag == 5:
                longs.append(struct.unpack(">q", data[pos:pos + 8])[0])
            pos += sizes[tag]
            if tag in (5, 6):
                i += 1
        else:
            break
        i += 1
    return longs


def inspect_installation(home):
    info = {"home": str(home), "jars": [], "cicflowmeter_jars": [], "launchers": [], "native_libs": [],
            "timeouts": {}, "manifest": {}}
    lib = home / "lib"
    info["jars"] = sorted(j.name for j in lib.glob("*.jar"))
    info["cicflowmeter_jars"] = [j for j in info["jars"] if "cicflowmeter" in j.lower()]
    info["launchers"] = sorted(p.name for p in (home / "bin").iterdir() if p.is_file())
    for p in home.rglob("*"):
        if p.is_file() and p.suffix.lower() in (".dll", ".so", ".dylib") and "pcap" in p.name.lower():
            info["native_libs"].append(str(p.relative_to(home)))
    for jar in info["cicflowmeter_jars"]:
        try:
            with zipfile.ZipFile(lib / jar) as z:
                names = z.namelist()
                if "META-INF/MANIFEST.MF" in names:
                    for line in z.read("META-INF/MANIFEST.MF").decode("utf-8", "replace").splitlines():
                        if ":" in line:
                            k, v = line.split(":", 1)
                            info["manifest"][k.strip()] = v.strip()
                for cls in ("cic/cs/unb/ca/ifm/Cmd.class", "cic/cs/unb/ca/ifm/ui/flow/FlowOfflinePane.class"):
                    if cls in names:
                        longs = class_long_constants(z.read(cls))
                        info["timeouts"][cls] = {
                            "flow_timeout_us_candidates": [v for v in longs if v in (120_000_000, 600_000_000)] or longs,
                            "activity_timeout_us_candidates": [v for v in longs if v in (5_000_000,)] or longs,
                            "all_long_constants": longs}
        except (zipfile.BadZipFile, OSError) as exc:
            info["manifest"]["error"] = str(exc)
    bat = home / "bin" / ("cfm.bat" if IS_WINDOWS else "cfm")
    if bat.is_file():
        text = bat.read_text(encoding="utf-8", errors="replace")
        m = re.search(r'DEFAULT_JVM_OPTS=(.*)', text)
        info["launcher_jvm_opts"] = m.group(1).strip() if m else ""
        m = re.search(r'-classpath\s+"?%?CLASSPATH%?"?\s+(\S+)', text) or re.search(r'(cic\.cs\.unb\.ca\.\S+)', text)
        info["launcher_main_class"] = m.group(1).strip('"') if m else ""
    return info


def java_info(explicit=None):
    """The Java cfm.bat will run: JAVA_HOME/bin/java if JAVA_HOME is set, otherwise java on PATH."""
    if explicit:
        java, source = Path(explicit), "--java"
    elif os.environ.get("JAVA_HOME"):
        java = Path(os.environ["JAVA_HOME"]) / "bin" / ("java.exe" if IS_WINDOWS else "java")
        source = f"JAVA_HOME={os.environ['JAVA_HOME']}"
    elif shutil.which("java"):
        java, source = Path(shutil.which("java")), "PATH"
    else:
        return None, "java not found (no JAVA_HOME, not on PATH)"
    if not java.is_file():
        return None, f"{java} does not exist ({source})"
    code, out, err, _ = run([str(java), "-version"])
    return java, f"(selected via {source})\n" + (err or out).strip()


# ---------------------------------------------------------------------------------------------------------------
# Phase 2 helpers
# ---------------------------------------------------------------------------------------------------------------

TSHARK_FIELDS = ["frame.number", "frame.time_epoch", "frame.len", "frame.protocols", "eth.type", "ip.src", "ip.dst",
                 "ip.proto", "ipv6.src", "ipv6.dst", "ipv6.nxt", "tcp.srcport", "tcp.dstport", "tcp.flags",
                 "udp.srcport", "udp.dstport", "_ws.malformed", "_ws.expert.severity"]


def packet_table(tshark, pcap):
    cmd = [str(tshark), "-r", str(pcap), "-n", "-T", "fields", "-E", "header=y", "-E", "separator=\t",
           "-E", "occurrence=f"] + sum((["-e", f] for f in TSHARK_FIELDS), [])
    code, out, err, _ = run(cmd)
    if code != 0:
        raise Stop(f"tshark failed (exit {code}): {err.strip()[:500]}")
    rows = list(csv.DictReader(io.StringIO(out), delimiter="\t"))
    for r in rows:
        r["ts"] = float(r["frame.time_epoch"])
        if r["ip.src"]:
            r["l3"], r["src"], r["dst"], r["proto"] = "IPv4", r["ip.src"], r["ip.dst"], r["ip.proto"]
        elif r["ipv6.src"]:
            r["l3"], r["src"], r["dst"], r["proto"] = "IPv6", r["ipv6.src"], r["ipv6.dst"], r["ipv6.nxt"]
        else:
            stack = [x for x in r["frame.protocols"].split(":") if x not in ("eth", "ethertype", "vlan")]
            r["l3"], r["src"], r["dst"], r["proto"] = (stack[0].upper() if stack else "?"), "", "", ""
        r["sport"] = r["tcp.srcport"] or r["udp.srcport"] or "0"
        r["dport"] = r["tcp.dstport"] or r["udp.dstport"] or "0"
        r["l4"] = "TCP" if r["tcp.srcport"] else "UDP" if r["udp.srcport"] else PROTO_NAMES.get(r["proto"], r["proto"] or "-")
        r["malformed"] = bool(r["_ws.malformed"]) or "malformed" in r["frame.protocols"]
    return rows, " ".join(cmd)


def flow_key(proto, a, ap, b, bp):
    """Bidirectional 5-tuple key in CICFlowMeter's convention: protocols other than TCP (6) and UDP (17)
    are written by CICFlowMeter as protocol 0 with ports 0, so both packets and flows are keyed that way."""
    proto = str(proto)
    if proto not in ("6", "17"):
        proto, ap, bp = "0", "0", "0"
    ends = sorted([(a, str(ap)), (b, str(bp))])
    return (str(proto), ends[0], ends[1])


# ---------------------------------------------------------------------------------------------------------------
# Flow CSV helpers
# ---------------------------------------------------------------------------------------------------------------

def read_flow_csv(path):
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.reader(fh)
        header = [h.strip() for h in next(reader)]
        rows = [r for r in reader if r]
    malformed = [i + 2 for i, r in enumerate(rows) if len(r) != len(header)]
    recs = [dict(zip(header, (v.strip() for v in r))) for r in rows]
    return header, recs, malformed


def pick(header, candidates):
    return next((c for c in candidates if c in header), None)


def parse_ts(text):
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(text.strip(), fmt)
        except ValueError:
            continue
    return None


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def summarize_flows(name, header, recs, malformed):
    fwd, bwd = pick(header, FWD_COLS), pick(header, BWD_COLS)
    ts = [parse_ts(r.get("Timestamp", "")) for r in recs]
    durations = [num(r.get("Flow Duration")) for r in recs]
    durations = [d for d in durations if d is not None]
    s = {
        "name": name, "records": len(recs), "columns": len(header), "malformed_lines": malformed,
        "fwd_col": fwd, "bwd_col": bwd,
        "fwd_packets": int(sum(num(r.get(fwd)) or 0 for r in recs)) if fwd else None,
        "bwd_packets": int(sum(num(r.get(bwd)) or 0 for r in recs)) if bwd else None,
        "protocols": dict(Counter(PROTO_NAMES.get(r.get("Protocol", ""), r.get("Protocol", "")) for r in recs)),
        "first_ts": str(min(t for t in ts if t)) if any(ts) else "", "last_ts": str(max(t for t in ts if t)) if any(ts) else "",
        "unparseable_ts": sum(1 for t in ts if t is None),
        "labels": dict(Counter(r.get("Label", "") for r in recs)),
    }
    if durations:
        s["duration_us"] = {"min": min(durations), "median": statistics.median(durations), "max": max(durations),
                            "zero": sum(1 for d in durations if d == 0),
                            ">= 120 s": sum(1 for d in durations if d >= 120_000_000)}
    s["total_packets"] = (s["fwd_packets"] or 0) + (s["bwd_packets"] or 0)
    return s


def print_summary(s):
    print(f"  {s['name']}: {s['records']} flow records, {s['columns']} columns"
          + (f", MALFORMED lines {s['malformed_lines']}" if s["malformed_lines"] else ""))
    print(f"    first/last Timestamp (as written, local time): {s['first_ts']}  ->  {s['last_ts']}"
          f"   (unparseable: {s['unparseable_ts']})")
    print(f"    protocols: {s['protocols']}")
    print(f"    {s['fwd_col']}: {s['fwd_packets']}   {s['bwd_col']}: {s['bwd_packets']}   total packets in flows: "
          f"{s['total_packets']}")
    if "duration_us" in s:
        d = s["duration_us"]
        print(f"    Flow Duration (us): min {d['min']:,.0f}, median {d['median']:,.0f}, max {d['max']:,.0f}, "
              f"zero-duration flows {d['zero']}, flows >= 120 s: {d['>= 120 s']}")
    print(f"    Label values: {s['labels']}")


def packet_accounting(packets, header, recs):
    fwd, bwd = pick(header, FWD_COLS), pick(header, BWD_COLS)
    cap = Counter()
    by_key_l4 = {}
    for p in packets:
        if p["src"]:
            k = flow_key(p["proto"], p["src"], p["sport"], p["dst"], p["dport"])
            cap[k] += 1
            by_key_l4[k] = p["l4"]
    flows = Counter()
    for r in recs:
        k = flow_key(r.get("Protocol", ""), r.get("Src IP", ""), r.get("Src Port", ""), r.get("Dst IP", ""), r.get("Dst Port", ""))
        flows[k] += int((num(r.get(fwd)) or 0) + (num(r.get(bwd)) or 0))
    rows = []
    for k in sorted(set(cap) | set(flows), key=lambda x: (-cap.get(x, 0), x)):
        rows.append({"key": k, "l4": by_key_l4.get(k, PROTO_NAMES.get(k[0], k[0])), "capture_packets": cap.get(k, 0),
                     "flow_packets": flows.get(k, 0), "difference": cap.get(k, 0) - flows.get(k, 0)})
    non_ip = [p for p in packets if not p["src"]]
    return rows, non_ip


def compare_flow_sets(name_a, a_header, a_recs, name_b, b_header, b_recs):
    out = {"a": name_a, "b": name_b, "records": (len(a_recs), len(b_recs))}
    out["columns_only_in_a"] = [c for c in a_header if c not in b_header]
    out["columns_only_in_b"] = [c for c in b_header if c not in a_header]
    out["same_column_order"] = a_header == b_header
    ident = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp"]

    def keyed(recs):
        seen, res = Counter(), {}
        for r in recs:
            base = tuple(r.get(c, "") for c in ident[:-1]) + (parse_ts(r.get("Timestamp", "")) or r.get("Timestamp", ""),)
            res[base + (seen[base],)] = r
            seen[base] += 1
        return res

    ka, kb = keyed(a_recs), keyed(b_recs)
    common = [k for k in ka if k in kb]
    out["matched_by_identifiers"] = len(common)
    out["only_in_a"] = [k[:-1] for k in ka if k not in kb]
    out["only_in_b"] = [k[:-1] for k in kb if k not in ka]
    shared_cols = [c for c in a_header if c in b_header and c not in ident and c != "Label"]
    identical, diffs = 0, []
    col_diff_count = Counter()
    for k in common:
        ra, rb = ka[k], kb[k]
        bad = []
        for c in shared_cols:
            va, vb = ra.get(c, ""), rb.get(c, "")
            if va == vb:
                continue
            na, nb = num(va), num(vb)
            if na is not None and nb is not None and (na == nb or (na != na and nb != nb)):
                continue
            bad.append((c, va, vb))
            col_diff_count[c] += 1
        if bad:
            diffs.append((k[:-1], bad))
        else:
            identical += 1
    out["identical_feature_values"] = identical
    out["rows_with_feature_differences"] = diffs
    out["columns_with_differences"] = dict(col_diff_count.most_common())
    out["label_values"] = (dict(Counter(r.get("Label", "") for r in a_recs)), dict(Counter(r.get("Label", "") for r in b_recs)))
    out["timestamp_text_differences"] = sum(1 for k in common if ka[k].get("Timestamp") != kb[k].get("Timestamp"))
    order_a = [k for k in ka if k in kb]
    out["same_row_order"] = order_a == [k for k in kb if k in ka]
    return out


def print_comparison(c, limit=15):
    print(f"  {c['a']} vs {c['b']}: records {c['records'][0]} vs {c['records'][1]}")
    print(f"    same column order: {c['same_column_order']}; only in {c['a']}: {c['columns_only_in_a'] or 'none'}; "
          f"only in {c['b']}: {c['columns_only_in_b'] or 'none'}")
    print(f"    matched by (Flow ID, Src/Dst IP, ports, Protocol, Timestamp as a time): {c['matched_by_identifiers']}; "
          f"identical feature values: {c['identical_feature_values']}; "
          f"matched with feature differences: {len(c['rows_with_feature_differences'])}")
    print(f"    only in {c['a']}: {len(c['only_in_a'])}; only in {c['b']}: {len(c['only_in_b'])}")
    for label, items in ((c["a"], c["only_in_a"]), (c["b"], c["only_in_b"])):
        for k in items[:limit]:
            print(f"      only in {label}: {k}")
    for k, bad in c["rows_with_feature_differences"][:limit]:
        print(f"      differs: {k}: " + "; ".join(f"{col}: {va!r} vs {vb!r}" for col, va, vb in bad[:6])
              + (" ..." if len(bad) > 6 else ""))
    if c["columns_with_differences"]:
        print(f"    columns that differ (rows): {c['columns_with_differences']}")
    print(f"    Label values: {c['a']} {c['label_values'][0]} | {c['b']} {c['label_values'][1]}")
    print(f"    matched rows whose Timestamp TEXT differs (e.g. am/AM): {c['timestamp_text_differences']}; "
          f"same row order: {c['same_row_order']}")


def trace_unaccounted(packets, header, recs, limit_per_conv=10):
    """For each conversation whose packets are not all in flows: assign each flow to the run of packets it
    covers (same 5-tuple, same start second in local time, same first-packet direction, packet count and
    exact microsecond duration) and list the packets covered by no flow."""
    fwd, bwd = pick(header, FWD_COLS), pick(header, BWD_COLS)
    by_conv = defaultdict(list)
    for p in packets:
        if p["src"] and p["l3"] == "IPv4":
            by_conv[flow_key(p["proto"], p["src"], p["sport"], p["dst"], p["dport"])].append(p)
    flows = defaultdict(list)
    for r in recs:
        if len(r) != len(header):
            continue
        flows[flow_key(r.get("Protocol", ""), r.get("Src IP", ""), r.get("Src Port", ""), r.get("Dst IP", ""),
                       r.get("Dst Port", ""))].append(r)
    total_left, unconfirmed, shown = 0, 0, 0
    unconf_pk, unconf_claimed = 0, 0
    kinds, conv_sizes, unconfirmed_list = Counter(), Counter(), []
    out = print
    for k, plist in sorted(by_conv.items(), key=lambda kv: -len(kv[1])):
        fl = sorted(flows.get(k, []), key=lambda r: (parse_ts(r["Timestamp"]) or datetime.min, num(r["Flow Duration"]) or 0))
        n_in = sum(int((num(r.get(fwd)) or 0) + (num(r.get(bwd)) or 0)) for r in fl)
        if n_in == len(plist):
            continue
        name = PROTO_NAMES.get(k[0], k[0])
        out = print if shown < 15 else detail
        shown += 1
        out(f"\n    {name} {k[1][0]}:{k[1][1]} <-> {k[2][0]}:{k[2][1]}: {len(plist)} packets in the capture, "
            f"{n_in} in {len(fl)} flow(s)")
        used, ok, placed, failed = set(), True, [], []
        # Flows are contiguous runs of the conversation's packets, and several can start in the same second (e.g. a
        # connection and its FIN tail). Longer flows are placed first (a long exact run is unambiguous), each on the
        # first run of not-yet-assigned packets with the same start second, first sender and exact duration.
        for r in sorted(fl, key=lambda r: -int((num(r.get(fwd)) or 0) + (num(r.get(bwd)) or 0))):
            n = int((num(r.get(fwd)) or 0) + (num(r.get(bwd)) or 0))
            start, dur = parse_ts(r["Timestamp"]), int(num(r["Flow Duration"]) or 0)
            found = None
            for i in range(0, len(plist) - n + 1):
                seg = plist[i:i + n]
                if any(p["frame.number"] in used for p in seg):
                    continue
                if (datetime.fromtimestamp(seg[0]["ts"]).replace(microsecond=0) == start
                        and (seg[0]["src"], seg[0]["sport"]) == (r["Src IP"], r["Src Port"])
                        and round((seg[-1]["ts"] - seg[0]["ts"]) * 1e6) == dur):
                    found = i
                    break
            if found is None:
                ok = False
                failed.append(f"      flow {r['Timestamp']} ({n} packets, {dur} us): could NOT be matched to a packet run")
                continue
            seg = plist[found:found + n]
            used.update(p["frame.number"] for p in seg)
            placed.append((found, f"      flow {r['Timestamp']}: frames {seg[0]['frame.number']}..{seg[-1]['frame.number']} "
                                  f"({n} packets, duration {dur} us exact); first flags {seg[0]['tcp.flags'] or '-'}, "
                                  f"last flags {seg[-1]['tcp.flags'] or '-'}"))
        for _, line in sorted(placed):
            out(line)
        for line in failed:
            out(line)
        left = [p for p in plist if p["frame.number"] not in used]
        if ok:
            total_left += len(left)
        else:
            # flows exist that could not be pinned to exact packet runs: only the shortfall (capture packets minus
            # packets the flows claim) is counted as "in no flow"; which packets those are is not determined
            total_left += max(0, len(plist) - n_in)
            unconf_pk += len(plist)
            unconf_claimed += n_in
        unconfirmed += 0 if ok else 1
        if not ok:
            unconfirmed_list.append(f"    {name} {k[1][0]}:{k[1][1]} <-> {k[2][0]}:{k[2][1]}: {len(plist)} packets, "
                                    f"{len(fl)} flow(s) claiming {n_in} packets")
        conv_sizes[("flows not matched exactly" if not ok else "no packet in a flow" if not used else "some packets in flows", len(plist) if len(plist) <= 3 else ">3")] += 1
        for p in (left if ok else []):
            kinds[f"{name} " + (f"flags {p['tcp.flags']} ({flag_names(p['tcp.flags'])})" if p["tcp.flags"] else "packet")] += 1
        if not ok:
            out(f"      (flows not matched exactly; {max(0, len(plist) - n_in)} packet(s) of this conversation are in no flow, "
                f"which ones is not determined; unmatched packets listed below for inspection)")
        for p in left[:limit_per_conv]:
            out(f"      {'NOT IN ANY FLOW' if ok else 'not pinned to a flow'}: frame {p['frame.number']} at {datetime.fromtimestamp(p['ts'])} "
                  f"{p['src']}:{p['sport']} -> {p['dst']}:{p['dport']} {('tcp flags ' + p['tcp.flags']) if p['tcp.flags'] else 'udp/other'} "
                  f"({p['frame.len']} bytes)")
        if len(left) > limit_per_conv:
            out(f"      ... {len(left) - limit_per_conv} more")
    if shown > 15:
        print(f"\n    ... {shown - 15:,} more conversations traced (complete trace in the report file)")
    print(f"\n    IPv4 packets in no flow: {total_left}")
    if unconfirmed:
        print(f"    of which {total_left - sum(kinds.values())} come from {unconfirmed} conversation(s) whose flows could not be "
              f"matched exactly to packet runs ({unconf_pk} packets, {unconf_claimed} claimed by their flows)")
    if kinds:
        print("    packets in no flow, by kind (exactly matched conversations):")
        for kind, n in kinds.most_common():
            print(f"      {n:>9,}  {kind}")
        print("    conversations with packets in no flow (packets in the conversation):")
        for (state, size), n in sorted(conv_sizes.items(), key=lambda kv: (kv[0][0], str(kv[0][1]))):
            print(f"      {n:>9,}  {state}, {size} packet(s)")
    if unconfirmed_list:
        print("    conversations whose flows could not be matched exactly to packets:")
        listing(unconfirmed_list, limit=20, what="conversations")
    return total_left


def malformed_line_analysis(old_path, new):
    """Explain lines of the existing CSV whose field count differs from its header, using the new extraction."""
    with open(old_path, "r", encoding="utf-8-sig", newline="") as fh:
        raw_lines = fh.read().splitlines()
    rows = list(csv.reader(io.StringIO("\n".join(raw_lines))))
    header = [h.strip() for h in rows[0]]
    bad = [(i + 1, r) for i, r in enumerate(rows) if i and r and len(r) != len(header)]
    print(f"  Existing CSV lines whose field count differs from the header ({len(header)}): {len(bad)}")
    if new is not None:
        print(f"  New extraction lines with a wrong field count: {len(new[2])}"
              + (f" (lines {new[2]})" if new[2] else " - CICFlowMeter wrote every line complete"))
    for line_no, r in bad:
        print(f"\n  line {line_no}: {len(r)} fields")
        print(f"    previous line ends:  ...{raw_lines[line_no - 2][-70:]}")
        print(f"    this line starts:    {raw_lines[line_no - 1][:110]}...")
        if new is None or len(r) != len(header) - 1:
            continue
        shifted = dict(zip(header, [""] + [v.strip() for v in r]))
        t = parse_ts(shifted.get("Timestamp", ""))
        cands = [x for x in new[1] if x.get("Src Port") == shifted.get("Src Port") and x.get("Dst IP") == shifted.get("Dst IP")
                 and x.get("Dst Port") == shifted.get("Dst Port") and x.get("Protocol") == shifted.get("Protocol")
                 and parse_ts(x.get("Timestamp", "")) == t]
        if len(cands) != 1:
            print(f"    shifted one column right it would be Src Port {shifted.get('Src Port')}, Dst {shifted.get('Dst IP')}:"
                  f"{shifted.get('Dst Port')}, protocol {shifted.get('Protocol')}, {shifted.get('Timestamp')}; matching new rows: {len(cands)}")
            continue
        x = cands[0]
        feats = [c for c in header[7:] if c != "Label"]
        same = sum(1 for c in feats if shifted.get(c) == x.get(c) or (num(shifted.get(c)) is not None and num(shifted.get(c)) == num(x.get(c))))
        print(f"    the new extraction has this flow complete: Flow ID {x.get('Flow ID')}, Src IP {x.get('Src IP')}")
        print(f"    existing line shifted back one column: Src IP as found {shifted.get('Src IP')!r}; "
              f"{same} of {len(feats)} feature values identical to the new row; Label in new row {x.get('Label')!r}")
    return len(bad)


# ---------------------------------------------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", required=True, choices=sorted(CAPTURES))
    ap.add_argument("--pcap", type=Path, default=None, help=r"default D:\mscad\PCAP_Converted\<capture>.pcap")
    ap.add_argument("--old-csv", type=Path, default=None, help=r"default D:\mscad\CSV\<capture>.pcap_Flow.csv")
    ap.add_argument("--audit-dir", type=Path, default=None, help=r"default D:\mscad\CICFlowMeter_AUDIT\<capture>")
    ap.add_argument("--cfm-home", type=Path, default=None, help="CICFlowMeter folder (contains bin\\ and lib\\)")
    ap.add_argument("--search-root", type=Path, action="append", default=None)
    ap.add_argument("--java", default=None)
    ap.add_argument("--tshark", default=None)
    ap.add_argument("--capinfos", default=None)
    ap.add_argument("--audit-only", action="store_true")
    ap.add_argument("--reuse-runs", action="store_true",
                    help="analyse run1/run2 already in --audit-dir instead of extracting again")
    ap.add_argument("--expected-sha256", default=None, help="override the Stage B SHA-256 ('' to skip; testing only)")
    args = ap.parse_args(argv)
    global TEE
    TEE = Tee(sys.stdout)
    sys.stdout = TEE
    try:
        return _main(args)
    finally:
        sys.stdout = TEE.stream


def _main(args):
    cap = args.capture
    args.pcap = args.pcap or Path(rf"D:\mscad\PCAP_Converted\{cap}.pcap")
    args.old_csv = args.old_csv or Path(rf"D:\mscad\CSV\{cap}.pcap_Flow.csv")
    args.audit_dir = args.audit_dir or Path(rf"D:\mscad\CICFlowMeter_AUDIT\{cap}")
    if args.expected_sha256 is None:
        args.expected_sha256 = CAPTURES[cap][1]
    print(f"Capture: {cap} | PCAP {args.pcap} | existing CSV {args.old_csv} | audit folder {args.audit_dir}")
    summary = {"phase_reached": 0}
    args.suffix = "_reanalysis" if args.reuse_runs else ""

    # ======================= Phase 1 =======================
    section("PHASE 1 - Environment audit (read-only)")
    if args.cfm_home:
        installs = [args.cfm_home.resolve()]
    else:
        home = Path.home()
        roots = args.search_root or [Path(r"D:\mscad"), Path("D:\\"), home / "Downloads", home / "Desktop",
                                     home / "Documents", home, Path("C:\\")]
        print("  Searching for Java CICFlowMeter installations (bin\\cfm + lib\\*.jar) under: "
              + ", ".join(str(r) for r in roots))
        installs = search_installations(roots, max_depth=5)
    py_cfm = None
    try:
        from importlib.metadata import version
        py_cfm = version("cicflowmeter")
    except Exception:
        pass
    print(f"  Python 'cicflowmeter' package: {py_cfm or 'not installed'}; 'cicflowmeter' on PATH: "
          f"{shutil.which('cicflowmeter') or 'no'}")
    inst_infos = []
    for h in installs:
        info = inspect_installation(h)
        inst_infos.append(info)
        print(f"\n  CICFlowMeter installation: {info['home']}")
        print(f"    CICFlowMeter JAR(s): {info['cicflowmeter_jars'] or 'NONE'}   (lib\\ has {len(info['jars'])} jars)")
        print(f"    MANIFEST: {info['manifest'] or '-'}")
        print(f"    bin\\: {info['launchers']}   main class in launcher: {info.get('launcher_main_class', '-')}")
        print(f"    launcher JVM options: {info.get('launcher_jvm_opts', '-')}")
        print(f"    native pcap libraries: {info['native_libs'] or 'NONE FOUND'}")
        for cls, t in info["timeouts"].items():
            print(f"    long constants in {cls}: {t['all_long_constants']}")
    summary["installations"] = inst_infos
    java, jver = java_info(args.java)
    print(f"\n  Java: {java or 'NOT FOUND'}\n    {jver.replace(chr(10), chr(10) + '    ')}")
    summary["java"] = {"path": str(java) if java else None, "version": jver}

    if not args.old_csv.is_file():
        print(f"\n  Existing extraction NOT FOUND at {args.old_csv}")
        old = None
    else:
        st = args.old_csv.stat()
        old_header, old_recs, old_bad = read_flow_csv(args.old_csv)
        old = (old_header, old_recs, old_bad)
        print(f"\n  Existing extraction: {args.old_csv}\n    {st.st_size:,} bytes, modified "
              f"{datetime.fromtimestamp(st.st_mtime)}, sha256 {sha256(args.old_csv)}")
        print(f"    {len(old_recs)} records, {len(old_header)} columns; first columns {old_header[:8]}")
        print(f"    previous command/configuration: not recorded in the file; the header style "
              f"({'Java CICFlowMeter 4.0 style' if 'Tot Fwd Pkts' in old_header else 'other'}) and the file name "
              f"'<pcap>_Flow.csv' are the only clues")
    summary["old_csv"] = str(args.old_csv)

    # ======================= Phase 2 =======================
    section("PHASE 2 - Capture inspection (read-only)")
    if not args.pcap.is_file():
        print(f"STOP: {args.pcap} not found")
        return 2
    pcap_sha_before = sha256(args.pcap)
    print(f"  {args.pcap}: {args.pcap.stat().st_size:,} bytes, sha256 {pcap_sha_before}")
    if args.expected_sha256 and pcap_sha_before != args.expected_sha256:
        print(f"STOP: {args.pcap.name} does not match its Stage B SHA-256")
        return 2
    tshark, capinfos = find_tool("tshark", args.tshark), find_tool("capinfos", args.capinfos)
    if tshark is None:
        print("STOP: tshark not found (needed for the packet inspection and accounting)")
        return 2
    print(f"  tshark: {tshark} ({run([str(tshark), '-v'])[1].splitlines()[0]})")
    if capinfos:
        code, out, err, _ = run([str(capinfos), "-M", str(args.pcap)])
        print("  capinfos -M:\n" + "\n".join("    " + l for l in out.splitlines() if l.split(":")[0].strip() in (
            "File type", "File encapsulation", "File timestamp precision", "Number of packets", "Capture duration",
            "Earliest packet time", "Latest packet time", "Packet size limit")))
    packets, tshark_cmd = packet_table(tshark, args.pcap)
    first = datetime.fromtimestamp(min(p["ts"] for p in packets), tz=timezone.utc)
    last = datetime.fromtimestamp(max(p["ts"] for p in packets), tz=timezone.utc)
    print(f"  packets: {len(packets)} (Stage B: {CAPTURES[args.capture][0]})   first {first:%Y-%m-%d %H:%M:%S.%f} UTC   "
          f"last {last:%Y-%m-%d %H:%M:%S.%f} UTC")
    print(f"  local time of first/last packet on this PC: {datetime.fromtimestamp(min(p['ts'] for p in packets))} / "
          f"{datetime.fromtimestamp(max(p['ts'] for p in packets))}")
    print(f"  network layer: {dict(Counter(p['l3'] for p in packets))}")
    print(f"  transport/protocol: {dict(Counter((p['l3'], p['l4']) for p in packets))}")
    print(f"  malformed packets (tshark): {sum(p['malformed'] for p in packets)}")
    code, phs, _, _ = run([str(tshark), "-r", str(args.pcap), "-n", "-q", "-z", "io,phs"])
    print("  protocol hierarchy (tshark -z io,phs):\n" + "\n".join("    " + l for l in phs.splitlines() if l.strip()))
    conv = Counter()
    for p in packets:
        if p["src"]:
            conv[(p["l3"], p["l4"]) + flow_key(p["proto"], p["src"], p["sport"], p["dst"], p["dport"])[1:]] += 1
    print(f"  bidirectional 5-tuples (protocol, endpoint A, endpoint B): {len(conv)}")
    listing([f"    {k[0]}/{k[1]:<6} {k[2][0]}:{k[2][1]}  <->  {k[3][0]}:{k[3][1]}   {n} packets"
             for k, n in conv.most_common()], what="5-tuples")
    non_ip = [p for p in packets if not p["src"]]
    print(f"  non-IP packets (no IPv4/IPv6 header, cannot form CICFlowMeter flows): {len(non_ip)} "
          f"{dict(Counter(p['frame.protocols'] for p in non_ip))}")
    summary["capture"] = {"packets": len(packets), "l3": dict(Counter(p["l3"] for p in packets)),
                          "l4": dict(Counter(f"{p['l3']}/{p['l4']}" for p in packets)), "five_tuples": len(conv),
                          "non_ip": len(non_ip), "tshark_command": tshark_cmd}
    summary["phase_reached"] = 2

    # ======================= Phase 3 =======================
    section("PHASE 3 - Controlled extraction")
    usable = [i for i in inst_infos if i["cicflowmeter_jars"] and i["native_libs"]
              and (Path(i["home"]) / "bin" / ("cfm.bat" if IS_WINDOWS else "cfm")).is_file()]
    if args.audit_only:
        print("  --audit-only: extraction not run.")
        return finish(args, summary, old, None, None, packets)
    if len(usable) != 1:
        print(f"STOP: {len(usable)} usable Java CICFlowMeter installation(s) found "
              f"({[i['home'] for i in usable] or 'none'}). Pass --cfm-home to choose one, or install/locate "
              "CICFlowMeter first (nothing was extracted).")
        return finish(args, summary, old, None, None, packets, code=2)
    if java is None:
        print("STOP: Java not found; CICFlowMeter cannot run (nothing was extracted).")
        return finish(args, summary, old, None, None, packets, code=2)
    if args.reuse_runs:
        csvs = {n: sorted((args.audit_dir / n).glob("*.csv")) for n in ("run1", "run2")}
        targets = [args.audit_dir / "stage_c_report_reanalysis.txt", args.audit_dir / "stage_c_summary_reanalysis.json"]
        if not all(len(v) == 1 for v in csvs.values()):
            print(f"STOP: --reuse-runs needs exactly one CSV in each of {args.audit_dir}\\run1 and \\run2 "
                  f"(found {[len(v) for v in csvs.values()]}).")
            return finish(args, summary, old, None, None, packets, code=2)
        if any(t.exists() for t in targets):
            print(f"STOP: {[str(t) for t in targets if t.exists()]} already exists; nothing will be overwritten.")
            return finish(args, summary, old, None, None, packets, code=2)
        runs = []
        for n in ("run1", "run2"):
            console = args.audit_dir / n / "cicflowmeter_console.txt"
            text = console.read_text(encoding="utf-8", errors="replace") if console.is_file() else ""
            stats = [l.strip() for l in text.splitlines() if "total" in l and "flows" in l or l.strip().startswith("Packet stats")]
            print(f"  [{n}] reusing {csvs[n][0]} (extracted earlier; not re-run)")
            print("    " + ("\n    ".join(stats) if stats else "(no CICFlowMeter console summary found)"))
            runs.append({"name": n, "csv": csvs[n][0], "reused": True, "console_summary": stats})
        summary["extraction"] = {"reused_existing_runs": True, "runs": [{k: str(v) for k, v in r.items()} for r in runs]}
        summary["phase_reached"] = 3
        return finish(args, summary, old, read_flow_csv(runs[0]["csv"]), read_flow_csv(runs[1]["csv"]), packets, runs=runs)
    inst = usable[0]
    launcher = Path(inst["home"]) / "bin" / ("cfm.bat" if IS_WINDOWS else "cfm")
    if args.audit_dir.exists() and any(args.audit_dir.iterdir()):
        print(f"STOP: {args.audit_dir} already exists and is not empty; nothing will be overwritten.")
        if all(len(list((args.audit_dir / n).glob("*.csv"))) == 1 for n in ("run1", "run2")):
            print("      It already holds run1 and run2 from an earlier extraction: add --reuse-runs to analyse them "
                  "without extracting again.")
        return finish(args, summary, old, None, None, packets, code=2)
    runs = []
    for run_name in ("run1", "run2"):
        out_dir = args.audit_dir / run_name
        out_dir.mkdir(parents=True, exist_ok=False)
        # launched by its plain name from its own bin folder (the launcher resolves lib\ relative to bin\)
        cmd = (["cmd", "/c", launcher.name] if IS_WINDOWS else [str(launcher)]) + [str(args.pcap), str(out_dir) + os.sep]
        print(f"\n  [{run_name}] working directory: {launcher.parent}\n  [{run_name}] command: {' '.join(cmd)}")
        started = datetime.now()
        code, out, err, secs = run(cmd, cwd=str(launcher.parent))
        console = f"command: {' '.join(cmd)}\ncwd: {launcher.parent}\nstarted: {started.isoformat()}\n" \
                  f"seconds: {secs:.2f}\nexit code: {code}\n--- stdout ---\n{out}\n--- stderr ---\n{err}\n"
        (out_dir / "cicflowmeter_console.txt").write_text(console, encoding="utf-8")
        print(f"  [{run_name}] exit code {code}, {secs:.1f} s; console output saved to {out_dir / 'cicflowmeter_console.txt'}")
        print("    " + "\n    ".join((out + err).strip().splitlines()[-15:]))
        csvs = sorted(out_dir.glob("*.csv"))
        if code != 0 or not csvs:
            print(f"STOP: CICFlowMeter did not produce a CSV in {out_dir} (exit code {code}).")
            return finish(args, summary, old, None, None, packets, code=1)
        runs.append({"name": run_name, "csv": csvs[0], "command": " ".join(cmd), "seconds": secs, "exit": code,
                     "started": started.isoformat()})
    pcap_sha_after = sha256(args.pcap)
    print(f"\n  {args.pcap.name} unchanged after extraction: {pcap_sha_after == pcap_sha_before}")
    summary["extraction"] = {"installation": inst["home"], "launcher": str(launcher), "runs": [
        {k: str(v) for k, v in r.items()} for r in runs], "pcap_unchanged": pcap_sha_after == pcap_sha_before}
    summary["phase_reached"] = 3
    new = read_flow_csv(runs[0]["csv"])
    rerun = read_flow_csv(runs[1]["csv"])
    return finish(args, summary, old, new, rerun, packets, runs=runs)


def finish(args, summary, old, new, rerun, packets, runs=None, code=None):
    # ======================= Phase 4 =======================
    targets = []
    if new is not None:
        targets.append(("new extraction (run1)", new))
    if old is not None:
        targets.append(("existing CSV", old))
    if targets:
        section("PHASE 4 - Flow-level verification and packet accounting")
        for name, (header, recs, bad) in targets:
            bad_idx = {line - 2 for line in bad}
            recs = [r for i, r in enumerate(recs) if i not in bad_idx]
            s = summarize_flows(name, header, recs, bad)
            print_summary(s)
            if bad:
                print(f"    NOTE: {len(bad)} malformed line(s) {bad} excluded from these statistics (analysed in Phase 5)")
            rows, non_ip = packet_accounting(packets, header, recs)
            missing = [r for r in rows if r["difference"] != 0]
            print(f"    packet accounting per bidirectional 5-tuple: capture IP packets "
                  f"{sum(r['capture_packets'] for r in rows)}, packets in flows {sum(r['flow_packets'] for r in rows)}, "
                  f"non-IP packets {len(non_ip)}")
            listing([
                      f"      {r['l4']:<7} {r['key'][1][0]}:{r['key'][1][1]} <-> {r['key'][2][0]}:{r['key'][2][1]}  "
                      f"capture {r['capture_packets']}, in flows {r['flow_packets']}, difference {r['difference']}"
                      + ("   <- ARP frames misread as IPv4 (8.6.0.1 = bytes 08 06 00 01 = ARP ethertype + hardware type; "
                         "8.0.6.4 = 08 00 06 04 = protocol type + address sizes)" if {r['key'][1][0], r['key'][2][0]}
                         == {"8.0.6.4", "8.6.0.1"} else "") for r in missing], what="5-tuples")
            if not missing:
                print("      every IP packet is represented in a flow with the same 5-tuple")
            if name.startswith("new") or new is None:
                print("    trace of IPv4 packets in no flow:")
                trace_unaccounted(packets, header, recs)
            summary.setdefault("phase4", {})[name] = {**s, "unaccounted_by_key": [
                {**r, "key": list(map(str, r["key"]))} for r in missing]}

    # ======================= Phase 5 =======================
    if new is not None:
        section("PHASE 5 - Comparison")
        c1 = compare_flow_sets("run1", new[0], new[1], "run2", rerun[0], rerun[1])
        print("  Reproducibility (two runs of the same command):")
        print_comparison(c1)
        if old is not None:
            print("\n  New extraction vs existing CSV:")
            c2 = compare_flow_sets("new(run1)", new[0], new[1], "existing", old[0], old[1])
            print_comparison(c2)
            print("\n  Malformed lines:")
            malformed_line_analysis(args.old_csv, new)
            summary["phase5"] = {"run1_vs_run2": jsonable(c1), "new_vs_existing": jsonable(c2)}
        else:
            summary["phase5"] = {"run1_vs_run2": jsonable(c1)}
        summary["phase_reached"] = 5
    report = None
    if summary["phase_reached"] >= 3:
        path = args.audit_dir / f"stage_c_summary{args.suffix}.json"
        report = args.audit_dir / f"stage_c_report{args.suffix}.txt"
        if path.exists() or report.exists():
            print(f"\nSTOP: {path} or {report} already exists; not overwritten.")
            report = None
        else:
            path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
            print(f"\n  Summary saved: {path}")
            print(f"  Complete report (everything above plus the lists cut on the console): {report}")
    print("\nNo existing file was modified." + ("" if summary["phase_reached"] >= 3 else " Nothing was written."))
    if report is not None and TEE is not None:
        report.write_text(TEE.buf.getvalue(), encoding="utf-8")
    return code if code is not None else 0


def jsonable(c):
    return {k: (v if not isinstance(v, list) else [list(map(str, x)) if isinstance(x, tuple) else str(x) for x in v])
            for k, v in c.items()}


if __name__ == "__main__":
    sys.exit(main())
