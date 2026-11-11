"""STAGE B - convert the six MSCAD PCAPNG captures to classic PCAP (libpcap, microsecond) and verify them.

Approved command per file (nothing else is applied: no filtering, truncation, time shifting or sampling):
    "C:\\Program Files\\Wireshark\\editcap.exe" -F pcap "<src>\\<name>.pcapng" "<dst>\\<name>.pcap"

Safety:
  * Originals are only read. Their SHA-256 is checked against the Stage A baseline before converting and
    re-checked after all conversions.
  * Nothing is overwritten: if any target .pcap or either report already exists, the script stops before
    converting anything. Nothing is ever deleted.
  * The script stops at the first error (editcap exit code, editcap error output, or any verification
    difference). Files already converted and verified are kept and listed.

Verification of each pair (independent pure-Python reader, packet by packet, in file order):
  packet count, order, timestamp (microseconds), captured length, original length, packet bytes,
  link type (Ethernet), classic-pcap header (microsecond libpcap), expected size (Stage A table and the size
  computed from the original), capinfos validation of the copy, and an SHA-256 digest of the normalised
  packet records of both files.

Reports (written only if all six pass):
  <dst>\\conversion_verification_report.md and <dst>\\conversion_verification_report.csv

Usage:
    python D:\\mscad\\convert_mscad_pcapng_to_pcap.py
Options exist only for testing on synthetic files: --src, --dst, --editcap, --capinfos, --no-stage-a-baseline.
"""
import argparse
import csv
import hashlib
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ORDER = ["N-0", "Scan-1", "App-01", "App-02", "W-B-01", "W-B-02"]
CATEGORY = {"N-0": "Normal", "Scan-1": "Port Scan", "App-01": "HTTP Slowloris DDoS", "App-02": "ICMP Flood",
            "W-B-01": "Web Crawling", "W-B-02": "Password Cracking (Brute Force)"}

# Stage A audit results (D:\mscad\PCAPNG_ORIGINAL, Wireshark 4.6.9).
STAGE_A = {
    "N-0":    {"size": 105_328,     "packets": 214,     "pcap_size": 101_085,
               "sha256": "c2ff3dbff25c373b8f1234d74ef949163da1006ebccc1faad1dfed6cbf54cb3f"},
    "Scan-1": {"size": 3_697_616,   "packets": 38_860,  "pcap_size": 2_998_738,
               "sha256": "bf3725cb6bf5884ec842dc60555811572ef78d57938cb41c0a5ceb2ffc7c5ffb"},
    "App-01": {"size": 623_312,     "packets": 3_217,   "pcap_size": 565_932,
               "sha256": "00259d5b154bbcbfdebf4e0c4b54f065a1c1af71a04c6292be13607ebf37741e"},
    "App-02": {"size": 480_507_712, "packets": 315_670, "pcap_size": 474_825_252,
               "sha256": "2c8e4a4c5038e38b6277bbd3bc544ca25ed89421d8e03833454c32e2b45787c5"},
    "W-B-01": {"size": 2_677_516,   "packets": 3_104,   "pcap_size": 2_621_571,
               "sha256": "81cc682e321dc15d71c672bd5ac8f0a39cb910654a390b61b22ebd239f142c7d"},
    "W-B-02": {"size": 268_401_688, "packets": 648_673, "pcap_size": 256_835_392,
               "sha256": "c2e4978ebf958cec5098be4e839e3caeb5d7a7010d88d83b670d46d674a430ef"},
}
REPORT_MD = "conversion_verification_report.md"
REPORT_CSV = "conversion_verification_report.csv"
ETHERNET = 1
PCAP_MAGIC_USEC_LE = 0xA1B2C3D4


class StopRun(Exception):
    """A condition that must stop the run."""


# ---------------------------------------------------------------------------------------------------------------
# Independent readers: yield (timestamp_ns, captured_length, original_length, packet_bytes) in file order
# ---------------------------------------------------------------------------------------------------------------

def _options(buf, endian):
    pos = 0
    while pos + 4 <= len(buf):
        code, length = struct.unpack_from(endian + "HH", buf, pos)
        pos += 4
        if code == 0:
            break
        yield code, buf[pos:pos + length]
        pos += (length + 3) & ~3


def read_pcapng(path, meta):
    meta.update(format="pcapng", linktypes=[], tsresol=[], blocks={})
    interfaces = []
    endian = "<"
    with open(path, "rb") as fh:
        while True:
            head = fh.read(8)
            if not head:
                return
            if len(head) < 8:
                raise StopRun(f"{path}: truncated block header")
            if struct.unpack("<I", head[:4])[0] == 0x0A0D0D0A:
                bom = fh.read(4)
                endian = "<" if struct.unpack("<I", bom)[0] == 0x1A2B3C4D else ">"
                blen = struct.unpack(endian + "I", head[4:])[0]
                fh.read(blen - 12)
                interfaces = []
                meta["blocks"]["SHB"] = meta["blocks"].get("SHB", 0) + 1
                continue
            btype, blen = struct.unpack(endian + "II", head)
            if blen < 12 or blen % 4:
                raise StopRun(f"{path}: invalid block length {blen}")
            body = fh.read(blen - 12)
            if len(body) != blen - 12 or len(fh.read(4)) != 4:
                raise StopRun(f"{path}: truncated block")
            meta["blocks"][btype] = meta["blocks"].get(btype, 0) + 1
            if btype == 1:
                linktype, _, _ = struct.unpack_from(endian + "HHI", body, 0)
                opts = dict(_options(body[8:], endian))
                raw = opts.get(9)
                units = 10 ** 6 if raw is None else (2 ** (raw[0] & 0x7F) if raw[0] & 0x80 else 10 ** raw[0])
                offset = struct.unpack(endian + "q", opts[14])[0] if 14 in opts else 0
                interfaces.append((linktype, units, offset))
                meta["linktypes"].append(linktype)
                meta["tsresol"].append(units)
            elif btype in (6, 2):
                if btype == 6:
                    iid, hi, lo, caplen, origlen = struct.unpack_from(endian + "IIIII", body, 0)
                else:
                    iid, _, hi, lo, caplen, origlen = struct.unpack_from(endian + "HHIIII", body, 0)
                if iid >= len(interfaces):
                    raise StopRun(f"{path}: packet refers to undefined interface {iid}")
                _, units, offset = interfaces[iid]
                ticks = (hi << 32) | lo
                ns = ticks * 1_000_000_000 // units + offset * 1_000_000_000
                yield ns, caplen, origlen, body[20:20 + caplen]
            elif btype == 3:
                origlen = struct.unpack_from(endian + "I", body, 0)[0]
                caplen = min(origlen, len(body) - 4)
                yield None, caplen, origlen, body[4:4 + caplen]


def read_pcap(path, meta):
    with open(path, "rb") as fh:
        hdr = fh.read(24)
        if len(hdr) < 24:
            raise StopRun(f"{path}: file shorter than a pcap header")
        magic = struct.unpack("<I", hdr[:4])[0]
        table = {0xA1B2C3D4: ("<", 10 ** 6, "pcap (microsecond, little-endian)"),
                 0xD4C3B2A1: (">", 10 ** 6, "pcap (microsecond, big-endian)"),
                 0xA1B23C4D: ("<", 10 ** 9, "pcap (nanosecond, little-endian)"),
                 0x4D3CB2A1: (">", 10 ** 9, "pcap (nanosecond, big-endian)")}
        if magic not in table:
            raise StopRun(f"{path}: not a classic pcap file (magic 0x{magic:08X})")
        endian, units, name = table[magic]
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHiIII", hdr[4:])
        meta.update(format=name, magic=magic, version=f"{major}.{minor}", snaplen=snaplen, linktypes=[linktype],
                    tsresol=[units])
        while True:
            rec = fh.read(16)
            if not rec:
                return
            if len(rec) < 16:
                raise StopRun(f"{path}: truncated packet record header")
            sec, frac, caplen, origlen = struct.unpack(endian + "IIII", rec)
            data = fh.read(caplen)
            if len(data) != caplen:
                raise StopRun(f"{path}: truncated packet data")
            yield sec * 1_000_000_000 + frac * (1_000_000_000 // units), caplen, origlen, data


# ---------------------------------------------------------------------------------------------------------------

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def utc(ns):
    if ns is None:
        return ""
    dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ns // 1000)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f UTC")


def record_digest_update(h, rec):
    ns, caplen, origlen, data = rec
    h.update(struct.pack("<qII", -1 if ns is None else ns, caplen, origlen))
    h.update(data)


def compare_pair(src, dst):
    """Compare every packet of the original and the copy, in order. Returns a result dict."""
    meta_o, meta_c = {}, {}
    it_o, it_c = read_pcapng(src, meta_o), read_pcap(dst, meta_c)
    h_o, h_c = hashlib.sha256(), hashlib.sha256()
    n = 0
    first = last = None
    min_ts = max_ts = None
    data_bytes = 0
    differences = []
    while True:
        a = next(it_o, None)
        b = next(it_c, None)
        if a is None and b is None:
            break
        n += 1
        if a is None or b is None:
            differences.append(f"packet {n}: present only in the {'converted' if a is None else 'original'} file")
            # count the remaining packets on the longer side
            rest = sum(1 for _ in (it_c if a is None else it_o))
            differences.append(f"{rest + 1} packet(s) beyond the shorter file")
            break
        record_digest_update(h_o, a)
        record_digest_update(h_c, b)
        if a[0] is None:
            differences.append(f"packet {n}: original has no timestamp (simple packet block)")
        elif a[0] != b[0]:
            differences.append(f"packet {n}: timestamp {utc(a[0])} != {utc(b[0])}")
        if a[1] != b[1]:
            differences.append(f"packet {n}: captured length {a[1]} != {b[1]}")
        if a[2] != b[2]:
            differences.append(f"packet {n}: original length {a[2]} != {b[2]}")
        if a[3] != b[3]:
            differences.append(f"packet {n}: packet bytes differ")
        if len(differences) >= 20:
            differences.append("... stopped after 20 differences")
            break
        first = a[0] if first is None else first
        last = a[0]
        if a[0] is not None:
            min_ts = a[0] if min_ts is None else min(min_ts, a[0])
            max_ts = a[0] if max_ts is None else max(max_ts, a[0])
        data_bytes += a[1]
    return {"packets_compared": n, "differences": differences, "first": first, "last": last,
            "duration_s": (max_ts - min_ts) / 1e9 if min_ts is not None else 0.0,
            "digest_original": h_o.hexdigest(), "digest_converted": h_c.hexdigest(),
            "meta_original": meta_o, "meta_converted": meta_c, "data_bytes": data_bytes}


def count_packets(path, reader):
    meta = {}
    n = data = 0
    for rec in reader(path, meta):
        n += 1
        data += rec[1]
    return n, data, meta


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=3600)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()


def capinfos_check(capinfos, path):
    code, out, err = run([str(capinfos), "-M", str(path)])
    text = out + ("\n" + err if err else "")
    fields = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([^:]+):\s+(.*)$", line)
        if m:
            fields.setdefault(m.group(1).strip(), m.group(2).strip())
    return code, fields, text


def find_tool(name, explicit):
    if explicit:
        return Path(explicit)
    for candidate in (shutil.which(name), rf"C:\Program Files\Wireshark\{name}.exe",
                      rf"C:\Program Files (x86)\Wireshark\{name}.exe"):
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    return None


def quote(p):
    s = str(p)
    return f'"{s}"' if (" " in s or "\\" in s) else s


# ---------------------------------------------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", type=Path, default=Path(r"D:\mscad\PCAPNG_ORIGINAL"))
    ap.add_argument("--dst", type=Path, default=Path(r"D:\mscad\PCAP_Converted"))
    ap.add_argument("--editcap", default=None)
    ap.add_argument("--capinfos", default=None)
    ap.add_argument("--no-stage-a-baseline", action="store_true",
                    help="testing only: do not compare with the Stage A sizes/hashes/packet counts")
    args = ap.parse_args(argv)
    use_baseline = not args.no_stage_a_baseline
    print(f"MSCAD PCAPNG -> PCAP conversion | source {args.src} | output {args.dst}")

    # ---------------- Pre-flight (nothing is written) ----------------
    editcap, capinfos = find_tool("editcap", args.editcap), find_tool("capinfos", args.capinfos)
    if editcap is None or capinfos is None:
        print("STOP: editcap or capinfos not found.")
        return 2
    versions = {}
    for label, tool in (("editcap", editcap), ("capinfos", capinfos)):
        code, out, err = run([str(tool), "-v"])
        first = next((line.strip() for line in (out + "\n" + err).splitlines() if line.strip()), "")
        if code != 0 or not first:
            print(f"STOP: '{tool} -v' failed (exit code {code}); cannot confirm the {label} version.")
            return 2
        versions[label] = first
    editcap_version, capinfos_version = versions["editcap"], versions["capinfos"]
    print(f"editcap:  {editcap}  ({editcap_version})\ncapinfos: {capinfos}  ({capinfos_version})")

    sources = {name: args.src / f"{name}.pcapng" for name in ORDER}
    targets = {name: args.dst / f"{name}.pcap" for name in ORDER}
    missing = [str(p) for p in sources.values() if not p.is_file()]
    if missing:
        print(f"STOP: original files missing: {missing}")
        return 2
    existing = [str(p) for p in list(targets.values()) + [args.dst / REPORT_MD, args.dst / REPORT_CSV] if p.exists()]
    if existing:
        print(f"STOP: these output files already exist and will not be overwritten: {existing}")
        return 2

    print("\nHashing originals (SHA-256) ...")
    sha_before = {}
    for name, p in sources.items():
        sha_before[name] = sha256_file(p)
        size = p.stat().st_size
        print(f"  {name + '.pcapng':<15} {size:>13,} bytes  {sha_before[name]}")
        if use_baseline and (sha_before[name] != STAGE_A[name]["sha256"] or size != STAGE_A[name]["size"]):
            print(f"STOP: {name}.pcapng differs from the Stage A audit (size or SHA-256). Nothing was converted.")
            return 2

    need = sum(STAGE_A[n]["pcap_size"] for n in ORDER) if use_baseline else sum(p.stat().st_size for p in sources.values())
    probe = args.dst if args.dst.exists() else args.dst.parent
    free = shutil.disk_usage(probe).free
    print(f"\nDisk space: {free / 1024 ** 2:,.1f} MB free, about {need / 1024 ** 2:,.1f} MB needed")
    if free < need * 1.2:
        print("STOP: not enough free disk space (20% margin required).")
        return 2

    args.dst.mkdir(parents=False, exist_ok=True)
    print(f"Output directory ready: {args.dst}")

    # ---------------- Convert and verify, one file at a time ----------------
    results = []
    failure = None
    for name in ORDER:
        src, dst = sources[name], targets[name]
        cmd = [str(editcap), "-F", "pcap", str(src), str(dst)]
        cmd_text = " ".join(quote(c) for c in cmd)
        print(f"\n[{name}] {cmd_text}")
        res = {"name": name, "category": CATEGORY[name], "command": cmd_text, "original": str(src),
               "converted": str(dst), "original_size": src.stat().st_size, "status": "FAILED", "notes": []}
        results.append(res)
        if dst.exists():
            failure = f"{dst} appeared before conversion; not overwritten"
            res["notes"].append(failure)
            break
        code, out, err = run(cmd)
        res["editcap_exit"] = code
        res["editcap_output"] = "\n".join(x for x in (out, err) if x)
        if code != 0 or err:
            failure = f"editcap exit code {code}; output: {res['editcap_output'] or '(none)'}"
            res["notes"].append(failure)
            break
        if not dst.is_file():
            failure = "editcap reported success but no output file exists"
            res["notes"].append(failure)
            break

        print("  verifying packet by packet ...")
        cmp = compare_pair(src, dst)
        mo, mc = cmp["meta_original"], cmp["meta_converted"]
        res.update(
            original_format="pcapng", converted_format=mc.get("format", "?"),
            original_packets=None, converted_packets=None, first=utc(cmp["first"]), last=utc(cmp["last"]),
            duration_s=cmp["duration_s"], converted_size=dst.stat().st_size,
            digest_original=cmp["digest_original"], digest_converted=cmp["digest_converted"],
            linktype_original=mo.get("linktypes"), linktype_converted=mc.get("linktypes"),
            sha256_converted=sha256_file(dst))
        n_o, data_o, _ = count_packets(src, read_pcapng)
        n_c, _, _ = count_packets(dst, read_pcap)
        res["original_packets"], res["converted_packets"] = n_o, n_c
        predicted = 24 + 16 * n_o + data_o
        res["expected_size"] = STAGE_A[name]["pcap_size"] if use_baseline else predicted

        checks = {
            "packet count identical": n_o == n_c,
            "packets identical in order (timestamp, lengths, bytes)": not cmp["differences"],
            "normalised packet-record digests identical": cmp["digest_original"] == cmp["digest_converted"],
            "classic microsecond libpcap header": mc.get("magic") == PCAP_MAGIC_USEC_LE and mc.get("version") == "2.4",
            "link type Ethernet in both": mo.get("linktypes") == [ETHERNET] and mc.get("linktypes") == [ETHERNET],
            "converted size = 24 + 16 x packets + packet data": res["converted_size"] == predicted,
            "converted size = Stage A expected size": (res["converted_size"] == STAGE_A[name]["pcap_size"]) if use_baseline else True,
            "packet count = Stage A count": (n_o == STAGE_A[name]["packets"]) if use_baseline else True,
        }
        code_ci, fields, ci_text = capinfos_check(capinfos, dst)
        res["capinfos"] = ci_text
        checks["capinfos reads the copy (exit 0)"] = code_ci == 0
        ftype = fields.get("File type", "")
        checks["capinfos: file type pcap"] = ftype == "pcap" or ftype.endswith("- pcap")
        checks["capinfos: microsecond timestamps"] = fields.get("File timestamp precision", "").startswith("microseconds")
        checks["capinfos: encapsulation ether"] = fields.get("File encapsulation", "") == "ether"
        checks["capinfos: packet count matches"] = fields.get("Number of packets", "").replace(",", "") == str(n_o)
        res["checks"] = checks
        res["notes"] += cmp["differences"]
        failed = [k for k, ok in checks.items() if not ok]
        res["timestamp_check"] = "PASS" if not any("timestamp" in d for d in cmp["differences"]) and n_o == n_c else "FAIL"
        res["integrity"] = "PASS" if not cmp["differences"] and cmp["digest_original"] == cmp["digest_converted"] else "FAIL"
        for k, ok in checks.items():
            print(f"    {'PASS' if ok else 'FAIL'}  {k}")
        if failed:
            failure = f"verification failed: {failed}"
            res["notes"].append(failure)
            for d in cmp["differences"][:10]:
                print(f"    difference: {d}")
            break
        res["status"] = "PASS"

    # ---------------- Originals unchanged? ----------------
    print("\nRe-hashing originals ...")
    sha_after = {name: sha256_file(p) for name, p in sources.items()}
    originals_ok = sha_after == sha_before
    for name in ORDER:
        print(f"  {name + '.pcapng':<15} {'unchanged' if sha_after[name] == sha_before[name] else 'CHANGED'}")
    for r in results:
        r["sha256_original_before"] = sha_before[r["name"]]
        r["sha256_original_after"] = sha_after[r["name"]]

    # ---------------- Summary ----------------
    print("\n" + "=" * 100)
    header = ["Filename", "Original Format", "Converted Format", "Original Packets", "Converted Packets",
              "Timestamp Check", "Packet Integrity", "Status"]
    rows = []
    for name in ORDER:
        r = next((x for x in results if x["name"] == name), None)
        if r is None:
            rows.append([f"{name}.pcapng", "pcapng", "-", STAGE_A[name]["packets"] if use_baseline else "-", "-",
                         "-", "-", "NOT RUN (stopped earlier)"])
        else:
            rows.append([f"{name}.pcapng", "pcapng", r.get("converted_format", "-"), r.get("original_packets", "-"),
                         r.get("converted_packets", "-"), r.get("timestamp_check", "-"), r.get("integrity", "-"),
                         r["status"]])
    widths = [max(len(str(x)) for x in col) for col in zip(header, *rows)]
    for row in [header] + rows:
        print("  ".join(str(v).ljust(w) for v, w in zip(row, widths)))
    all_pass = failure is None and originals_ok and len(results) == len(ORDER) and all(r["status"] == "PASS" for r in results)
    if not originals_ok:
        print("\nFAIL: an original file changed during the run.")
    if failure:
        print(f"\nSTOPPED at {results[-1]['name']}: {failure}")
        print("Files converted and verified before the stop are kept: "
              + (", ".join(r["converted"] for r in results if r["status"] == "PASS") or "none"))
        print(f"Kept as written (not deleted): {results[-1]['converted'] if Path(results[-1]['converted']).exists() else 'no file'}")
        print("Reports are written only when all six conversions pass.")
        return 1
    if not all_pass:
        return 1

    write_reports(args, results, header, rows, editcap, editcap_version, capinfos_version)
    print(f"\nALL SIX CONVERSIONS PASSED VERIFICATION.\nReports: {args.dst / REPORT_MD}\n         {args.dst / REPORT_CSV}")
    return 0


def write_reports(args, results, header, rows, editcap, editcap_version, capinfos_version):
    csv_cols = ["Filename", "Category", "Original Format", "Converted Format", "Original File", "Converted File",
                "Original Size (bytes)", "Converted Size (bytes)", "Expected Converted Size (bytes)",
                "Original Packets", "Converted Packets", "First Packet (UTC)", "Last Packet (UTC)", "Duration (s)",
                "Timestamp Check", "Packet Integrity", "Normalised Record Digest (original)",
                "Normalised Record Digest (converted)", "Original SHA-256 Before", "Original SHA-256 After",
                "Original Unchanged", "Converted SHA-256", "Link Type", "editcap Exit Code", "editcap Output",
                "Command", "Status"]
    with open(args.dst / REPORT_CSV, "x", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(csv_cols)
        for r in results:
            w.writerow([f"{r['name']}.pcapng", r["category"], "pcapng", r["converted_format"], r["original"],
                        r["converted"], r["original_size"], r["converted_size"], r["expected_size"],
                        r["original_packets"], r["converted_packets"], r["first"], r["last"], f"{r['duration_s']:.6f}",
                        r["timestamp_check"], r["integrity"], r["digest_original"], r["digest_converted"],
                        r["sha256_original_before"], r["sha256_original_after"],
                        r["sha256_original_before"] == r["sha256_original_after"], r["sha256_converted"],
                        "Ethernet (1)", r["editcap_exit"], r["editcap_output"] or "", r["command"], r["status"]])

    lines = [
        "# MSCAD PCAPNG to PCAP conversion verification report", "",
        f"* Run: {datetime.now().isoformat(timespec='seconds')} on {platform.platform()}",
        f"* Original directory: `{args.src}`",
        f"* Converted directory: `{args.dst}`",
        f"* Utility: `{editcap}` - {editcap_version}",
        f"* Validation: {capinfos_version}",
        "* Output format: classic libpcap, microsecond timestamps (magic 0xA1B2C3D4, version 2.4), link type Ethernet",
        "* Transformations: none (no filtering, truncation, time shifting or sampling)", "",
        "| " + " | ".join(header) + " |", "|" + "---|" * len(header),
    ]
    lines += ["| " + " | ".join(str(v) for v in row) + " |" for row in rows]
    lines += ["", "## Per-file details", "",
              "| File | Original size | Converted size | Expected size | First packet (UTC) | Last packet (UTC) | Duration (s) | Original SHA-256 unchanged |",
              "|---|---:|---:|---:|---|---|---:|---|"]
    for r in results:
        lines.append(f"| {r['name']} | {r['original_size']:,} | {r['converted_size']:,} | {r['expected_size']:,} | "
                     f"{r['first']} | {r['last']} | {r['duration_s']:.6f} | "
                     f"{'yes' if r['sha256_original_before'] == r['sha256_original_after'] else 'NO'} |")
    lines += ["", "## Commands", ""] + [f"* `{r['command']}` (exit code {r['editcap_exit']}"
                                          f"{', output: ' + r['editcap_output'] if r['editcap_output'] else ', no output'})"
                                          for r in results]
    lines += ["", "## Checks per file", ""]
    for r in results:
        lines.append(f"* **{r['name']}**: " + "; ".join(f"{k}: {'PASS' if ok else 'FAIL'}" for k, ok in r["checks"].items()))
    lines += ["", "## Format-related differences (not packet data)", "",
              "* The copies are smaller because a pcap record header is 16 bytes, while a pcapng Enhanced Packet Block "
              "adds 32 bytes plus padding.",
              "* Classic pcap has no place for pcapng metadata: interface name/description, capture hardware/OS/"
              "application strings, and the Interface Statistics block. Packet data, lengths, order and microsecond "
              "timestamps are identical (verified packet by packet).",
              "* File-level SHA-256 values of original and copy differ by design (different container formats); the "
              "normalised packet-record digests are identical.", "",
              "## Warnings or errors", "", "None.", ""]
    with open(args.dst / REPORT_MD, "x", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
