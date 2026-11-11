"""STAGE A - read-only audit of the six MSCAD PCAPNG captures before converting them to classic PCAP.

Nothing is created, modified, moved or installed. Files are opened read-only and everything is printed.

Usage:
    python audit_pcapng.py                      (searches D:\\mscad)
    python audit_pcapng.py --root "D:\\some\\folder"

What it reports:
  1. Location of each of the six files (all copies if a name occurs more than once), size and SHA-256.
  2. Wireshark editcap / capinfos: path, version, and whether classic pcap output ("pcap"/"nsecpcap") is supported.
  3. An independent pure-Python read of each PCAPNG file: sections, interfaces (link type, snaplen,
     timestamp resolution/offset, name), packet blocks by type, first/last timestamp, duration, time order,
     truncated packets, packet options/comments.
  4. capinfos output for each file (if capinfos is installed), for cross-checking.
  5. Whether a classic PCAP copy can represent each file exactly, and why not if it cannot.
"""
import argparse
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

FILES = {
    "N-0.pcapng": "Normal",
    "Scan-1.pcapng": "Port Scan",
    "App-01.pcapng": "HTTP Slowloris DDoS",
    "App-02.pcapng": "ICMP Flood",
    "W-B-01.pcapng": "Web Crawling",
    "W-B-02.pcapng": "Password Cracking (Brute Force)",
}
LINKTYPES = {0: "NULL/Loopback", 1: "Ethernet", 101: "Raw IP", 105: "IEEE 802.11", 113: "Linux cooked (SLL)",
             127: "802.11 radiotap", 228: "Raw IPv4", 229: "Raw IPv6", 276: "Linux cooked v2 (SLL2)"}
WIRESHARK_DIRS = [Path(r"C:\Program Files\Wireshark"), Path(r"C:\Program Files (x86)\Wireshark")]


def section(title):
    print("\n" + "=" * 100 + f"\n{title}\n" + "=" * 100)


def human(n):
    return f"{n / 1024:,.2f} KB" if n < 1024 ** 2 else f"{n / 1024 ** 2:,.2f} MB"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fmt_ts(ns):
    if ns is None:
        return "-"
    dt = datetime.fromtimestamp(ns // 1_000_000_000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S") + f".{ns % 1_000_000_000:09d} UTC"


# ---------------------------------------------------------------------------------------------------------------
# Independent PCAPNG / PCAP reader (read-only, standard library only)
# ---------------------------------------------------------------------------------------------------------------

def parse_options(buf, endian):
    """Yield (code, value) pairs from a pcapng options area."""
    pos = 0
    while pos + 4 <= len(buf):
        code, length = struct.unpack_from(endian + "HH", buf, pos)
        pos += 4
        if code == 0:
            break
        yield code, buf[pos:pos + length]
        pos += (length + 3) & ~3


def tsresol_info(raw):
    """Return (units_per_second, description) for an if_tsresol option byte (default 10^-6)."""
    if raw is None:
        return 10 ** 6, "10^-6 (microseconds, default)"
    v = raw[0]
    if v & 0x80:
        return 2 ** (v & 0x7F), f"2^-{v & 0x7F}"
    names = {6: "microseconds", 9: "nanoseconds", 3: "milliseconds"}
    return 10 ** v, f"10^-{v}" + (f" ({names[v]})" if v in names else "")


def read_pcapng(path):
    info = {"format": "pcapng", "sections": 0, "interfaces": [], "blocks": {}, "packets": 0, "first": None,
            "last": None, "out_of_order": 0, "truncated": 0, "sub_us_nonzero": 0, "packets_with_options": 0,
            "comments": 0, "spb_packets": 0, "per_interface_packets": {}, "errors": []}
    prev = None
    with open(path, "rb") as fh:
        iface_base = 0
        endian = "<"
        while True:
            head = fh.read(8)
            if not head:
                break
            if len(head) < 8:
                info["errors"].append(f"truncated block header at offset {fh.tell() - len(head)}")
                break
            btype_le = struct.unpack("<I", head[:4])[0]
            if btype_le == 0x0A0D0D0A:  # Section Header Block: byte order from its magic
                bom = fh.read(4)
                endian = "<" if struct.unpack("<I", bom)[0] == 0x1A2B3C4D else ">"
                blen = struct.unpack(endian + "I", head[4:8])[0]
                body = bom + fh.read(blen - 12)
                info["sections"] += 1
                iface_base = len(info["interfaces"])
                for code, val in parse_options(body[16:blen - 12], endian):
                    if code == 1:
                        info["comments"] += 1
                info["blocks"]["Section Header"] = info["blocks"].get("Section Header", 0) + 1
                continue
            btype, blen = struct.unpack(endian + "II", head)
            if blen < 12 or blen % 4:
                info["errors"].append(f"invalid block length {blen} at offset {fh.tell() - 8}")
                break
            body = fh.read(blen - 12)
            fh.read(4)
            name = {1: "Interface Description", 2: "Packet (obsolete)", 3: "Simple Packet", 4: "Name Resolution",
                    5: "Interface Statistics", 6: "Enhanced Packet", 10: "Decryption Secrets"}.get(btype, f"type 0x{btype:08X}")
            info["blocks"][name] = info["blocks"].get(name, 0) + 1
            if btype == 1:
                linktype, _, snaplen = struct.unpack_from(endian + "HHI", body, 0)
                opts = dict(parse_options(body[8:], endian))
                units, desc = tsresol_info(opts.get(9))
                offset = struct.unpack(endian + "q", opts[14])[0] if 14 in opts else 0
                info["interfaces"].append({
                    "id": len(info["interfaces"]) - iface_base, "linktype": linktype,
                    "linktype_name": LINKTYPES.get(linktype, "other"), "snaplen": snaplen, "units": units,
                    "tsresol": desc, "tsoffset": offset,
                    "name": opts.get(2, b"").decode("utf-8", "replace"),
                    "description": opts.get(3, b"").decode("utf-8", "replace")})
            elif btype in (6, 2):
                if btype == 6:
                    iid, hi, lo, caplen, origlen = struct.unpack_from(endian + "IIIII", body, 0)
                    data_off = 20
                else:
                    iid, _, hi, lo, caplen, origlen = struct.unpack_from(endian + "HHIIII", body, 0)
                    data_off = 20
                iface = info["interfaces"][iface_base + iid] if iface_base + iid < len(info["interfaces"]) else None
                if iface is None:
                    info["errors"].append(f"packet refers to undefined interface {iid}")
                    continue
                ticks = (hi << 32) | lo
                ns = (ticks * 1_000_000_000) // iface["units"] + iface["tsoffset"] * 1_000_000_000
                if (ticks * 1_000_000_000) % iface["units"]:
                    info["sub_us_nonzero"] += 1  # not representable exactly even in nanoseconds
                elif ns % 1000:
                    info["sub_us_nonzero"] += 1
                if prev is not None and ns < prev:
                    info["out_of_order"] += 1
                prev = ns
                info["first"] = ns if info["first"] is None else info["first"]
                info["last"] = ns
                info["min"] = ns if info.get("min") is None else min(info["min"], ns)
                info["max"] = ns if info.get("max") is None else max(info["max"], ns)
                info["packets"] += 1
                key = iface_base + iid
                info["per_interface_packets"][key] = info["per_interface_packets"].get(key, 0) + 1
                if caplen < origlen:
                    info["truncated"] += 1
                opt_start = data_off + ((caplen + 3) & ~3)
                if opt_start < len(body):
                    opts = list(parse_options(body[opt_start:], endian))
                    if opts:
                        info["packets_with_options"] += 1
                        info["comments"] += sum(1 for c, _ in opts if c == 1)
            elif btype == 3:
                info["packets"] += 1
                info["spb_packets"] += 1
    return info


def read_pcap(path):
    with open(path, "rb") as fh:
        hdr = fh.read(24)
        magic = struct.unpack("<I", hdr[:4])[0]
        endian, units = {0xA1B2C3D4: ("<", 10 ** 6), 0xD4C3B2A1: (">", 10 ** 6),
                         0xA1B23C4D: ("<", 10 ** 9), 0x4D3CB2A1: (">", 10 ** 9)}[magic]
        _, _, _, _, snaplen, linktype = struct.unpack(endian + "HHiIII", hdr[4:])
        info = {"format": "pcap (nanosecond)" if units == 10 ** 9 else "pcap (microsecond)", "packets": 0,
                "first": None, "last": None, "out_of_order": 0, "truncated": 0, "errors": [],
                "interfaces": [{"id": 0, "linktype": linktype, "linktype_name": LINKTYPES.get(linktype, "other"),
                                "snaplen": snaplen, "tsresol": "10^-9" if units == 10 ** 9 else "10^-6",
                                "tsoffset": 0, "name": "", "description": ""}]}
        prev = None
        while True:
            rec = fh.read(16)
            if not rec:
                break
            if len(rec) < 16:
                info["errors"].append("truncated record header")
                break
            sec, frac, caplen, origlen = struct.unpack(endian + "IIII", rec)
            fh.seek(caplen, os.SEEK_CUR)
            ns = sec * 1_000_000_000 + frac * (1_000_000_000 // units)
            if prev is not None and ns < prev:
                info["out_of_order"] += 1
            prev = ns
            info["first"] = ns if info["first"] is None else info["first"]
            info["last"] = ns
            info["min"] = ns if info.get("min") is None else min(info["min"], ns)
            info["max"] = ns if info.get("max") is None else max(info["max"], ns)
            info["packets"] += 1
            info["truncated"] += caplen < origlen
    return info


def read_capture(path):
    with open(path, "rb") as fh:
        magic = fh.read(4)
    if magic == b"\x0a\x0d\x0d\x0a":
        return read_pcapng(path)
    if struct.unpack("<I", magic)[0] in (0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1):
        return read_pcap(path)
    return {"format": f"unknown (magic {magic.hex()})", "errors": ["not a pcapng/pcap file"], "packets": 0,
            "interfaces": [], "first": None, "last": None}


# ---------------------------------------------------------------------------------------------------------------

def find_tool(name):
    found = shutil.which(name)
    if found:
        return Path(found)
    for d in WIRESHARK_DIRS:
        p = d / f"{name}.exe"
        if p.is_file():
            return p
    return None


def run(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, str(exc)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path(r"D:\mscad"))
    args = ap.parse_args()

    section(f"1. Locate the six PCAPNG files under {args.root}")
    found = {name: [] for name in FILES}
    lower = {n.lower(): n for n in FILES}
    for dirpath, _, filenames in os.walk(args.root):
        for fn in filenames:
            if fn.lower() in lower:
                found[lower[fn.lower()]].append(Path(dirpath) / fn)
    selected = {}
    for name, paths in found.items():
        if not paths:
            print(f"  MISSING   {name}")
        for p in paths:
            print(f"  {'FOUND' if len(paths) == 1 else 'DUPLICATE'}  {p}  {p.stat().st_size:,} bytes ({human(p.stat().st_size)})")
        if len(paths) == 1:
            selected[name] = paths[0]
    dirs = sorted({str(p.parent) for p in selected.values()})
    print(f"\n  Directories containing the selected files: {dirs}")
    if len(selected) != len(FILES):
        print("  NOTE: not every file was found exactly once; resolve this before Stage B (pass --root).")

    section("2. Wireshark tools")
    editcap, capinfos = find_tool("editcap"), find_tool("capinfos")
    for name, tool in (("editcap", editcap), ("capinfos", capinfos)):
        if tool is None:
            print(f"  {name}: NOT FOUND (checked PATH and {', '.join(map(str, WIRESHARK_DIRS))})")
            continue
        code, out = run([str(tool), "-v"])
        first = next((l for l in out.splitlines() if l.strip()), "")
        print(f"  {name}: {tool}\n    version: {first.strip()}")
    if editcap:
        code, out = run([str(editcap), "-F"])
        types = {m.group(1): m.group(2).strip() for m in re.finditer(r"^\s+(\S+)\s+-\s+(.*)$", out, re.M)}
        for t in ("pcap", "nsecpcap", "pcapng"):
            print(f"    output type '{t}': {'supported - ' + types[t] if t in types else 'NOT listed'}")

    section("3. Size and SHA-256 of each original (baseline to prove the originals stay unchanged)")
    for name, p in selected.items():
        print(f"  {name:<15} {p.stat().st_size:>13,} bytes  {human(p.stat().st_size):>12}  sha256 {sha256(p)}")

    section("4. Capture characteristics (independent read of the file structure)")
    summary = []
    for name, p in selected.items():
        info = read_capture(p)
        print(f"\n  {name}  [{FILES[name]}]  format: {info['format']}")
        if info.get("sections") is not None:
            print(f"    sections: {info.get('sections')}   blocks: {info.get('blocks')}")
        for i in info["interfaces"]:
            print(f"    interface {i['id']}: link type {i['linktype']} ({i['linktype_name']}), snaplen {i['snaplen']}, "
                  f"timestamp resolution {i['tsresol']}, offset {i['tsoffset']} s"
                  + (f", name '{i['name']}'" if i["name"] else "") + (f", '{i['description']}'" if i["description"] else ""))
        dur = (info["max"] - info["min"]) / 1e9 if info.get("min") is not None else 0
        print(f"    packets: {info['packets']:,}" + (f" (per interface: {info.get('per_interface_packets')})"
                                                       if info.get("per_interface_packets") else ""))
        print(f"    first packet in file: {fmt_ts(info['first'])}\n    last packet in file:  {fmt_ts(info['last'])}")
        if info.get("out_of_order"):
            print(f"    earliest timestamp:   {fmt_ts(info.get('min'))}\n    latest timestamp:     {fmt_ts(info.get('max'))}")
        print(f"    capture duration (latest - earliest): {dur:,.9f} s")
        print(f"    packets out of time order: {info.get('out_of_order', 0):,}   truncated (caplen < length): "
              f"{info.get('truncated', 0):,}")
        if info["format"] == "pcapng":
            print(f"    timestamps with sub-microsecond detail: {info['sub_us_nonzero']:,}   simple packet blocks "
                  f"(no timestamp): {info['spb_packets']:,}   packets with options: {info['packets_with_options']:,}   "
                  f"comments: {info['comments']:,}")
        for e in info.get("errors", []):
            print(f"    ERROR: {e}")

        # Can classic pcap represent this file exactly?
        issues = []
        linktypes = {i["linktype"] for i in info["interfaces"]}
        if info["format"] != "pcapng":
            issues.append(f"file is already {info['format']}, not pcapng")
        if len(linktypes) > 1:
            issues.append(f"several link types {sorted(linktypes)}: classic pcap holds one link type per file")
        if info.get("sections", 1) > 1:
            issues.append(f"{info['sections']} sections")
        if info.get("sub_us_nonzero"):
            issues.append("sub-microsecond timestamps: microsecond pcap would truncate them; nanosecond pcap "
                          "('nsecpcap') keeps them")
        if info.get("spb_packets"):
            issues.append("simple packet blocks carry no timestamp")
        if any(i["tsoffset"] for i in info["interfaces"]):
            issues.append("interface timestamp offset is applied to every timestamp")
        if info.get("packets_with_options") or info.get("comments"):
            issues.append("packet options/comments cannot be stored in pcap (metadata only, not packet data)")
        if len(info["interfaces"]) > 1 and len(linktypes) == 1:
            issues.append(f"{len(info['interfaces'])} interfaces with the same link type: packets are kept but the "
                          "interface number is lost")
        if info.get("errors"):
            issues.append("structure errors (see above)")
        summary.append((name, info["format"], info["packets"], sorted(linktypes),
                        "; ".join(i["tsresol"] for i in info["interfaces"]), issues))

    if capinfos:
        section("5. capinfos cross-check (Wireshark's own reading)")
        for name, p in selected.items():
            code, out = run([str(capinfos), "-M", str(p)])
            print(f"\n  --- {name} (exit code {code})")
            print("\n".join("    " + l for l in out.splitlines()))

    section("6. Summary: can a classic PCAP copy be exact?")
    for name, fmt, packets, lts, res, issues in summary:
        verdict = "exact copy possible (packet data and timestamps)" if not issues else "SEE NOTES"
        print(f"  {name:<15} {fmt:<8} {packets:>12,} packets  link types {lts}  resolution {res}  -> {verdict}")
        for i in issues:
            print(f"      - {i}")
    free = shutil.disk_usage(args.root).free
    need = sum(p.stat().st_size for p in selected.values())
    print(f"\n  Free space on {args.root.anchor or args.root}: {human(free)}; the copies need roughly {human(need)} or less.")
    existing = args.root / "PCAP_Converted"
    print(f"  {existing}: {'EXISTS - contents: ' + str(sorted(os.listdir(existing))) if existing.exists() else 'does not exist yet'}")
    print("\nNothing was created or modified.")


if __name__ == "__main__":
    sys.exit(main())
