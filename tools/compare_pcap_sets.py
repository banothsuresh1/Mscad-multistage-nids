"""Read-only: compare two sets of MSCAD captures packet by packet (e.g. D:\\mscad\\PCAPS vs D:\\mscad\\PCAP_Converted).

For each of the six captures: format, link type, packet count, and every packet in order (timestamp to the
microsecond, captured length, original length, packet bytes). Works with pcap and pcapng on either side.
Writes nothing.

Usage:
    python compare_pcap_sets.py                                   (D:\\mscad\\PCAPS vs D:\\mscad\\PCAP_Converted)
    python compare_pcap_sets.py --a <folder> --b <folder>
"""
import argparse
import hashlib
import struct
import sys
from pathlib import Path

NAMES = ["N-0", "Scan-1", "App-01", "App-02", "W-B-01", "W-B-02"]


def read_pcap(fh, meta):
    hdr = fh.read(24)
    magic = struct.unpack("<I", hdr[:4])[0]
    endian, units, name = {0xA1B2C3D4: ("<", 10**6, "pcap"), 0xD4C3B2A1: (">", 10**6, "pcap"),
                           0xA1B23C4D: ("<", 10**9, "pcap (ns)"), 0x4D3CB2A1: (">", 10**9, "pcap (ns)")}[magic]
    meta.update(format=name, linktypes=[struct.unpack(endian + "I", hdr[20:24])[0]])
    while True:
        rec = fh.read(16)
        if len(rec) < 16:
            return
        sec, frac, caplen, origlen = struct.unpack(endian + "IIII", rec)
        yield sec * 10**9 + frac * (10**9 // units), caplen, origlen, fh.read(caplen)


def read_pcapng(fh, meta):
    meta.update(format="pcapng", linktypes=[])
    ifaces, endian = [], "<"
    while True:
        head = fh.read(8)
        if len(head) < 8:
            return
        if struct.unpack("<I", head[:4])[0] == 0x0A0D0D0A:
            bom = fh.read(4)
            endian = "<" if struct.unpack("<I", bom)[0] == 0x1A2B3C4D else ">"
            fh.read(struct.unpack(endian + "I", head[4:])[0] - 12)
            ifaces = []
            continue
        btype, blen = struct.unpack(endian + "II", head)
        body = fh.read(blen - 12)
        fh.read(4)
        if btype == 1:
            link = struct.unpack_from(endian + "H", body, 0)[0]
            units, pos = 10**6, 8
            while pos + 4 <= len(body):
                code, ln = struct.unpack_from(endian + "HH", body, pos)
                if code == 0:
                    break
                if code == 9:
                    v = body[pos + 4]
                    units = 2 ** (v & 0x7F) if v & 0x80 else 10 ** v
                pos += 4 + ((ln + 3) & ~3)
            ifaces.append(units)
            meta["linktypes"].append(link)
        elif btype == 6:
            iid, hi, lo, caplen, origlen = struct.unpack_from(endian + "IIIII", body, 0)
            yield ((hi << 32) | lo) * 10**9 // ifaces[iid], caplen, origlen, body[20:20 + caplen]


def packets(path, meta):
    fh = open(path, "rb")
    first = fh.read(4)
    fh.seek(0)
    return read_pcapng(fh, meta) if first == b"\x0a\x0d\x0d\x0a" else read_pcap(fh, meta)


def compare(a, b):
    ma, mb = {}, {}
    ia, ib = packets(a, ma), packets(b, mb)
    n, diffs, ha, hb = 0, [], hashlib.sha256(), hashlib.sha256()
    while True:
        x, y = next(ia, None), next(ib, None)
        if x is None and y is None:
            break
        n += 1
        if x is None or y is None:
            rest = sum(1 for _ in (ib if x is None else ia))
            diffs.append(f"packet {n}+: {rest + 1} extra packet(s) only in {'B' if x is None else 'A'}")
            break
        for h, r in ((ha, x), (hb, y)):
            h.update(struct.pack("<qII", r[0] // 1000, r[1], r[2]) + r[3])
        if x[0] // 1000 != y[0] // 1000:
            diffs.append(f"packet {n}: timestamp differs")
        if x[1:3] != y[1:3]:
            diffs.append(f"packet {n}: lengths {x[1:3]} vs {y[1:3]}")
        if x[3] != y[3]:
            diffs.append(f"packet {n}: bytes differ")
        if len(diffs) >= 10:
            diffs.append("... stopped after 10 differences")
            break
    return n, diffs, ma, mb, ha.hexdigest() == hb.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", type=Path, default=Path(r"D:\mscad\PCAPS"))
    ap.add_argument("--b", type=Path, default=Path(r"D:\mscad\PCAP_Converted"))
    args = ap.parse_args()
    print(f"A = {args.a}\nB = {args.b}\n")
    all_same = True
    for name in NAMES:
        fa, fb = args.a / f"{name}.pcap", args.b / f"{name}.pcap"
        if not fa.is_file() or not fb.is_file():
            print(f"{name:<7} MISSING: {fa if not fa.is_file() else fb}")
            all_same = False
            continue
        n, diffs, ma, mb, same_digest = compare(fa, fb)
        same = not diffs and same_digest
        all_same &= same
        print(f"{name:<7} A {fa.stat().st_size:>12,} bytes {ma.get('format')}  B {fb.stat().st_size:>12,} bytes "
              f"{mb.get('format')}  link {ma.get('linktypes')}/{mb.get('linktypes')}  packets compared {n:,}  "
              f"-> {'IDENTICAL packets' if same else 'DIFFERENT'}")
        for d in diffs:
            print(f"          {d}")
    print("\nAll six pairs have identical packets." if all_same else "\nAt least one pair differs (see above).")
    print("Nothing was written.")


if __name__ == "__main__":
    sys.exit(main())
