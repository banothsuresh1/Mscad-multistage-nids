"""Read-only: is a damaged CSV identical to a clean CICFlowMeter output except for removed/changed text?

Compares the two files byte by byte: longest common beginning and end, then shows exactly what text the
clean file has that the damaged one lacks (and vice versa), with line numbers and the flows involved.
Writes nothing.

Usage:
    python csv_damage_forensics.py <clean_csv> <damaged_csv>
"""
import sys
from pathlib import Path


def lines_info(data, start, end):
    """Line numbers (1-based) spanned by byte range [start, end) of data."""
    first = data.count(b"\n", 0, start) + 1
    last = data.count(b"\n", 0, max(start, end - 1)) + 1
    return first, last


def show(label, data, start, end, limit=600):
    chunk = data[start:end]
    first, last = lines_info(data, start, end)
    print(f"\n  {label}: {len(chunk)} bytes, lines {first}..{last} of that file")
    text = chunk.decode("utf-8", "replace")
    print("    " + (text[:limit] + (" ..." if len(text) > limit else "")).replace("\r", "").replace("\n", "\n    "))
    flows = [l.split(",")[0] for l in text.replace("\r", "").split("\n") if l.count(",") > 10]
    if flows:
        print(f"    complete rows inside it (Flow ID): {flows}")


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    clean_p, damaged_p = Path(sys.argv[1]), Path(sys.argv[2])
    clean, damaged = clean_p.read_bytes(), damaged_p.read_bytes()
    nl = b"\n"
    print(f"clean:   {clean_p}  {len(clean):,} bytes, {clean.count(nl)} lines")
    print(f"damaged: {damaged_p}  {len(damaged):,} bytes, {damaged.count(nl)} lines")
    if clean == damaged:
        print("\nThe files are byte-for-byte identical.")
        return 0
    p = 0
    while p < min(len(clean), len(damaged)) and clean[p] == damaged[p]:
        p += 1
    s = 0
    while s < min(len(clean), len(damaged)) - p and clean[-1 - s] == damaged[-1 - s]:
        s += 1
    only_clean = (p, len(clean) - s)
    only_damaged = (p, len(damaged) - s)
    print(f"\nIdentical first {p:,} bytes and identical last {s:,} bytes.")
    if only_clean[1] > only_clean[0]:
        show("text present ONLY in the clean file", clean, *only_clean)
    if only_damaged[1] > only_damaged[0]:
        show("text present ONLY in the damaged file", damaged, *only_damaged)
    if only_damaged[1] == only_damaged[0]:
        print("\nVERDICT: the damaged file equals the clean file with ONE contiguous block of text removed "
              "(nothing added or changed anywhere else).")
    else:
        print("\nVERDICT: the files differ by more than one removed block (text was also added or changed, or the "
              "row order differs); a single-deletion explanation does not hold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
