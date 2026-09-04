#!/usr/bin/env python3
"""M10 - Binary Diff Tool

Binary comparison, byte-by-byte diff, entropy comparison.
Uses hashlib, os, difflib only.
"""

import hashlib
import os
import sys
import math
import difflib


def file_hash(path, algo):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(data):
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def read_all(path):
    with open(path, "rb") as f:
        return f.read()


def byte_diff(a, b, context=4):
    """Byte-by-byte comparison. Returns list of differing offsets."""
    diffs = []
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            diffs.append(i)
    for i in range(n, max(len(a), len(b))):
        diffs.append(i)
    return diffs


def block_entropy(data, size=256):
    """Compute entropy per block of given size."""
    out = []
    for i in range(0, len(data), size):
        block = data[i:i + size]
        out.append((i, entropy(block)))
    return out


def similarity_ratio(a, b):
    return difflib.SequenceMatcher(None, a, b).ratio()


def format_diff(a, b, diffs, max_show=50):
    lines = []
    lines.append("Total differing offsets: %d" % len(diffs))
    lines.append("Byte-by-byte diff (first %d):" % min(max_show, len(diffs)))
    for idx in diffs[:max_show]:
        av = a[idx] if idx < len(a) else None
        bv = b[idx] if idx < len(b) else None
        astr = "%02x" % av if av is not None else "  "
        bstr = "%02x" % bv if bv is not None else "  "
        lines.append("  @0x%-8x A=%s  B=%s" % (idx, astr, bstr))
    if len(diffs) > max_show:
        lines.append("  ... (%d more)" % (len(diffs) - max_show))
    return "\n".join(lines)


def report(a_path, b_path):
    a = read_all(a_path)
    b = read_all(b_path)
    lines = []
    lines.append("=== M10 - Binary Diff Tool ===")
    lines.append("File A: %s (%d bytes)" % (a_path, len(a)))
    lines.append("File B: %s (%d bytes)" % (b_path, len(b)))

    lines.append("\n-- Hashes --")
    for algo in ("md5", "sha1", "sha256"):
        ha = file_hash(a_path, algo)
        hb = file_hash(b_path, algo)
        match = "SAME" if ha == hb else "DIFF"
        lines.append("  %s A: %s" % (algo.upper(), ha))
        lines.append("  %s B: %s  (%s)" % (algo.upper(), hb, match))

    same = a == b
    lines.append("\n-- Identical: %s --" % ("YES" if same else "NO"))

    diffs = byte_diff(a, b)
    lines.append("")
    lines.append(format_diff(a, b, diffs))

    ratio = similarity_ratio(a, b)
    lines.append("\n-- Similarity Ratio (difflib) --")
    lines.append("  %.4f" % ratio)

    lines.append("\n-- Entropy Comparison (per 256-byte block) --")
    ea = block_entropy(a)
    eb = block_entropy(b)
    nblocks = max(len(ea), len(eb))
    lines.append("  Block        A-ent    B-ent    Delta")
    for i in range(0, nblocks, 16):
        i_a = ea[i] if i < len(ea) else (i * 256, 0.0)
        i_b = eb[i] if i < len(eb) else (i * 256, 0.0)
        delta = abs(i_a[1] - i_b[1])
        lines.append("  0x%-8x  %6.3f   %6.3f   %+6.3f" % (i * 256, i_a[1], i_b[1], delta))
        if i >= 64:
            lines.append("  ...")
            break

    if a and b:
        lines.append("\n-- Hex Diff Window (first 32 bytes) --")
        lines.append("  A: %s" % a[:32].hex(" "))
        lines.append("  B: %s" % b[:32].hex(" "))

    return "\n".join(lines)


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 bin_diff.py <fileA> <fileB>")
        return 1
    a_path, b_path = sys.argv[1], sys.argv[2]
    if not os.path.isfile(a_path) or not os.path.isfile(b_path):
        print("Error: both files must exist")
        return 1
    try:
        print(report(a_path, b_path))
        return 0
    except Exception as e:
        print("Error: %s" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
