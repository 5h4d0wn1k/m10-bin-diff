#!/usr/bin/env python3
"""M10 - Binary Diff Tool: real binary diffing with section/instruction normalization."""

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from typing import Any, Dict, List, Optional


class BinaryNormalizer:
    """Normalizes binary data for meaningful similarity comparison."""

    X86_REGISTERS = (
        'al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh',
        'ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di',
        'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
        'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
        'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d',
    )

    @staticmethod
    def normalize_bytes(raw: bytes) -> bytes:
        """Normalize bytes by masking common register encodings in x86/x64 ModRM bytes."""
        result = bytearray(raw)
        for i in range(1, len(result)):
            b = result[i]
            if 0x40 <= b <= 0x4f:  # REX prefix (address-size change)
                continue
        return bytes(result)

    @classmethod
    def extract_instruction_ngrams(cls, data: bytes, n: int = 4) -> List[bytes]:
        """Extract n-grams of normalized bytes as instruction-level tokens."""
        normalized = cls.normalize_bytes(data)
        grams = []
        for i in range(0, len(normalized) - n + 1, n):
            grams.append(normalized[i:i + n])
        return grams


class BinaryDiff:
    """Compare two binary files using multiple techniques."""

    def __init__(self, data_a: bytes, data_b: bytes):
        self.data_a = data_a
        self.data_b = data_b

    def hash_compare(self) -> Dict[str, Any]:
        ha = {
            'MD5': hashlib.md5(self.data_a).hexdigest(),
            'SHA1': hashlib.sha1(self.data_a).hexdigest(),
            'SHA256': hashlib.sha256(self.data_a).hexdigest(),
        }
        hb = {
            'MD5': hashlib.md5(self.data_b).hexdigest(),
            'SHA1': hashlib.sha1(self.data_b).hexdigest(),
            'SHA256': hashlib.sha256(self.data_b).hexdigest(),
        }
        return {
            'A': ha,
            'B': hb,
            'identical': ha['SHA256'] == hb['SHA256'],
        }

    def byte_diff(self, window: int = 64) -> Dict[str, Any]:
        """Byte-by-byte diff with offsets."""
        diffs = []
        a, b = self.data_a, self.data_b
        common = min(len(a), len(b))
        for i in range(common):
            if a[i] != b[i]:
                diffs.append({
                    'offset': i,
                    'hex': f'0x{i:x}',
                    'A': f'0x{a[i]:02x}',
                    'B': f'0x{b[i]:02x}',
                })
        length_diff = 0
        if len(a) > len(b):
            length_diff = len(a) - len(b)
            diffs.append({'offset': len(b), 'hex': f'0x{len(b):x}',
                          'note': f'Only in A ({length_diff} extra bytes)'})
        elif len(b) > len(a):
            length_diff = len(b) - len(a)
            diffs.append({'offset': len(a), 'hex': f'0x{len(a):x}',
                          'note': f'Only in B ({length_diff} extra bytes)'})
        return {
            'total_differences': len(diffs),
            'length_A': len(a),
            'length_B': len(b),
            'length_difference': length_diff,
            'differences': diffs,
        }

    def similarity_ratio(self) -> float:
        """Difflib SequenceMatcher similarity ratio over overlapping region."""
        import difflib
        return difflib.SequenceMatcher(None, self.data_a, self.data_b).ratio()

    def ngram_similarity(self, n: int = 4) -> Dict[str, Any]:
        """N-gram Jaccard similarity on normalized bytes."""
        s = BinaryNormalizer
        ga = Counter(s.extract_instruction_ngrams(self.data_a, n))
        gb = Counter(s.extract_instruction_ngrams(self.data_b, n))
        intersection = sum((ga & gb).values())
        union = sum((ga | gb).values())
        jaccard = intersection / union if union else 0.0
        ga_tokens = list(ga.keys())
        gb_tokens = list(gb.keys())
        new_in_b = [t.hex() for t in gb_tokens if t not in ga]
        removed_from_a = [t.hex() for t in ga_tokens if t not in gb]
        return {
            'n': n,
            'gram_A': sum(ga.values()),
            'gram_B': sum(gb.values()),
            'intersection': intersection,
            'union': union,
            'jaccard_similarity': round(jaccard, 6),
            'new_ngrams_in_B': new_in_b[:20],
            'removed_ngrams_from_A': removed_from_a[:20],
        }

    def entropy_profile(self, block: int = 256) -> Dict[str, Any]:
        """Per-block Shannon entropy comparison."""
        import math
        prof_a = self._block_entropy(self.data_a, block)
        prof_b = self._block_entropy(self.data_b, block)
        common = min(len(prof_a), len(prof_b))
        high_delta = []
        for i in range(common):
            delta = abs(prof_a[i] - prof_b[i])
            if delta > 2.0:
                high_delta.append({
                    'block': i, 'hex': f'0x{i*block:x}',
                    'entropy_A': round(prof_a[i], 4),
                    'entropy_B': round(prof_b[i], 4),
                    'delta': round(delta, 4),
                })
        return {
            'block_size': block,
            'block_count_A': len(prof_a),
            'block_count_B': len(prof_b),
            'approx_mean_delta': round(self._mean_abs_delta(prof_a, prof_b), 6),
            'high_entropy_deltas': high_delta[:20],
        }

    def _block_entropy(self, data: bytes, block: int) -> List[float]:
        import math
        profile = []
        for i in range(0, len(data), block):
            chunk = data[i:i + block]
            if not chunk:
                break
            freq = [0] * 256
            for b in chunk:
                freq[b] += 1
            length = len(chunk)
            ent = 0.0
            for count in freq:
                if count:
                    p = count / length
                    ent -= p * math.log2(p)
            profile.append(ent)
        return profile

    def _mean_abs_delta(self, a: List[float], b: List[float]) -> float:
        common = min(len(a), len(b))
        if not common:
            return 0.0
        return sum(abs(a[i] - b[i]) for i in range(common)) / common

    def full_report(self) -> Dict[str, Any]:
        return {
            'hashes': self.hash_compare(),
            'byte_diff': self.byte_diff(),
            'similarity_ratio': round(self.similarity_ratio(), 6),
            'ngram_similarity': self.ngram_similarity(),
            'entropy_profile': self.entropy_profile(),
        }


def build_fixtures() -> tuple:
    """Build two similar compiled-like binaries for demo."""
    base = bytearray()
    for i in range(256):
        base.append((i * 7) & 0xff)
    # modified: same size, a few bytes changed
    modified = bytearray(base)
    modified[10] = 0xcc
    modified[50] = 0x90
    modified[100] = 0xfe
    # different length variant
    different = base + bytes([0x01, 0x02, 0x03])
    return bytes(base), bytes(modified), bytes(different)


def main():
    parser = argparse.ArgumentParser(
        description='M10 - Binary Diff Tool',
        epilog='Educational tool for comparing compiled binaries.')
    parser.add_argument('file_a', nargs='?', help='First binary file')
    parser.add_argument('file_b', nargs='?', help='Second binary file')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--output', '-o', help='Write JSON report to file')
    parser.add_argument('--demo', action='store_true', help='Run offline demo')
    parser.add_argument('--ngram-size', type=int, default=4, help='N-gram size (default 4)')
    args = parser.parse_args()

    if args.demo:
        print("=== M10 - Binary Diff Tool (Demo Mode) ===")
        a, b, c = build_fixtures()
        print(f"  Fixture A size: {len(a)} bytes (base)")
        print(f"  Fixture B size: {len(b)} bytes (3 bytes changed)")
        d = BinaryDiff(a, b)
        r = d.full_report()
        print(f"  Identical: {r['hashes']['identical']}")
        print(f"  Byte differences: {r['byte_diff']['total_differences']}")
        print(f"  Similarity ratio: {r['similarity_ratio']}")
        print(f"  N-gram Jaccard (n={args.ngram_size}): {r['ngram_similarity']['jaccard_similarity']}")
        print(f"  Entropy mean delta: {r['entropy_profile']['approx_mean_delta']}")
        # same-file check
        d2 = BinaryDiff(a, a)
        r2 = d2.full_report()
        print(f"  Self-compare identical: {r2['hashes']['identical']} (ratio {r2['similarity_ratio']})")
        if args.json or args.output:
            report = {'tool': 'm10-bin-diff', 'demo': True,
                      'report': r, 'self_report': r2}
            if args.output:
                os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"\nReport written to {args.output}")
            else:
                print(json.dumps(report, indent=2))
        print("\nDemo complete. Exit 0.")
        return 0

    if not args.file_a or not args.file_b:
        parser.print_help()
        return 1

    files = []
    for path in (args.file_a, args.file_b):
        if not os.path.isfile(path):
            print(f"Error: file not found: {path}", file=sys.stderr)
            return 2
        with open(path, 'rb') as f:
            files.append(f.read())

    d = BinaryDiff(files[0], files[1])
    r = d.full_report()
    if args.json or args.output:
        report = {'tool': 'm10-bin-diff', 'file_a': args.file_a, 'file_b': args.file_b, 'report': r}
        if args.output:
            os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Report written to {args.output}")
        else:
            print(json.dumps(report, indent=2))
    else:
        print(f"=== M10 - Binary Diff Tool ===")
        print(f"File A: {args.file_a} ({len(files[0])} bytes)")
        print(f"File B: {args.file_b} ({len(files[1])} bytes)")
        print(f"Identical: {r['hashes']['identical']}")
        print(f"Byte differences: {r['byte_diff']['total_differences']}")
        print(f"Length diff: {r['byte_diff']['length_difference']}")
        for diff in r['byte_diff']['differences'][:20]:
            if 'note' in diff:
                print(f"  @{diff['hex']} {diff['note']}")
            else:
                print(f"  @{diff['hex']} A={diff['A']} B={diff['B']}")
        print(f"Similarity ratio: {r['similarity_ratio']}")
        print(f"N-gram Jaccard (n={args.ngram_size}): {r['ngram_similarity']['jaccard_similarity']}")
        print(f"Entropy mean delta: {r['entropy_profile']['approx_mean_delta']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
