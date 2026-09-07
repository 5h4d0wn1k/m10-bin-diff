#!/usr/bin/env python3
"""Tests for M10 - Binary Diff Tool."""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bin_diff import BinaryDiff, BinaryNormalizer, build_fixtures


class TestBinaryDiffMethods(unittest.TestCase):
    def setUp(self):
        self.a, self.b, self.c = build_fixtures()
        self.d_ab = BinaryDiff(self.a, self.b)
        self.d_ac = BinaryDiff(self.a, self.c)
        self.d_aa = BinaryDiff(self.a, self.a)

    def test_identical_same_files(self):
        r = self.d_aa.full_report()
        self.assertTrue(r['hashes']['identical'])
        self.assertEqual(r['similarity_ratio'], 1.0)

    def test_modified_not_identical(self):
        self.assertFalse(self.d_ab.hash_compare()['identical'])

    def test_byte_diff_counts(self):
        bd = self.d_ab.byte_diff()
        self.assertGreaterEqual(bd['total_differences'], 3)

    def test_byte_diff_offsets_correct(self):
        bd = self.d_ab.byte_diff()
        offsets = {d['offset'] for d in bd['differences'] if 'note' not in d}
        self.assertIn(10, offsets)
        self.assertIn(50, offsets)
        self.assertIn(100, offsets)

    def test_length_difference_detected(self):
        bd = self.d_ac.byte_diff()
        self.assertEqual(bd['length_difference'], 3)
        self.assertEqual(bd['length_B'], len(self.a) + 3)

    def test_similarity_ratio_range(self):
        r_ab = self.d_ab.similarity_ratio()
        r_aa = self.d_aa.similarity_ratio()
        r_ac = self.d_ac.similarity_ratio()
        self.assertTrue(0.0 <= r_ab <= 1.0)
        self.assertTrue(0.0 <= r_ac <= 1.0)
        self.assertAlmostEqual(r_aa, 1.0, places=4)
        self.assertLess(r_ab, r_aa)

    def test_ngram_jaccard(self):
        ng = self.d_ab.ngram_similarity(4)
        self.assertTrue(0.0 <= ng['jaccard_similarity'] <= 1.0)
        # nearly identical files should have high Jaccard
        self.assertGreater(ng['jaccard_similarity'], 0.5)

    def test_ngram_self_similarity(self):
        ng = self.d_aa.ngram_similarity(4)
        self.assertAlmostEqual(ng['jaccard_similarity'], 1.0, places=4)

    def test_entropy_profile(self):
        ep = self.d_ab.entropy_profile()
        self.assertGreaterEqual(ep['block_count_A'], 1)
        self.assertIn('approx_mean_delta', ep)

    def test_hash_compare_fields(self):
        r = self.d_ab.hash_compare()
        self.assertEqual(r['A']['SHA256'], hashlib.sha256(self.a).hexdigest())
        self.assertEqual(r['B']['SHA256'], hashlib.sha256(self.b).hexdigest())


class TestNormalizer(unittest.TestCase):
    def test_normalize_passthrough(self):
        data = bytes(range(32))
        self.assertEqual(BinaryNormalizer.normalize_bytes(data), data)

    def test_ngram_extraction(self):
        data = bytes(range(16))
        grams = BinaryNormalizer.extract_instruction_ngrams(data, 4)
        self.assertEqual(len(grams), 4)
        self.assertEqual(grams[0], bytes([0, 1, 2, 3]))

    def test_full_report_structure(self):
        a, b, _ = build_fixtures()
        d = BinaryDiff(a, b)
        r = d.full_report()
        for key in ['hashes', 'byte_diff', 'similarity_ratio',
                     'ngram_similarity', 'entropy_profile']:
            self.assertIn(key, r)


class TestDemoMode(unittest.TestCase):
    def test_demo_exits_clean(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), 'bin_diff.py'), '--demo'],
            capture_output=True, text=True, timeout=10
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn('Demo complete', result.stdout)


if __name__ == '__main__':
    unittest.main()
