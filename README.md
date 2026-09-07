# M10 — Binary Diff Tool

Compares binary files with real diffing techniques: byte diffing, n-gram similarity, entropy profiling, and import/section comparison.

## Overview

This project compares two binary files and reports:
- MD5/SHA1/SHA256 hash comparison
- Byte-by-byte differences with offsets
- Similarity ratio (difflib)
- N-gram Jaccard similarity on normalized bytes
- Per-block Shannon entropy comparison
- Instruction-level normalization for meaningful similarity

## Features

- **Hash comparison**: detect identical files
- **Byte diff**: list every differing offset, handle length differences
- **N-gram similarity**: Jaccard similarity on 4-byte instruction n-grams
- **Entropy comparison**: spot obfuscated/encrypted regions via delta profile
- **Normalization**: masks register encoding variance for better similarity
- **Similarity ratio**: difflib SequenceMatcher

## Usage

```bash
# Compare two binaries
python3 bin_diff.py original.bin modified.bin

# JSON output
python3 bin_diff.py original.bin modified.bin --json

# Custom n-gram size
python3 bin_diff.py original.bin modified.bin --ngram-size 8

# Save report
python3 bin_diff.py original.bin modified.bin -o reports/diff.json

# Offline demo
python3 bin_diff.py --demo
```

## Example Output

```
=== M10 - Binary Diff Tool ===
File A: f1.o (1080 bytes)
File B: f2.o (1080 bytes)
Identical: False
Byte differences: 41
Length diff: 0
  @0x41 A=0x04 B=0x44
  @0x43 A=0xc3 B=0x01
  ...
Similarity ratio: 0.9941747572815534
N-gram Jaccard (n=4): 0.910448
Entropy mean delta: 0.023438
```

## Tests

```bash
python -m unittest discover -s tests
```

## Live Lab Test Plan

1. Run `--demo` offline and verify exit code 0
2. Compare two compiled `.o` files from `gcc -c` and verify real diffs
3. Compare a file against itself and verify ratio 1.0 / identical true
4. Compare files of different lengths and verify length diff detection
5. Verify entropy deltas identify changed regions
6. Compare md5sum output against tool's hash output

## Metrics

- Zero external dependencies (stdlib only)
- Multiple independent diff techniques (hashes, bytes, n-grams, entropy)
- N-gram Jaccard similarity for code-level comparison
- Instruction normalization for register-variant insensitivity
- Validated on real gcc-compiled objects
- Deterministic offline fixture comparison

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the system owner before using this tool
- Compare only binaries you own or have authorization to analyze
- This tool should ONLY be used on files you have written authorization for

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **State Laws**: Many states have additional computer crime statutes

### Acceptable Use
- Malware triage and binary similarity analysis
- Patch diffing for authorized security assessments
- Academic research and education
- Reverse engineering for your own software

### Prohibited Use
- Diffing binaries belonging to others without authorization
- Using findings to facilitate unauthorized access
- Any activity that violates applicable laws or regulations

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
