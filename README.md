# M10 — Binary Diff Tool

Compares binary files byte-by-byte with hashing and entropy analysis.

## Overview

This project compares two binary files and reports:
- MD5/SHA1/SHA256 hash comparison
- Byte-by-byte differences with offsets
- Similarity ratio (difflib)
- Per-block Shannon entropy comparison
- Hex diff window for visual inspection

## Features

- **Hash comparison**: detect identical files
- **Byte diff**: list every differing offset
- **Entropy comparison**: spot obfuscated/encrypted regions
- **Similarity ratio**: quantify how similar files are
- **Hex window**: quick visual sanity check

## Usage

```bash
python3 bin_diff.py original.bin modified.bin
```

## Example Output

```
=== M10 - Binary Diff Tool ===
File A: original.bin (4096 bytes)
File B: modified.bin (4098 bytes)

-- Hashes --
  MD5 A: 5d41402abc4b2a76b9719d911017c592
  ...

Total differing offsets: 3
  @0x0400 A=90  B=cc
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
