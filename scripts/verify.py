#!/usr/bin/env python3
"""
MACK Sovereign Catalog - Cryptographic Verification Utility
Implements Section 3.D and batch verification from VERIFICATION.md.
"""
import sys
import os
import hashlib

def verify_file(filepath, expected_sha256):
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    calculated = hasher.hexdigest().lower()
    match = (calculated == expected_sha256.lower())
    print(f"File       : {filepath}")
    print(f"Calculated : {calculated}")
    print(f"Expected   : {expected_sha256.lower()}")
    print(f"Verdict    : {'MATCH (CLEAN/SEALED)' if match else 'MISMATCH (QUARANTINE)'}")
    return match

def verify_manifest(manifest_path="checksums.sha256"):
    if not os.path.isfile(manifest_path):
        print(f"Error: Manifest '{manifest_path}' not found.", file=sys.stderr)
        return False

    all_passed = True
    base_dir = os.path.dirname(manifest_path) or "."
    with open(manifest_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                continue
            expected_hash, filename = parts[0].strip(), parts[1].strip()
            target_path = os.path.join(base_dir, filename)
            if not os.path.isfile(target_path):
                print(f"{filename}: FAILED open or read (File not found)")
                all_passed = False
                continue
            if verify_file(target_path, expected_hash):
                print(f"{filename}: OK\n")
            else:
                print(f"{filename}: FAILED (Checksum Mismatch)\n")
                all_passed = False

    return all_passed

if __name__ == "__main__":
    if len(sys.argv) == 1:
        success = verify_manifest("checksums.sha256")
        sys.exit(0 if success else 1)
    elif len(sys.argv) == 3:
        success = verify_file(sys.argv[1], sys.argv[2])
        sys.exit(0 if success else 1)
    elif len(sys.argv) == 2 and sys.argv[1].endswith(".sha256"):
        success = verify_manifest(sys.argv[1])
        sys.exit(0 if success else 1)
    else:
        print("Usage:")
        print("  python3 scripts/verify.py                     # Verify checksums.sha256 in current dir")
        print("  python3 scripts/verify.py <manifest.sha256>   # Verify specific manifest")
        print("  python3 scripts/verify.py <file> <sha256>     # Verify single file")
        sys.exit(2)
