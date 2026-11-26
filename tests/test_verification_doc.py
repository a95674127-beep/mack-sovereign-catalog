import os
import re
import sys
import hashlib
import subprocess

def test_verification_doc(repo_root):
    print(f"=== Running Lightweight Verification & Doc Consistency Test ===")
    print(f"Target repository directory: {repo_root}")
    
    checksums_path = os.path.join(repo_root, "checksums.sha256")
    doc_path = os.path.join(repo_root, "VERIFICATION.md")
    
    if not os.path.isfile(checksums_path):
        raise FileNotFoundError(f"Missing checksums.sha256 at {checksums_path}")
    if not os.path.isfile(doc_path):
        raise FileNotFoundError(f"Missing VERIFICATION.md at {doc_path}")
        
    # 1. Parse checksums.sha256
    canonical_checksums = {}
    with open(checksums_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                canonical_checksums[parts[1].strip()] = parts[0].strip().lower()

    print(f"\n[Check 1] Validating checksums.sha256 against repository files ({len(canonical_checksums)} entries)...")
    computed_hashes = {}
    computed_sizes = {}
    for filename, expected_hash in canonical_checksums.items():
        filepath = os.path.join(repo_root, filename)
        if not os.path.isfile(filepath):
            raise AssertionError(f"Package file listed in checksums.sha256 missing on disk: {filename}")
        
        hasher = hashlib.sha256()
        size = os.path.getsize(filepath)
        with open(filepath, "rb") as bf:
            while chunk := bf.read(65536):
                hasher.update(chunk)
        calc_hash = hasher.hexdigest().lower()
        computed_hashes[filename] = calc_hash
        computed_sizes[filename] = size
        
        if calc_hash != expected_hash:
            raise AssertionError(f"Hash mismatch for {filename}:\n  Expected: {expected_hash}\n  Got:      {calc_hash}")
        print(f"  ✓ {filename} ({size} bytes): {calc_hash[:16]}... OK")

    # 2. Parse VERIFICATION.md Reference Table (Section 2)
    print(f"\n[Check 2] Validating VERIFICATION.md Section 2 reference table...")
    with open(doc_path, "r", encoding="utf-8") as f:
        doc_content = f.read()

    # Regex to capture Markdown table rows:
    # | **MACK-01** | `aegis-seal-main.zip` | 37,481 bytes | `f124...` | **CLEAN** | `#0001` |
    table_pattern = re.compile(
        r"\|\s*\*\*([^*]+)\*\*\s*\|\s*`([^`]+)`\s*\|\s*([0-9,]+)\s*bytes\s*\|\s*`([0-9a-fA-F]{64})`\s*\|\s*\*\*([^*]+)\*\*\s*\|\s*`([^`]+)`\s*\|"
    )
    
    matches = table_pattern.findall(doc_content)
    if not matches:
        raise AssertionError("Failed to parse Section 2 Verification Digest Reference Table in VERIFICATION.md")
    
    print(f"  Found {len(matches)} artifact entries in reference table:")
    for catalog_id, filename, size_str, hash_str, status, ingress in matches:
        clean_size = int(size_str.replace(",", ""))
        clean_hash = hash_str.lower()
        
        if filename not in canonical_checksums:
            raise AssertionError(f"Reference table lists unknown file: {filename}")
        
        # Verify size matches actual
        actual_size = computed_sizes[filename]
        if clean_size != actual_size:
            raise AssertionError(
                f"Documented size mismatch for {filename} ({catalog_id}):\n"
                f"  Table:  {clean_size} bytes\n"
                f"  Actual: {actual_size} bytes"
            )
            
        # Verify hash matches canonical
        actual_hash = computed_hashes[filename]
        if clean_hash != actual_hash:
            raise AssertionError(
                f"Documented hash mismatch for {filename} ({catalog_id}):\n"
                f"  Table:  {clean_hash}\n"
                f"  Actual: {actual_hash}"
            )
        print(f"  ✓ [{catalog_id}] {filename}: Size={clean_size}B, Hash={clean_hash[:16]}..., Status={status}, Ingress={ingress} matches disk")

    # 3. Check Section 4 Sample Outputs
    print(f"\n[Check 3] Validating Section 4 sample command outputs...")
    
    # 3a. Batch run output check
    batch_pattern = re.compile(r"#### ✅ Successful Batch Run.*?```text\n(.*?)```", re.DOTALL)
    batch_match = batch_pattern.search(doc_content)
    if not batch_match:
        raise AssertionError("Missing Section 4.1 'Successful Batch Run' sample code block")
    
    batch_text = batch_match.group(1)
    for filename in canonical_checksums:
        expected_line = f"{filename}: OK"
        if expected_line not in batch_text:
            raise AssertionError(f"Batch sample output missing line: {expected_line}")
    print("  ✓ Section 4.1 batch success sample lines match expected 'filename: OK' for all artifacts")

    # 3b. Linux sha256sum sample output
    linux_sample_pattern = re.compile(r"#### ✅ Linux `sha256sum` \(Success\).*?```text\n(.*?)```", re.DOTALL)
    linux_match = linux_sample_pattern.search(doc_content)
    if linux_match:
        linux_text = linux_match.group(1)
        expected_sample = f"{computed_hashes['aegis-seal-main.zip']}  aegis-seal-main.zip"
        if expected_sample not in linux_text:
            raise AssertionError(f"Linux sample output mismatch. Expected:\n  {expected_sample}\nGot block:\n{linux_text}")
        print("  ✓ Linux sha256sum sample matches canonical hash")

    # 3c. macOS shasum sample output
    mac_sample_pattern = re.compile(r"#### ✅ macOS `shasum -a 256` \(Success\).*?```text\n(.*?)```", re.DOTALL)
    mac_match = mac_sample_pattern.search(doc_content)
    if mac_match:
        mac_text = mac_match.group(1)
        expected_sample = f"{computed_hashes['ai-infinity-force-one-vault-main.zip']}  ai-infinity-force-one-vault-main.zip"
        if expected_sample not in mac_text:
            raise AssertionError(f"macOS sample output mismatch. Expected:\n  {expected_sample}\nGot block:\n{mac_text}")
        print("  ✓ macOS shasum sample matches canonical hash")

    # 3d. PowerShell sample output
    ps_sample_pattern = re.compile(r"#### ✅ Windows PowerShell \(Success\).*?```powershell\n(.*?)```", re.DOTALL)
    ps_match = ps_sample_pattern.search(doc_content)
    if ps_match:
        ps_text = ps_match.group(1)
        expected_hash_upper = computed_hashes['Gen2-Mack-Stack-main.zip'].upper()
        if expected_hash_upper not in ps_text:
            raise AssertionError(f"PowerShell sample output mismatch. Expected uppercase hash:\n  {expected_hash_upper}\nGot block:\n{ps_text}")
        print("  ✓ Windows PowerShell sample matches canonical uppercase hash")

    # 3e. Python sample output
    py_sample_pattern = re.compile(r"#### ✅ Python 3 Verifier Output \(Success\).*?```text\n(.*?)```", re.DOTALL)
    py_match = py_sample_pattern.search(doc_content)
    if py_match:
        py_text = py_match.group(1)
        expected_hash = computed_hashes['smart-flow-pump-system-main.zip']
        if expected_hash not in py_text:
            raise AssertionError(f"Python sample output mismatch. Expected hash:\n  {expected_hash}\nGot block:\n{py_text}")
        print("  ✓ Python 3 verifier sample matches canonical hash")

    print("\n✅ ALL CHECKS PASSED: Sample hashes, file sizes, and command outputs in VERIFICATION.md match repository files perfectly.")
    return 0

if __name__ == "__main__":
    repo_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    sys.exit(test_verification_doc(repo_dir))
