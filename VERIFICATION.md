# MACK Verification Guide & Cryptographic Digest Specification

**Publisher:** Allen Mack / AI Infinity Force One Sovereign Authority  
**Repository:** `a95674127-beep/mack-sovereign-catalog`  
**Standards:** NIST SP 800-207 Zero-Trust Architecture | FIPS 180-4 Secure Hash Standard (SHA-256)  
**Classification:** Non-ITAR / Unclassified / Public Verification Specification  

---

## 1. Overview & Verification Purpose

This guide provides independent auditors, defense evaluators, security researchers, and system integrators with explicit instructions for:
1. **Reproducing cryptographic verification checks** on all MACK sovereign distribution packages (MACK-01 through MACK-05).
2. **Interpreting the 64-character SHA-256 verification digests**, forensic triage verdicts (`CLEAN`, `SEALED`), and sequential ingestion ledger numbers.
3. **Automating integrity verification** across environments using native CLI utilities, PowerShell, Python, and the repository's `checksums.sha256` manifest.
4. **Analyzing terminal command outputs** for both successful verifications and simulated failure modes.
5. **Diagnosing and resolving common verification mismatches** (e.g., CRLF conversions, dynamic archive compression, partial transfers, caching).
6. **Understanding cryptographic boundaries**, separating bit-level archive integrity from runtime execution guarantees and sworn legal chain-of-custody.

---

## 2. Verification Digest Reference Table

Every artifact in the MACK Sovereign Catalog has an immutable SHA-256 cryptographic hash calculated over its exact distribution payload.

| Catalog ID | Package / Artifact Filename | Exact File Size | SHA-256 Verification Digest | Triage Status | Ledger Ingress # |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **MACK-01** | `aegis-seal-main.zip` | 13,858 bytes | `f124e8c30c435610620bd9909388ae6dbee1e075dedf57e72756391f45d3cca1` | **CLEAN** | `#0001` |
| **MACK-02** | `ai-infinity-force-one-vault-main.zip` | 177,354 bytes | `76fa4ccbd76051b06e89d19db68e4375a2036406b62d0eda0576a46ee72ef806` | **CLEAN** | `#0002` |
| **MACK-03A** | `Account_Investigation_Accountability.html` | 26,071 bytes | `a8de55a7934a388004e3372421ad158d7bca3c6f030071bff35e5b52f169b6b6` | **SEALED** | `#0003` |
| **MACK-03B** | `affidavit-allen-mack-2026-11-24.pdf` | 6,488 bytes | `b53b39dbb27e7d70e5619573f98742e03a79201d797b7433fa1f7a2fe84d697f` | **SEALED** | `#0003` |
| **MACK-04** | `Gen2-Mack-Stack-main.zip` | 141,452 bytes | `2083a57a594f72f4a0a0624bb67067c210f11cbc49d637c8eaf9f17307e76481` | **CLEAN** | `#0004` |
| **MACK-05** | `smart-flow-pump-system-main.zip` | 80,578 bytes | `e8ac792a6ffd441625159d04a2b9634fc5208cd61f9aa21fd9d9f74b4d6dfc0f` | **CLEAN** | `#0005` |

---

## 3. How to Reproduce Verification Checks

### A. Linux & BSD (GNU Coreutils)
```bash
sha256sum aegis-seal-main.zip
```

### B. macOS (Terminal)
```bash
shasum -a 256 ai-infinity-force-one-vault-main.zip
```

### C. Windows (PowerShell)
```powershell
Get-FileHash -Algorithm SHA256 .\Gen2-Mack-Stack-main.zip | Format-List
```

### D. Automated Batch Verification (`checksums.sha256`)
```bash
sha256sum -c checksums.sha256
```

### E. Cross-Platform Python 3 Verification Script
```python
import hashlib, sys

def verify_file(filepath, expected_sha256):
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    calculated = hasher.hexdigest().lower()
    match = (calculated == expected_sha256.lower())
    print(f"File: {filepath}")
    print(f"Calculated : {calculated}")
    print(f"Expected   : {expected_sha256.lower()}")
    print(f"Verdict    : {'MATCH (CLEAN/SEALED)' if match else 'MISMATCH (QUARANTINE)'}")
    return match

# Example execution:
verify_file("smart-flow-pump-system-main.zip", "e8ac792a6ffd441625159d04a2b9634fc5208cd61f9aa21fd9d9f74b4d6dfc0f")
```

---

## 4. Sample Successful and Failed Command Output

### 4.1 Batch Verification (`sha256sum -c checksums.sha256`)

#### ✅ Successful Batch Run (All Artifacts Verified)
```text
$ sha256sum -c checksums.sha256
aegis-seal-main.zip: OK
ai-infinity-force-one-vault-main.zip: OK
Account_Investigation_Accountability.html: OK
affidavit-allen-mack-2026-11-24.pdf: OK
Gen2-Mack-Stack-main.zip: OK
smart-flow-pump-system-main.zip: OK

$ echo $?
0
```
*Exit Code `0`: All files exist, are uncorrupted, and match their canonical cryptographic digests bit-for-bit.*

---

#### ❌ Failed Batch Run: Hash Mismatch (Corrupted or Tampered File)
```text
$ sha256sum -c checksums.sha256
aegis-seal-main.zip: OK
ai-infinity-force-one-vault-main.zip: OK
Account_Investigation_Accountability.html: OK
affidavit-allen-mack-2026-11-24.pdf: OK
Gen2-Mack-Stack-main.zip: FAILED
smart-flow-pump-system-main.zip: OK
sha256sum: WARNING: 1 computed checksum did NOT match

$ echo $?
1
```
*Exit Code `1`: `Gen2-Mack-Stack-main.zip` failed digest verification. Immediately flag the file as `QUARANTINE` and halt deployment.*

---

#### ❌ Failed Batch Run: Missing File
```text
$ sha256sum -c checksums.sha256
aegis-seal-main.zip: OK
ai-infinity-force-one-vault-main.zip: OK
Account_Investigation_Accountability.html: OK
affidavit-allen-mack-2026-11-24.pdf: OK
Gen2-Mack-Stack-main.zip: OK
sha256sum: smart-flow-pump-system-main.zip: No such file or directory
smart-flow-pump-system-main.zip: FAILED open or read
sha256sum: WARNING: 1 listed file could not be read

$ echo $?
1
```
*Exit Code `1`: Artifact missing from the working directory. Package bundle incomplete.*

---

### 4.2 Individual Package Checks

#### ✅ Linux `sha256sum` (Success)
```text
$ sha256sum aegis-seal-main.zip
f124e8c30c435610620bd9909388ae6dbee1e075dedf57e72756391f45d3cca1  aegis-seal-main.zip
```

#### ❌ Linux `sha256sum` (Mismatch Example)
```text
$ sha256sum aegis-seal-main.zip
d41d8cd98f00b204e9800998ecf8427e00000000000000000000000000000000  aegis-seal-main.zip
# Alert: Hash does not match catalog value (f124e8c30c435610620bd9909388ae6dbee1e075dedf57e72756391f45d3cca1)
```

---

#### ✅ macOS `shasum -a 256` (Success)
```text
$ shasum -a 256 ai-infinity-force-one-vault-main.zip
76fa4ccbd76051b06e89d19db68e4375a2036406b62d0eda0576a46ee72ef806  ai-infinity-force-one-vault-main.zip
```

#### ❌ macOS `shasum -a 256` (Mismatch Example)
```text
$ shasum -a 256 ai-infinity-force-one-vault-main.zip
a35b8098e945c2f30b982ef20098bcde76051b06e89d19db68e4375a2036406b  ai-infinity-force-one-vault-main.zip
# Alert: Hash mismatch against catalog canonical 76fa4ccbd76051b06e89d19db68e4375a2036406b62d0eda0576a46ee72ef806
```

---

#### ✅ Windows PowerShell (Success)
```powershell
PS C:\MACK\Catalog> Get-FileHash -Algorithm SHA256 .\Gen2-Mack-Stack-main.zip | Format-List

Algorithm : SHA256
Hash      : 2083A57A594F72F4A0A0624BB67067C210F11CBC49D637C8EAF9F17307E76481
Path      : C:\MACK\Catalog\Gen2-Mack-Stack-main.zip

PS C:\MACK\Catalog> (Get-FileHash .\Gen2-Mack-Stack-main.zip).Hash -eq "2083A57A594F72F4A0A0624BB67067C210F11CBC49D637C8EAF9F17307E76481"
True
```

#### ❌ Windows PowerShell (Mismatch Example)
```powershell
PS C:\MACK\Catalog> (Get-FileHash .\Gen2-Mack-Stack-main.zip).Hash -eq "2083A57A594F72F4A0A0624BB67067C210F11CBC49D637C8EAF9F17307E76481"
False
```

---

#### ✅ Python 3 Verifier Output (Success)
```text
$ python3 verify.py smart-flow-pump-system-main.zip
File       : smart-flow-pump-system-main.zip
Calculated : e8ac792a6ffd441625159d04a2b9634fc5208cd61f9aa21fd9d9f74b4d6dfc0f
Expected   : e8ac792a6ffd441625159d04a2b9634fc5208cd61f9aa21fd9d9f74b4d6dfc0f
Verdict    : MATCH (CLEAN/SEALED)
```

#### ❌ Python 3 Verifier Output (Mismatch)
```text
$ python3 verify.py smart-flow-pump-system-main.zip
File       : smart-flow-pump-system-main.zip
Calculated : 9f8a32b610c84138e3a2004fa9d83271bc9802ea741208fb927163cba043e710
Expected   : e8ac792a6ffd441625159d04a2b9634fc5208cd61f9aa21fd9d9f74b4d6dfc0f
Verdict    : MISMATCH (QUARANTINE)
```

---

## 5. Interpreting Each Package's Verification Digest

### What the SHA-256 Digest Proves
1. **Mathematical Immutability:** Any alteration—even a single flipped bit, altered timestamp in an archive header, or appended whitespace—results in an entirely different, uncorrelated 256-bit avalanche hash.
2. **Provenance Authenticity:** Matching digests guarantee the exact archive analyzed and approved under sovereign ingress authority is identical to the file in the evaluator's possession.
3. **Distribution Integrity:** Proves the package has not suffered transit truncation, mirror corruption, or hostile payload injection.

### Package-by-Package Breakdown

#### [MACK-01] Aegis-Seal Cryptographic Sealing Engine
- **Digest:** `f124e8c30c435610620bd9909388ae6dbee1e075dedf57e72756391f45d3cca1`
- **What is Anchored:** The hardened Rust cryptographic core (`src/main.rs`, `src/lib.rs`, `Cargo.toml`).
- **Critical Verification Checks:**
  - Verify `#![forbid(unsafe_code)]` is present across the crate root.
  - Confirm Ed25519 signature routines and zeroize dependencies match the pinned `Cargo.lock`.
  - Check absence of panics or unhandled unwrap paths in production builds.

#### [MACK-02] AI Infinity Force One Sovereign Vault Engine
- **Digest:** `76fa4ccbd76051b06e89d19db68e4375a2036406b62d0eda0576a46ee72ef806`
- **What is Anchored:** The 12-lane detonation matrix and visual threat triage dashboard.
- **Critical Verification Checks:**
  - Inspect Vite/React 19 console build configs and component hierarchy.
  - Verify that backend token handling isolates credentials to server-side environments (`MACK_ENGINE_TOKEN`) rather than client bundle injection.
  - Confirm D-DIL and JAG/S2 ledger indicators conform to audit log specifications.

#### [MACK-03] Forensic Chain-of-Custody Dossier & Sworn Affidavit
- **HTML Digest:** `a8de55a7934a388004e3372421ad158d7bca3c6f030071bff35e5b52f169b6b6`
- **PDF Digest:** `b53b39dbb27e7d70e5619573f98742e03a79201d797b7433fa1f7a2fe84d697f`
- **What is Anchored:** Formal legal instruments executed under penalty of perjury (Levy County, Florida) detailing forensic account takeover timelines, carrier logs, and constitutional infringement records.
- **Critical Verification Checks:**
  - Verify zero-tracking, zero-CDN offline self-containment of the HTML hearing file.
  - Verify cryptographic immutability of the PDF document without redactions or trailing metadata injection.

#### [MACK-04] Gen 2 MACK-Stack Sovereign Security Runtime
- **Digest:** `2083a57a594f72f4a0a0624bb67067c210f11cbc49d637c8eaf9f17307e76481`
- **What is Anchored:** Enclave boundaries, zero-trust token validators, and microservice compartmentalization primitives.
- **Critical Verification Checks:**
  - Validate isolation policies and safe inter-process communication contracts.
  - Check Landlock LSM / seccomp profile definitions and least-privilege capability masks.

#### [MACK-05] SF-ITES Smart-Flow Critical Infrastructure IoT Controller
- **Digest:** `e8ac792a6ffd441625159d04a2b9634fc5208cd61f9aa21fd9d9f74b4d6dfc0f`
- **What is Anchored:** Dual-stage edge protection: ESP32 bare-metal C++ firmware with hardware relay cutoff, Raspberry Pi Python gateway, and Rust `sim/pump_guard` digital twin core.
- **Critical Verification Checks:**
  - Inspect firmware relay trip logic (ensuring dry-run and electrical overload triggers instant physical cutoff).
  - Verify Ed25519 telemetry signing format on edge sensor readings.
  - Inspect local SQLite encrypted buffering mechanisms on the gateway.

---

## 6. How to Resolve Common Verification Mismatches

When a calculated hash differs from the canonical catalog digest, follow this structured diagnostic protocol before escalating:

| Root Cause | Diagnostic Indicator | Technical Explanation | Concrete Resolution Step |
| :--- | :--- | :--- | :--- |
| **Git Line-Ending Normalization (CRLF vs LF)** | Affects `Account_Investigation_Accountability.html` (text/HTML file). Size changes by a few hundred bytes. | Git on Windows with `core.autocrlf = true` or `text=auto` replaces LF (`\n`) with CRLF (`\r\n`), altering every line ending and destroying the hash. | Configure Git before checkout: <br>`git config core.autocrlf false`<br>`git checkout -- Account_Investigation_Accountability.html`<br>Or download raw binary without git conversion: `curl -L -O <raw_url>`. |
| **Dynamic GitHub Archive Regeneration** | Affects `.zip` archives downloaded via `github.com/.../archive/refs/tags/...`. | GitHub dynamically generates ZIP archives on the fly. Zip file headers contain variable timestamps and file order, altering the package hash even if file contents are identical. | **Do not use dynamic GitHub archive URLs.** Verify only the specific distribution release ZIP assets uploaded by the Ingress Authority or mirrored in the sovereign release ledger. |
| **Incomplete / Interrupted Download** | File size is smaller than the exact byte size listed in the table (e.g., 50,000 bytes instead of 177,354 bytes). | Network dropouts, proxy truncation, or browser timeouts resulted in a partial file download. | Check exact file size: <br>`ls -l <filename>` (Linux/macOS) or `(Get-Item <filename>).Length` (PowerShell). Redownload via `curl -C - -O <url>` to resume/verify completion. |
| **Browser Auto-Unpacking / Renaming** | Filename is `filename (1).zip` or archive is automatically unzipped into a folder (e.g., macOS Safari "Open safe files after downloading"). | Browser utilities modify file structures or append duplicate counters to filename headers. | Disable automatic extraction in browser preferences. Download using CLI (`curl -O` or `wget`) to prevent browser tampering. |
| **Proxy / Gateway CDN Cache Pollution** | Consistent hash mismatch across multiple retries from the same network. | An enterprise forward proxy, corporate antivirus SSL inspection, or stale CDN edge is returning a cached or sanitized file. | Bypass proxy caching with cache-busting headers: <br>`curl -H "Cache-Control: no-cache" -L -O <url>`. Alternatively, download via secondary verified cellular or isolated network. |
| **True Unauthorized Tampering / Corruption** | File size matches, download was clean, line endings unchanged, but SHA-256 hash completely differs. | The file has been modified, backdoored, injected with foreign payloads, or corrupted on disk. | **DO NOT EXECUTE.** <br>1. Mark status as **QUARANTINE**.<br>2. Move file to an isolated quarantine folder.<br>3. Log mismatch in the audit ledger.<br>4. Re-fetch from the authoritative sovereign repository. |

### Diagnostic Decision Tree

```text
[Calculated Hash != Catalog Digest]
   │
   ├─► Is the file size different from the Catalog Reference Table?
   │     ├─ Yes ──► Check for partial download (redownload with curl/wget)
   │     └─ No  ──► Continue
   │
   ├─► Is it the HTML file on Windows?
   │     ├─ Yes ──► Check line endings: run `dos2unix` or `git config core.autocrlf false`
   │     └─ No  ──► Continue
   │
   ├─► Was it downloaded from a dynamic GitHub "/archive/" link?
   │     ├─ Yes ──► Download the official static release asset, not dynamic git archive
   │     └─ No  ──► Continue
   │
   └─► Size matches, static asset, but hash still fails:
         └─► ⚠️ VERDICT: QUARANTINE. Tamper-evident lock triggered.
```

---

## 7. Triage Status Classification System

| Status Badge | Technical Definition | Operational Action |
| :--- | :--- | :--- |
| **`CLEAN`** | Digest bit-identically matches catalog record; static vulnerability, secret leak, and unsafe code scans report zero findings. | Approved for air-gapped staging, enclave deployment, and technical evaluation. |
| **`SEALED`** | Evidentiary legal record or sworn affidavit; frozen under strict chain-of-custody protocols; no post-execution modifications permitted. | Admissible in legal, regulatory, and oversight proceedings; archived in immutable cold storage. |
| **`QUARANTINE`** | Calculated digest deviates from catalog reference; package exhibits unexpected bytes, missing signatures, or untracked modifications. | Immediate rejection; file must not be executed or loaded into secure environments. |

---

## 8. Verification Boundaries & Explicit Scope

To maintain rigorous zero-trust transparency:
- **Archive Hash vs. Code Execution:** A valid SHA-256 hash guarantees that the file has not been modified since ingress; it does not replace automated test suites, integration tests, or compiler safety proofs.
- **Independent Validation:** While all assets are authored under zero-trust principles, formal compliance badges (e.g. NIST SP 800-207, NIST SP 800-82, Common Criteria) reflect targeted architectural alignment and must be validated by the deploying authority's accreditation board.
- **Public Key Infrastructure:** Ed25519 public keys for signature validation must be obtained directly from verified out-of-band sovereign channels or the official publisher key ledger.

---
*MACK Sovereign Catalog Specification — Maintained by Allen Mack / AI Infinity Force One Sovereign Authority*
