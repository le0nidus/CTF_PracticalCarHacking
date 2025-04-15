# 🔓 CTF Writeup: CRC Cracking & Hitag2 RKE Attack

This repository documents my work on a CTF challenge focused on reverse-engineering and cryptographic attacks involving CRC and the Hitag2 Remote Keyless Entry (RKE) protocol.

> 🧩 **CTF Challenge Link**: [CTF Challenge Page](#)  
> *(Replace `#` with the actual link once available)*

---

## 💡 Challenge Overview

The challenge consisted of two main components:

### 1. **CRC Challenge**
- Given a CRC-based authentication mechanism
- The goal was to reverse the logic or brute-force CRC values to forge valid messages
- Implemented a script to:
  - Analyze the CRC structure
  - Filter viable inputs
  - Reconstruct messages that produce a given CRC

### 2. **Hitag2 RKE Analysis**
- Focused on a real-world style Hitag2 key fob exchange
- Recovered unique IDs (UIDs) from intercepted frames
- Explored vulnerabilities in the keystream generation
- Wrote tooling to format and feed UIDs into a key-cracking binary (`ht2crack5`)

---

## 🛠 Tools & Scripts

### ✅ `crc_cracker.py`
- Automates CRC reverse analysis
- Supports brute-force and preimage search
- Adaptable to different polynomial configurations

### ✅ `extract_uids.py`
- Parses intercepted RKE packets
- Filters relevant frames
- Extracts and prints UIDs in format for cracking

Example output:
```bash
./ht2crack5 0xAABBCCDD 0x11223344
