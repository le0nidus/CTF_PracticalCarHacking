# 🔓 CTF Writeup: CRC Cracking & Hitag2 RKE Attack

This repository documents my work on a CTF challenge focused on reverse-engineering and cryptographic attacks involving CRC and the Hitag2 Remote Keyless Entry (RKE) protocol.

> 🧩 **CTF Challenge Link**: [CTF Challenge Page](https://ctf-teaser.icanhack.nl/)  

---

## 💡 Challenge Overview

The challenge consisted of two main components:

### 1. **CRC Challenge** `crc_cracker.py`
- Given a CRC-based authentication mechanism and a stream of 15 messages
- Each message consists of 1 MSB byte of crc, 3 bytes on data
- The CRC is computed on the data and a secret byte that we need to discover its' value
- The goal was to calculate the checksum of a given message
- Implemented a script to:
  - Implement CRC algorithm according to the documentaion
  - Brute force to find the secret byte
  - Calculate the CRC for the given message

### 2. **Hitag2 RKE Analysis** `parseRKE.py`
- Given a real recording of RKE Hitag2 Cipher based keyfob, the goal was to discover the UID and crack the key
- Used URH to decode the bits from the RF signal
- Recovered unique IDs (UIDs) and other fields from the RF packets 
- Formatted the output to be a valid input to a hitag2 crack tool (used [crack5](https://github.com/RfidResearchGroup/proxmark3/tree/master/tools/hitag2crack))


