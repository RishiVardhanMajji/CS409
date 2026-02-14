# Cryptanalysis & Secure Design

This repository contains a suite of cryptographic exploits and protocol analyses. The project focuses on identifying vulnerabilities in cryptographic implementations and engineering practical exploits to recover keys and plaintexts.

## 🛡️ Key Exploits & Technical Highlights

### 1. ECDSA Nonce Reuse & Private Key Recovery
* **Vulnerability:** Exploited the critical flaw where a nonce ($k$) is repeated across multiple signatures.
* **Attack:** Implemented a mathematical recovery of the nonce and the signer's private key ($d$) using the relation $k = (z_1 - z_2) \cdot (s_1 - s_2)^{-1} \pmod n$.
* **Relevance:** Direct simulation of a high-impact vulnerability in transaction signing protocols.

### 2. Merkle Tree Proof & Subtree Brute-forcing
* **Vulnerability:** Targeted a Merkle tree implementation allowing limited proof queries ($n/4$).
* **Attack:** Engineered a recovery system that leverages sibling leaf hashes and 2-byte subtree hashes to brute-force unknown flag segments.
* **Relevance:** Demonstrates understanding of Merkle trees, the foundational data structure for block headers and SPV (Simplified Payment Verification).

### 3. Timing Side-Channel Attack on HMAC
* **Vulnerability:** Exploited insecure byte-by-byte string comparison in MAC validation which leaks timing information via early-exit behavior.
* **Attack:** Developed a statistical timing attack that measures response latency (approx. 1s per correct byte) to reconstruct the correct MAC hex-digest prefix.

### 4. Padding Oracle Attack (CBC Mode)
* **Vulnerability:** Targeted AES-128 in CBC mode where the server leaks PKCS#7 padding validity.
* **Attack:** Built a forged-block decryption engine that recovers intermediate states ($I = D_K(C)$) and subsequent plaintexts byte-by-byte.

### 5. EdDSA & Digital Signature Forgeries
* **Deterministic Nonce Attack:** Recovered private keys from an EdDSA variant where $k$ was poorly derived as $H(m \parallel P_K.x)$.
* **Prefix Collision:** Exploited a variant where the nonce depended only on the first half of the message, allowing for signature forgery via nonce reuse.

### 6. Meet-in-the-Middle (Grover's Cipher)
* **Vulnerability:** 32-bit (4-byte) message space vulnerable to space-time tradeoff.
* **Attack:** Implemented a meet-in-the-middle attack using lookup tables to reduce complexity from $2^{32}$ to $2 \cdot 2^{16}$, significantly accelerating the search.

## 🛠️ Skills & Tools Demonstrated
* **Protocols & Algorithms:** RSA-OAEP, AES (CBC, ECB, CTR), HMAC, ECDSA, EdDSA, Merkle Trees.
* **Attacks:** Timing Side-Channels, Padding Oracles, Birthday Attacks on Merkle-Damgård, Length Extension.
* **Tooling:** OpenSSL (symmetric/asymmetric workflows), Python (Cryptodome, hashlib).


---
**Author:** Rishi Vardhan Majji
**Academic Guide:** Prof. Sruthi Sekar
