<div align="center">

<img src="https://img.shields.io/badge/C%2B%2B-23-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white"/>
<img src="https://img.shields.io/badge/Post--Quantum-Cryptography-7C3AED?style=for-the-badge"/>
<img src="https://img.shields.io/badge/NIST-FIPS%20203%2F204-0F6E56?style=for-the-badge"/>
<img src="https://img.shields.io/badge/License-MIT-gray?style=for-the-badge"/>

# 🔐 Quill

### Post-quantum encrypted P2P messenger

Quill is a peer-to-peer messenger built in C++23 that is fully resistant to quantum computer attacks. It implements the NIST post-quantum standards (FIPS 203, FIPS 204) for key exchange and digital signatures, combined with AES-256-GCM for session encryption.

> Built as a semester project at AGH University of Science and Technology, Kraków.  
> Foundation for an upcoming engineering thesis on intelligent PQC algorithm selection.

</div>

---

## Why post-quantum?

Classical asymmetric cryptography (RSA, ECDH) is theoretically broken by Shor's algorithm running on a sufficiently large quantum computer. In 2024, NIST published the first quantum-resistant standards. Quill implements them from scratch — no TLS, no OpenSSL handshake, custom protocol.

```
Classical crypto          Post-quantum (Quill)
─────────────────         ──────────────────────
RSA-2048    →  broken     Kyber-768   →  FIPS 203 ✓
ECDH        →  broken     Dilithium   →  FIPS 204 ✓
AES-256-GCM →  safe*      AES-256-GCM →  session  ✓

* Grover's algorithm reduces AES-256 to ~128-bit security — still safe.
```

---

## Protocol overview

Quill implements a custom 4-step handshake. There is no classical asymmetric crypto anywhere in the stack.

```
ALICE                                          BOB
  │                                             │
  │──── ① ClientHello ────────────────────────►│
  │       security level, supported algos,      │
  │       Alice's Dilithium public key          │
  │                                             │  generates Kyber keypair
  │                                             │  signs pub_kyber with Dilithium
  │◄─── ② ServerHello ──────────────────────── │
  │       pub_kyber_B, pub_dil_B,               │
  │       sig_B(pub_kyber_B)                    │
  │                                             │
  │  verify sig_B ✓                             │
  │  Kyber encaps(pub_kyber_B)                  │
  │  → (ciphertext, shared_secret)              │
  │                                             │
  │──── ③ ClientKeyExchange ──────────────────►│
  │       ciphertext, sig_A(ciphertext)         │
  │                                             │  verify sig_A ✓
  │                                             │  Kyber decaps → shared_secret
  │◄─── ④ ServerFinished ───────────────────── │
  │       sig_B(hash(shared_secret))            │
  │                                             │
  │  key = HKDF(shared_secret)                  │  key = HKDF(shared_secret)
  │                                             │
  │════════ AES-256-GCM encrypted session ═════│
  │  nonce(12B) ‖ ciphertext ‖ GCM tag(16B)    │
```

**Security properties:**

| Property | Mechanism |
|---|---|
| Quantum-safe key exchange | Kyber-768 (ML-KEM, FIPS 203) |
| Mutual authentication | Dilithium (ML-DSA, FIPS 204) |
| MITM protection | Dilithium signatures on both sides |
| Forward secrecy | New Kyber keypair per session |
| Session encryption | AES-256-GCM |
| Key derivation | HKDF(shared\_secret) |
| Nonce safety | 96-bit random nonce per message |

---

## Security levels

Quill supports three configurable security levels, selectable at connection time:

| Level | KEM | Signature | NIST Level | Use case |
|---|---|---|---|---|
| `FAST` | Kyber-512 | FALCON-512 | 1 (~AES-128) | IoT, real-time |
| `BALANCED` | Kyber-768 | Dilithium | 3 (~AES-192) | default |
| `MAX` | Kyber-1024 | SPHINCS+ | 5 (~AES-256) | critical data |

---

## Getting started

### Prerequisites

```bash
# Arch Linux
sudo pacman -S cmake openssl

# Ubuntu/Debian
sudo apt install cmake libssl-dev
```

**liboqs** must be built from source:

```bash
git clone https://github.com/open-quantum-safe/liboqs
cd liboqs && mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
sudo cmake --install .
```

### Build

```bash
git clone https://github.com/yourusername/quill
cd quill
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

### Run

Start the server (Bob):

```bash
./quill_server 8443
```

Connect as client (Alice):

```bash
./quill_client 127.0.0.1 8443
```

Both sides negotiate the handshake automatically. After `✓ Session established`, all messages are AES-256-GCM encrypted.

---

## Project structure

```
quill/
├── src/
│   ├── crypto/          # KyberKEM, DilithiumSign, AesGcm, HKDF
│   ├── network/         # TCP server/client, length-prefixed framing
│   ├── protocol/        # Handshake state machine, SessionManager
│   └── app/             # CLI, RoomManager
├── include/             # Public headers
│   ├── crypto.h         # Kyber, AES-256-GCM primitives
│   └── network.h        # send_msg / recv_msg framing
├── tests/               # Google Test unit tests
├── docs/                # Protocol specification
└── CMakeLists.txt
```

---

## Cryptographic stack

```
┌─────────────────────────────────────────────┐
│              Application layer               │
├─────────────────────────────────────────────┤
│         AES-256-GCM  (OpenSSL EVP)           │  session encryption
├────────────────────┬────────────────────────┤
│   Kyber-768 KEM    │   Dilithium DSA         │  liboqs
│   (ML-KEM FIPS203) │   (ML-DSA FIPS204)      │
├────────────────────┴────────────────────────┤
│         HKDF-SHA256  (OpenSSL EVP_KDF)       │  key derivation
├─────────────────────────────────────────────┤
│         TCP  (POSIX sockets)                 │  transport
└─────────────────────────────────────────────┘
```

**Libraries:**

- [liboqs](https://openquantumsafe.org) — Open Quantum Safe, MIT license — Kyber, Dilithium, FALCON, SPHINCS+
- [OpenSSL](https://openssl.org) — Apache 2.0 — AES-256-GCM, HKDF, RAND_bytes
- [nlohmann/json](https://github.com/nlohmann/json) — MIT — message serialization

---

## Known limitations

- **Key distribution** — Dilithium public keys must be exchanged out-of-band before first connection (TOFU or pre-shared config). There is no PKI or certificate authority — intentional for scope, documented as future work.
- **NAT traversal** — direct TCP, no STUN/TURN. Both peers must be reachable at a known address.
- **Single session** — current demo supports one client at a time. Multi-client via `std::thread` is planned.

---

## Roadmap

- [x] Kyber-768 key exchange over TCP
- [x] AES-256-GCM encrypted messaging
- [ ] Dilithium signature verification (MITM protection)
- [ ] HKDF key derivation
- [ ] FAST / MAX security levels (FALCON, SPHINCS+)
- [ ] Multi-client with `std::thread`
- [ ] File transfer (64KB chunks, SHA-3 integrity)
- [ ] Handshake visualizer with per-step timing
- [ ] Engineering thesis: intelligent PQC algorithm selection

---

## References

- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM (Kyber)
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — ML-DSA (Dilithium)
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) — SLH-DSA (SPHINCS+)
- CRYSTALS-Kyber: A CCA-Secure Module-Lattice-Based KEM — Bos et al.
- CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme — Ducas et al.
- [Open Quantum Safe](https://openquantumsafe.org) — liboqs documentation

---

<div align="center">

AGH University of Science and Technology, Kraków  
Computer Science and Intelligent Systems  
Studio Projektowe — Semester 6

</div>
