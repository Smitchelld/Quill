# Quill — przegląd stanu projektu

**Wersja:** 1.0.0 · **Testy:** 97 · **CI:** GitHub Actions (build + ctest)

## Czym jest Quill

Post-kwantowy komunikator P2P w C++23. Cała asymetria oparta na standardach NIST (FIPS 203/204), zero klasycznej kryptografii (RSA/ECDH). Interfejs w ImGui, transport TCP, kryptografia z liboqs + OpenSSL (+ libargon2 na starszym OpenSSL).

---

## Architektura

```
main.cpp  →  ChatApp (UI/logika)  →  quill_core (biblioteka statyczna)
                                        ├── crypto/    PQC, KDF, tożsamość, zaufanie
                                        ├── network/   gniazda TCP, framing
                                        └── protocol/  wiadomości, transfer plików
```

Kluczowa decyzja: **`quill_core` nie zależy od UI**. Testy i CI linkują tę samą bibliotekę co aplikacja.

| Moduł | Odpowiedzialność |
|---|---|
| `CryptoManager` | handshake (klient+serwer), TOFU, HKDF, tożsamość |
| `KyberKEM` | ML-KEM 512/768/1024 — wymiana klucza (efemeryczna, PFS) |
| `DilithiumSign` | ML-DSA-65/87 + Falcon-512 — podpisy |
| `Hkdf` | HKDF-SHA256 — klucz sesji |
| `AesGcm` | AES-256-GCM — sesja i chunki plików (+ AAD) |
| `Argon2` | Argon2id — szyfrowanie kluczy na dysku (OpenSSL ≥3.2 lub libargon2) |
| `IdentityManager` | trwałe klucze DSA, QID1/QID2 |
| `ProfileManager` | profile, logowanie, polityka passphrase |
| `TrustStore` | TOFU / `known_hosts` |
| `FileTransfer` | chunking 64 KB, SHA-3 per chunk + całości, FILE_NACK |

---

## Jak to działa

### 1. Logowanie
Profil = `~/.quill/profiles/<nazwa>/`. Klucz DSA zaszyfrowany Argon2id → AES-256-GCM. To lokalne odblokowanie tożsamości, nie auth sieciowy.

### 2. Handshake
Kyber (efemeryczny) + DSA (trwały) + HKDF + TOFU fail-closed przed KEM encaps przy MISMATCH.

### 3. Czat (CHAT)
AES-256-GCM, AAD=`CHAT|<seq>`, anty-replay fail-closed, reset seq przy PFS.

### 4. Transfer plików

```
FILE_START (metadane)
    → FILE_CHUNK × N
        • AES-256-GCM, unikalny nonce
        • AAD = "FILE|<transfer_id>|<chunk_index>"
        • chunk_hash = SHA3-256(plaintext chunka) — weryfikacja przed buforowaniem
    → FILE_END (SHA3-256 całego pliku)
    → [opcjonalnie] FILE_NACK { missing: [indeksy] } → retransmisja chunków (max 5 rund)
```

Serwer = hub: odszyfrowuje od nadawcy, re-szyfruje per odbiorca (nie E2E).

---

## Stan jakości

- **97 testów** Google Test (quill_core, bez UI)
- **CI** na GitHub Actions: Ubuntu, liboqs + ctest, `QUILL_BUILD_GUI=OFF`
- **ImGui** jako git submodule (`--recurse-submodules`)
- Wszystko z prezentacji zaimplementowane

---

## Znane ograniczenia

| Obszar | Opis | Waga |
|---|---|---|
| **E2E vs hub** | Serwer widzi plaintext (świadoma decyzja) | architektura |
| **NAT** | Tylko TCP; brak hole punching / STUN | funkcja |
| **Protokół** | Brak wersjonowania JSON | architektura |
| **Skala plików** | Cały plik w RAM przy wysyłce | wydajność |

---

## Co dalej (opcjonalnie)

- **NAT traversal** — jedyny duży feature z roadmapy
- **Docker** — obraz pod build + testy (bez GUI)
- **Praca inżynierska** — inteligentny dobór poziomu PQC (FAST/BALANCED/MAX)
- **ASan/UBSan** w CI, prawdziwe E2E — długoterminowo
