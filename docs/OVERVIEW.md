# Quill — przegląd stanu projektu

## Czym jest Quill

Post-kwantowy komunikator P2P w C++23. Cała asymetria oparta na standardach NIST (FIPS 203/204), zero klasycznej kryptografii (RSA/ECDH). Interfejs w ImGui, transport TCP, kryptografia z liboqs + OpenSSL.

---

## Architektura

```
main.cpp  →  ChatApp (UI/logika)  →  quill_core (biblioteka statyczna)
                                        ├── crypto/    PQC, KDF, tożsamość, zaufanie
                                        ├── network/   gniazda TCP, framing
                                        └── protocol/  wiadomości, transfer plików
```

Kluczowa decyzja: **`quill_core` nie zależy od UI**. Dzięki temu testy linkują się z tą samą biblioteką co aplikacja, a logika krypto jest odseparowana od ImGui.

| Moduł | Odpowiedzialność |
|---|---|
| `CryptoManager` | orkiestracja całego handshake (klient+serwer), spina KEM/DSA/HKDF/TOFU/tożsamość |
| `KyberKEM` | ML-KEM 512/768/1024 — wymiana klucza (efemeryczna, PFS) |
| `DilithiumSign` | ML-DSA-65/87 + Falcon-512 — podpisy |
| `Hkdf` | HKDF-SHA256 — wyprowadzenie klucza sesji |
| `AesGcm` | AES-256-GCM — szyfrowanie sesji i chunków plików |
| `Argon2` | Argon2id — KDF z passphrase'a (tylko klucze na dysku) |
| `IdentityManager` | trwałe klucze DSA, format QID1/QID2, self-test |
| `ProfileManager` | profile lokalne, logowanie, `profile.json` |
| `TrustStore` | TOFU / `known_hosts`, stany zaufania |
| `FileTransfer` | chunking 64 KB, SHA-3-256 |

---

## Jak to działa

### 1. Logowanie (lokalne odblokowanie tożsamości)
Profil = katalog `~/.quill/profiles/<nazwa>/`. Klucz DSA leży zaszyfrowany (Argon2id → klucz AES → AES-256-GCM). Złe hasło = nieudana weryfikacja tagu GCM. To **nie jest** uwierzytelnienie wobec sieci — to odblokowanie klucza na tym urządzeniu (model Signal/ssh).

### 2. Handshake (`CryptoManager`)

```
KLIENT                                    SERWER
  │                                         │  Kyber keygen (efemeryczny)
  │                                         │  DSA z dysku (trwały)
  │◄──── SRV_HELLO: pub_kyber, pub_dsa, sig(pub_kyber)
  │  verify(sig)            ← ZAWSZE przed użyciem materiału KEM
  │  TOFU check             ← fail-closed PRZED encaps przy MISMATCH
  │  KEM encaps → (ct, ss)
  │  sig(ct)                ← trwałą tożsamością
  │───── CLI_KEX: ct, pub_dsa, sig(ct) ────►│
  │                                          │  verify(sig)
  │                                          │  TOFU remember (cli:fingerprint)
  │                                          │  KEM decaps → ss
  │  AES_key = HKDF(ss, salt=pub_kyber‖ct, info="...v1|LEVEL")
  │                                          │  (identyczny transkrypt → identyczny klucz)
  │═════════ AES-256-GCM: nonce(12B) ‖ ct ‖ tag(16B) ═══════│
```

Inwarianty wymuszane w warstwie krypto, nie w UI:
- `verify()` zawsze przed `encaps`/`decaps`
- przy zmianie klucza serwera połączenie zrywane **zanim** klient wyśle ciphertext
- surowy `shared_secret` nigdy nie jest kluczem sesji (HKDF) i jest czyszczony (`OPENSSL_cleanse`)

### 3. TOFU
Pierwszy kontakt → `UNVERIFIED` (klucz zapamiętany). Ten sam klucz → `KNOWN`. Po porównaniu fingerprintu out-of-band → `VERIFIED`. Inny klucz → `MISMATCH` (blokada, wpis nietknięty, wyjście tylko przez świadome Remove). Porównanie po pełnym SHA-3-256; skrócony fingerprint `A3F2-9C1B-…` tylko do wyświetlania.

### 4. Forward Secrecy
Nowa para Kyber na każdy handshake; rotacja na żądanie bez zrywania TCP. Tożsamość DSA stała, materiał klucza efemeryczny.

### 5. Transfer plików
Plik → chunki 64 KB → każdy szyfrowany osobno (unikalny nonce) → SHA-3-256 całości w `FILE_END`. Odbiorca składa i weryfikuje hash przed zapisem (fail-fast).

---

## Stan jakości

- **91 testów** (Google Test): wektory RFC 5869 / NIST SHA-3, tamper AES-GCM + AAD (anty-replay), Kyber/Dilithium wszystkie poziomy, scenariusze ataku na TOFU, korupcja kluczy, integracyjny handshake przez `socketpair`.
- Testy wykryły 2 realne błędy (martwy `SecureMessage`, brak detekcji korupcji QID1) — naprawione.
- Build czysty, wszystko z prezentacji jest w kodzie.

---

## Słabe punkty / dług (uczciwy obraz)

| Obszar | Problem | Waga |
|---|---|---|
| ~~**Replay**~~ | ✅ **NAPRAWIONE** — CHAT ma numery sekwencji per kierunek wiązane przez AAD GCM; odbiorca odrzuca seq≤ostatni (fail-closed), reset przy rotacji PFS | ~~bezpieczeństwo~~ |
| **E2E vs hub** | architektura to przekaźnik: serwer odszyfrowuje od nadawcy i re-szyfruje per odbiorca → serwer widzi plaintext (świadoma decyzja, nie bug — wymaga redesignu pod prawdziwe E2E) | bezpieczeństwo/architektura |
| ~~**Replay (pliki)**~~ | ✅ **NAPRAWIONE** — `FILE_CHUNK` wiązany przez AAD `FILE\|tid\|index` (sender, odbiorca, relay serwera) | ~~bezpieczeństwo~~ |
| ~~**Bug serwera**~~ | ✅ **NAPRAWIONE** — auto-rotacja PFS przez `pending_pfs_rotation` + handshake w wątku handlera | ~~poprawność~~ |
| **Build** | `third_party/imgui` poza repo → świeży clone się nie zbuduje | proces |
| **Wątki** | `m_security_level`, `m_msg_count` współdzielone bez pełnej synchronizacji | poprawność |
| ~~**Identity at rest**~~ | ✅ **NAPRAWIONE** — nowe profile: min. 8 znaków, odrzucenie `aaaaaaaa`-style, zawsze QID2 | ~~bezpieczeństwo~~ |
| **Protokół** | brak wersjonowania komunikatów / negocjacji; sztywne typy JSON | architektura |
| **CI** | brak automatycznego buildu + testów | proces |

> Uwaga: sprzątanie martwych połączeń jednak działa (`server_client_handler` usuwa klienta z `m_clients`/`m_rooms` po rozłączeniu) — pozycja usunięta z listy.

---

## Co rozważyć dalej

Pogrupowane wg charakteru:

- **Twardy security:** ✅ ochrona przed replay + AAD w GCM (zrobione dla CHAT); dalej: AAD dla chunków plików, wymóg niepustego passphrase'a, opcjonalne szyfrowanie pamięci klucza w RAM, ewentualny prawdziwy E2E (zamiast hub-and-spoke).
- **Poprawność/stabilność:** fix crasha auto-rotacji serwera, uporządkowanie współbieżności (atomiki/mutexy na współdzielonym stanie).
- **Proces/jakość:** `third_party/imgui` jako submoduł, GitHub Actions (build + `ctest`), sanitizery (ASan/UBSan) w trybie debug.
- **Architektura (pod pracę inżynierską):** wersjonowanie protokołu, automatyczny dobór poziomu PQC (temat pracy) — np. heurystyka FAST/BALANCED/MAX zależna od warunków.
- **Funkcje:** selective repeat w transferze plików, SHA-3 per chunk, NAT traversal (UDP hole punching + rendezvous).
