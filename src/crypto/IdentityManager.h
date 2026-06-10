#ifndef QUILL_IDENTITYMANAGER_H
#define QUILL_IDENTITYMANAGER_H

#include "DilithiumSign.h"
#include <filesystem>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;

// ── IdentityManager ───────────────────────────────────────────────
// Trwała tożsamość: para kluczy podpisu (ML-DSA / Falcon) generowana raz
// i zapisywana na dysku, ładowana przy każdym kolejnym starcie.
// Stabilna tożsamość jest warunkiem koniecznym sensownego TOFU.
//
// Model bezpieczeństwa:
//  - katalog tożsamości aktywowany przez profil (ProfileManager) lub
//    fallback: $QUILL_IDENTITY_DIR / ~/.quill/identity (chmod 0700)
//  - plik klucza: chmod 0600, zapis atomowy (tmp + rename)
//  - odmowa wczytania klucza o zbyt szerokich uprawnieniach (jak OpenSSH)
//  - self-test sign/verify po wczytaniu — uszkodzony klucz = wyjątek, nie
//    cicha regeneracja (cicha podmiana tożsamości maskowałaby atak)
//  - format QID2: klucz szyfrowany at rest (Argon2id + AES-256-GCM);
//    pusty passphrase => format QID1 (plaintext, 0600) — known limitation
//  - plik QID1 przy aktywnym passphrasie jest po wczytaniu automatycznie
//    podnoszony do QID2 (migracja w miejscu)
class IdentityManager {
public:
    // Aktywuje katalog tożsamości + passphrase (pusty = klucze plaintext).
    // Czyści cache poprzedniego profilu.
    static void activate(const std::filesystem::path& dir,
                         const std::string& passphrase);

    // Wylogowanie: czyści passphrase i klucze tajne z pamięci (cleanse).
    static void deactivate();

    // Zwraca trwałą parę kluczy podpisu dla poziomu bezpieczeństwa.
    // Pierwsze wywołanie generuje i zapisuje klucz; kolejne ładują z dysku
    // (wynik jest cache'owany w pamięci na czas życia procesu).
    // Rzuca std::runtime_error przy uszkodzonym pliku, złych uprawnieniach
    // lub błędnym passphrasie (GCM tag mismatch).
    static SignatureKeyPair load_or_generate(const std::string& level);

    // Fingerprint klucza publicznego: SHA-3-256, pierwsze 12 bajtów,
    // format do weryfikacji out-of-band: "A3F2-9C1B-44DE-F021-8B3C-7A09"
    static std::string fingerprint(const Bytes& public_key);

    // Aktywny katalog tożsamości (lub fallback z env/HOME)
    static std::filesystem::path identity_dir();
};

#endif // QUILL_IDENTITYMANAGER_H
