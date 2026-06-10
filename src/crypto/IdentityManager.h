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
//  - katalog tożsamości: $QUILL_IDENTITY_DIR lub ~/.quill/identity (chmod 0700)
//  - plik klucza: chmod 0600, zapis atomowy (tmp + rename)
//  - odmowa wczytania klucza o zbyt szerokich uprawnieniach (jak OpenSSH)
//  - self-test sign/verify po wczytaniu — uszkodzony klucz = wyjątek, nie
//    cicha regeneracja (cicha podmiana tożsamości maskowałaby atak)
//  - klucz tajny NIE jest szyfrowany na dysku (poza zakresem projektu,
//    udokumentowane jako known limitation)
class IdentityManager {
public:
    // Zwraca trwałą parę kluczy podpisu dla poziomu bezpieczeństwa.
    // Pierwsze wywołanie generuje i zapisuje klucz; kolejne ładują z dysku
    // (wynik jest cache'owany w pamięci na czas życia procesu).
    // Rzuca std::runtime_error przy uszkodzonym pliku lub złych uprawnieniach.
    static SignatureKeyPair load_or_generate(const std::string& level);

    // Fingerprint klucza publicznego: SHA-3-256, pierwsze 12 bajtów,
    // format do weryfikacji out-of-band: "A3F2-9C1B-44DE-F021-8B3C-7A09"
    static std::string fingerprint(const Bytes& public_key);

    // Katalog przechowywania tożsamości ($QUILL_IDENTITY_DIR lub ~/.quill/identity)
    static std::filesystem::path identity_dir();
};

#endif // QUILL_IDENTITYMANAGER_H
