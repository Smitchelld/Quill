#ifndef QUILL_PROFILEMANAGER_H
#define QUILL_PROFILEMANAGER_H

#include <filesystem>
#include <string>
#include <vector>

// ── ProfileManager ────────────────────────────────────────────────
// Profil lokalny = tożsamość kryptograficzna:
//   ~/.quill/profiles/<nazwa>/
//   ├── profile.json   # display name, fingerprint (jawny), encrypted flag
//   ├── identity/      # klucze DSA (QID1/QID2) per algorytm
//   └── known_hosts    # (przyszłe TOFU)
//
// "Logowanie" = lokalne odblokowanie tożsamości passphrase'em.
// NIE jest to uwierzytelnienie wobec sieci — to robi podpis ML-DSA
// w handshake'u. Passphrase chroni wyłącznie klucz na dysku.
struct ProfileInfo {
    std::string           name;
    std::string           fingerprint; // jawny (klucz publiczny), z profile.json
    bool                  encrypted = false;
    std::filesystem::path dir;
};

class ProfileManager {
public:
    static constexpr size_t MIN_PASSPHRASE_LEN = 8;

    // $QUILL_PROFILES_DIR lub ~/.quill/profiles
    static std::filesystem::path profiles_root();

    static std::vector<ProfileInfo> list();

    // Tworzy profil i od razu generuje tożsamość BALANCED (dzięki temu
    // przy logowaniu jest co weryfikować passphrase'em).
    // Passphrase: min. MIN_PASSPHRASE_LEN znaków, nie może być jednym powtarzanym znakiem.
    // Klucze zawsze szyfrowane (QID2).
    // Rzuca std::runtime_error: zła nazwa / słaby passphrase / profil istnieje / błąd krypto.
    static ProfileInfo create(const std::string& name, const std::string& passphrase);

    // Odblokowuje profil: aktywuje IdentityManager i weryfikuje passphrase
    // przez odszyfrowanie + self-test klucza BALANCED.
    // Błędny passphrase => std::runtime_error (GCM tag mismatch).
    static ProfileInfo unlock(const std::string& name, const std::string& passphrase);

    // Wylogowanie: czyści klucze i passphrase z pamięci.
    static void logout();
};

#endif // QUILL_PROFILEMANAGER_H
