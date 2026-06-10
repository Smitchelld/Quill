#ifndef QUILL_TRUSTSTORE_H
#define QUILL_TRUSTSTORE_H

#include <filesystem>
#include <string>
#include <vector>
#include <cstdint>

using Bytes = std::vector<uint8_t>;

// ── TrustStore (TOFU — Trust On First Use) ────────────────────────
// Model wzorowany na Signal/OpenSSH known_hosts:
//
//  UNVERIFIED — pierwsze połączenie; klucz zapisany, banner ostrzegawczy,
//               komunikacja możliwa, fingerprint do weryfikacji out-of-band
//  KNOWN      — klucz zgodny z known_hosts, ale nie potwierdzony przez
//               użytkownika; komunikacja możliwa
//  VERIFIED   — fingerprint potwierdzony out-of-band; pełne zaufanie
//  MISMATCH   — klucz INNY niż zapamiętany => natychmiastowa blokada
//               połączenia + alert; wymaga świadomej akcji użytkownika
//               (Trusted Peers -> Remove), wpis NIE jest nadpisywany
//
// Identyfikacja peera:
//  - klient:  "srv:<host>:<port>"  — pełny model ze zmianą klucza
//  - serwer:  "cli:<fingerprint>"  — rozpoznawanie powracających klientów
//    (klient nie ma stałego adresu, więc identyfikatorem jest sam klucz;
//     mismatch z definicji niemożliwy w tym kierunku)
//
// Plik: <katalog profilu>/known_hosts (JSON, chmod 0600).
// Porównywany jest PEŁNY SHA-3-256 klucza (nie skrócony fingerprint).
enum class TrustState { UNVERIFIED, KNOWN, VERIFIED, MISMATCH };

struct TrustDecision {
    TrustState  state;
    std::string fingerprint;        // fingerprint klucza z handshake'u
    std::string stored_fingerprint; // przy MISMATCH: czego oczekiwano
};

struct TrustEntry {
    std::string peer_id;
    std::string fingerprint;
    std::string algo;
    bool        verified = false;
};

class TrustStore {
public:
    // TOFU: nowy peer => zapis jako UNVERIFIED. Znany => KNOWN/VERIFIED.
    // Inny klucz => MISMATCH (wpis pozostaje nietknięty!).
    static TrustDecision check_and_remember(const std::string& peer_id,
                                            const Bytes& public_key,
                                            const std::string& algo);

    // Użytkownik potwierdził fingerprint out-of-band
    static void mark_verified(const std::string& peer_id);

    // Świadome usunięcie wpisu (jedyna droga po MISMATCH)
    static void remove(const std::string& peer_id);

    static std::vector<TrustEntry> list();

    // <katalog profilu>/known_hosts
    static std::filesystem::path store_path();

    static const char* state_name(TrustState s);
};

#endif // QUILL_TRUSTSTORE_H
