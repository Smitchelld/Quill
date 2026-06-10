#ifndef QUILL_CRYPTOMANAGER_H
#define QUILL_CRYPTOMANAGER_H

#include "TrustStore.h"
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstdint>

using Bytes = std::vector<uint8_t>;
class Socket;

// ── CryptoManager ─────────────────────────────────────────────────
// Ujednolicona warstwa krypto: cały PQC handshake (ML-KEM + ML-DSA),
// TOFU, HKDF i tożsamość w jednym miejscu — bez zależności od UI.
//
// Przebieg (poziom określa algorytmy: FAST/BALANCED/MAX):
//   1. SRV_HELLO:  serwer -> klient: pub_kyber, pub_dsa, sig(pub_kyber)
//   2. klient:     verify(sig) -> TOFU check -> KEM encaps -> sig(ct)
//   3. CLI_KEX:    klient -> serwer: ct, pub_dsa, sig(ct)
//   4. serwer:     verify(sig) -> TOFU remember -> KEM decaps
//   5. obie strony: AES_key = HKDF-SHA256(ss, salt=pub_kyber||ct, info=level)
//
// Inwarianty bezpieczeństwa (egzekwowane tutaj, nie w UI):
//   - verify() ZAWSZE przed encaps/decaps
//   - TOFU MISMATCH zrywa handshake PRZED enkapsulacją (fail-closed)
//   - klucz sesji nigdy nie jest surowym shared_secret (HKDF + cleanse)
//   - Kyber efemeryczny per handshake (PFS), DSA trwały (IdentityManager)

// Zmiana klucza peera względem known_hosts — potencjalny MITM
struct TofuMismatchError : std::runtime_error {
    std::string expected_fp;
    std::string received_fp;
    TofuMismatchError(std::string expected, std::string received)
        : std::runtime_error("TOFU: klucz peera inny niz zapamietany — polaczenie zablokowane"),
          expected_fp(std::move(expected)), received_fp(std::move(received)) {}
};

struct HandshakeResult {
    Bytes       session_key;       // 32B, po HKDF
    std::string peer_fingerprint;
    TrustState  peer_trust;
    double      total_ms = 0.0;
};

// Callback dla wizualizera: (etykieta kroku, czas w ms; <0 = bez czasu)
using StepCallback = std::function<void(const std::string&, double)>;

class CryptoManager {
public:
    explicit CryptoManager(std::string level);

    // Strona kliencka. peer_id identyfikuje serwer w known_hosts
    // (konwencja: "srv:<host>:<port>"). Rzuca TofuMismatchError przy
    // zmianie klucza serwera, std::runtime_error przy innych błędach.
    HandshakeResult client_handshake(Socket& sock,
                                     const std::string& peer_id,
                                     const StepCallback& on_step = nullptr);

    // Strona serwerowa. Klient jest identyfikowany w known_hosts po
    // własnym kluczu ("cli:<fingerprint>") — mismatch tu nie występuje.
    HandshakeResult server_handshake(Socket& sock,
                                     const StepCallback& on_step = nullptr);

    const std::string& level() const { return m_level; }

private:
    std::string m_level;
};

#endif // QUILL_CRYPTOMANAGER_H
