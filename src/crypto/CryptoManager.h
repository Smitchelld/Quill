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

struct TofuMismatchError : std::runtime_error {
    std::string expected_fp;
    std::string received_fp;
    TofuMismatchError(std::string expected, std::string received)
        : std::runtime_error("TOFU: klucz peera inny niz zapamietany — polaczenie zablokowane"),
          expected_fp(std::move(expected)), received_fp(std::move(received)) {}
};

struct HandshakeResult {
    Bytes       session_key;
    std::string peer_fingerprint;
    TrustState  peer_trust;
    double      total_ms = 0.0;
};

using StepCallback = std::function<void(const std::string&, double)>;

class CryptoManager {
public:
    explicit CryptoManager(std::string level);

    HandshakeResult client_handshake(Socket& sock,
                                     const std::string& peer_id,
                                     const StepCallback& on_step = nullptr,
                                     bool server_rehandshake = false);

    HandshakeResult server_handshake(Socket& sock,
                                     const StepCallback& on_step = nullptr);

    const std::string& level() const { return m_level; }

private:
    std::string m_level;
};

#endif // QUILL_CRYPTOMANAGER_H
