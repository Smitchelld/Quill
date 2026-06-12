#ifndef QUILL_TRUSTSTORE_H
#define QUILL_TRUSTSTORE_H

#include <filesystem>
#include <string>
#include <vector>
#include <cstdint>

using Bytes = std::vector<uint8_t>;

// TOFU known_hosts: MISMATCH blocks connection until user removes stale entry.
enum class TrustState { UNVERIFIED, KNOWN, VERIFIED, MISMATCH };

struct TrustDecision {
    TrustState  state;
    std::string fingerprint;
    std::string stored_fingerprint;
};

struct TrustEntry {
    std::string peer_id;
    std::string fingerprint;
    std::string algo;
    bool        verified = false;
};

class TrustStore {
public:
    static TrustDecision check_and_remember(const std::string& peer_id,
                                            const Bytes& public_key,
                                            const std::string& algo,
                                            bool allow_algo_rotation = false);

    static void mark_verified(const std::string& peer_id);
    static void remove(const std::string& peer_id);
    static std::vector<TrustEntry> list();
    static std::filesystem::path store_path();
    static const char* state_name(TrustState s);
};

#endif // QUILL_TRUSTSTORE_H
