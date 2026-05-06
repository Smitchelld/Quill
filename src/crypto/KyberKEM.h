#ifndef QUILL_KYBERKEM_H
#define QUILL_KYBERKEM_H

#include <oqs/oqs.h>
#include <vector>
#include <string>
#include <memory>

using Bytes = std::vector<uint8_t>;

struct KyberKeyPair {
    Bytes public_key;
    Bytes secret_key;
};

class KyberKEM {
public:
    explicit KyberKEM(const std::string& level);
    ~KyberKEM();

    KyberKEM(const KyberKEM&) = delete;
    KyberKEM& operator=(const KyberKEM&) = delete;

    KyberKeyPair generate_keypair() const;
    std::pair<Bytes, Bytes> encapsulate(const Bytes& peer_public_key) const;
    Bytes decapsulate(const Bytes& ciphertext, const Bytes& secret_key) const;

private:
    OQS_KEM* kem = nullptr;
    static const char* resolve_algo(const std::string& level);
};

#endif