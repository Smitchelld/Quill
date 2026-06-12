#ifndef QUILL_DILITHIUMSIGN_H
#define QUILL_DILITHIUMSIGN_H

#include <oqs/oqs.h>
#include <vector>
#include <string>
#include <memory>

using Bytes = std::vector<uint8_t>;

struct SignatureKeyPair {
    Bytes public_key;
    Bytes secret_key;
};

class DilithiumSign {
public:
    explicit DilithiumSign(const std::string& level = "BALANCED");
    ~DilithiumSign();

    DilithiumSign(const DilithiumSign&) = delete;
    DilithiumSign& operator=(const DilithiumSign&) = delete;

    SignatureKeyPair generate_keypair() const;

    Bytes sign(const Bytes& message, const Bytes& secret_key) const;

    bool verify(const Bytes& message, const Bytes& signature, const Bytes& public_key) const;

    // Metadane algorytmu — do walidacji kluczy wczytywanych z dysku
    const char* algo_name()   const { return m_sig->method_name; }
    size_t      pub_key_len() const { return m_sig->length_public_key; }
    size_t      sec_key_len() const { return m_sig->length_secret_key; }

private:
    OQS_SIG* m_sig = nullptr;
    static const char* resolve_algo(const std::string& level);
};

#endif // QUILL_DILITHIUMSIGN_H
