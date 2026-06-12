#include "DilithiumSign.h"
#include <stdexcept>

DilithiumSign::DilithiumSign(const std::string& level) {
    m_sig = OQS_SIG_new(resolve_algo(level));
    if (!m_sig) {
        throw std::runtime_error("Nie udalo sie zainicjalizowac algorytmu podpisu dla poziomu: " + level);
    }
}

DilithiumSign::~DilithiumSign() {
    if (m_sig) {
        OQS_SIG_free(m_sig);
    }
}

const char* DilithiumSign::resolve_algo(const std::string& level) {

    if (level == "FAST") {
        return OQS_SIG_alg_falcon_512;
    }
    if (level == "BALANCED") {
        return OQS_SIG_alg_ml_dsa_65;
    }
    if (level == "MAX") {
        return OQS_SIG_alg_ml_dsa_87;
    }
    
    throw std::runtime_error("Nieznany poziom bezpieczenstwa: " + level);
}

SignatureKeyPair DilithiumSign::generate_keypair() const {
    SignatureKeyPair kp;
    kp.public_key.resize(m_sig->length_public_key);
    kp.secret_key.resize(m_sig->length_secret_key);

    if (OQS_SIG_keypair(m_sig, kp.public_key.data(), kp.secret_key.data()) != OQS_SUCCESS) {
        throw std::runtime_error("Blad generowania pary kluczy Dilithium");
    }

    return kp;
}

Bytes DilithiumSign::sign(const Bytes& message, const Bytes& secret_key) const {
    Bytes signature(m_sig->length_signature);
    size_t signature_len = 0;

    if (OQS_SIG_sign(m_sig, signature.data(), &signature_len, 
                     message.data(), message.size(), secret_key.data()) != OQS_SUCCESS) {
        throw std::runtime_error("Blad podczas tworzenia podpisu cyfrowego");
    }

    signature.resize(signature_len);
    return signature;
}

bool DilithiumSign::verify(const Bytes& message, const Bytes& signature, const Bytes& public_key) const {
    return OQS_SIG_verify(m_sig, message.data(), message.size(), 
                          signature.data(), signature.size(), public_key.data()) == OQS_SUCCESS;
}
