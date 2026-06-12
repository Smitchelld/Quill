#include "KyberKEM.h"

#include <stdexcept>

KyberKEM::KyberKEM(const std::string& level) {
    kem = OQS_KEM_new(resolve_algo(level));
    if (!kem) throw std::runtime_error("Nie udało się zainicjalizować Kyber: " + level);
}

KyberKEM::~KyberKEM() {
    if (kem) OQS_KEM_free(kem);
}

const char* KyberKEM::resolve_algo(const std::string& level) {
    if (level == "FAST")     return OQS_KEM_alg_kyber_512;
    if (level == "BALANCED") return OQS_KEM_alg_kyber_768;
    if (level == "MAX")      return OQS_KEM_alg_kyber_1024;
    throw std::runtime_error("Nieznany poziom bezpieczeństwa: " + level);
}

KyberKeyPair KyberKEM::generate_keypair() const {
    KyberKeyPair kp;
    kp.public_key.resize(kem->length_public_key);
    kp.secret_key.resize(kem->length_secret_key);
    
    if (OQS_KEM_keypair(kem, kp.public_key.data(), kp.secret_key.data()) != OQS_SUCCESS)
        throw std::runtime_error("Błąd generowania pary kluczy Kyber");
    
    return kp;
}

std::pair<Bytes, Bytes> KyberKEM::encapsulate(const Bytes& peer_public_key) const {
    Bytes ct(kem->length_ciphertext);
    Bytes ss(kem->length_shared_secret);
    
    if (OQS_KEM_encaps(kem, ct.data(), ss.data(), peer_public_key.data()) != OQS_SUCCESS)
        throw std::runtime_error("Błąd enkapsulacji Kyber");
        
    return {ct, ss};
}

Bytes KyberKEM::decapsulate(const Bytes& ciphertext, const Bytes& secret_key) const {
    Bytes ss(kem->length_shared_secret);
    
    if (OQS_KEM_decaps(kem, ss.data(), ciphertext.data(), secret_key.data()) != OQS_SUCCESS)
        throw std::runtime_error("Błąd dekapsulacji Kyber");
        
    return ss;
}
