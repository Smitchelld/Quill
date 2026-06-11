#include "CryptoManager.h"
#include "KyberKEM.h"
#include "DilithiumSign.h"
#include "Hkdf.h"
#include "IdentityManager.h"
#include "../network/Socket.h"

#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <chrono>

using json = nlohmann::json;
using clk  = std::chrono::high_resolution_clock;

static double ms_between(clk::time_point a, clk::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

static void step(const StepCallback& cb, const std::string& label, double t = -1.0) {
    if (cb) cb(label, t);
}

CryptoManager::CryptoManager(std::string level) : m_level(std::move(level)) {}

// ── KLIENT ────────────────────────────────────────────────────────

HandshakeResult CryptoManager::client_handshake(Socket& sock,
                                                const std::string& peer_id,
                                                const StepCallback& on_step,
                                                bool server_rehandshake) {
    KyberKEM      kem(m_level);
    DilithiumSign signer(m_level);

    // 1. SRV_HELLO
    auto data = sock.receive_bytes();
    auto j    = json::parse(data.begin(), data.end());

    Bytes srv_sig_pub   = j["sig_pub"].get<Bytes>();
    Bytes srv_kyber_pub = j["kyber_pub"].get<Bytes>();
    Bytes srv_sig       = j["sig"].get<Bytes>();

    // 2a. Weryfikacja podpisu — ZAWSZE przed użyciem materiału KEM
    auto t0 = clk::now();
    if (!signer.verify(srv_kyber_pub, srv_sig, srv_sig_pub))
        throw std::runtime_error("Server Identity Verification FAILED!");
    auto t1 = clk::now();
    step(on_step, "Server Signature Verified (ML-DSA)", ms_between(t0, t1));

    // 2b. TOFU — fail-closed PRZED enkapsulacją: przy MISMATCH atakujący
    //     nie dostaje nawet ciphertextu KEM
    auto trust = TrustStore::check_and_remember(peer_id, srv_sig_pub,
                                                signer.algo_name(),
                                                server_rehandshake);
    if (trust.state == TrustState::MISMATCH) {
        step(on_step, "TOFU: KEY MISMATCH — CONNECTION BLOCKED");
        throw TofuMismatchError(trust.stored_fingerprint, trust.fingerprint);
    }
    step(on_step, std::string("TOFU: ") + TrustStore::state_name(trust.state));

    // 2c. Enkapsulacja
    auto t2 = clk::now();
    auto [ct, ss] = kem.encapsulate(srv_kyber_pub);
    auto t3 = clk::now();
    step(on_step, "KEM Encapsulation (ML-KEM)", ms_between(t2, t3));

    // 2d. Podpis ciphertextu trwałą tożsamością
    auto t4        = clk::now();
    auto my_sig_kp = IdentityManager::load_or_generate(m_level);
    auto my_sig    = signer.sign(ct, my_sig_kp.secret_key);
    auto t5        = clk::now();
    step(on_step, "Identity Loaded + Ciphertext Signed (ML-DSA)", ms_between(t4, t5));

    // 3. CLI_KEX
    json res;
    res["type"]       = "CLI_KEX";
    res["sig_pub"]    = my_sig_kp.public_key;
    res["ciphertext"] = ct;
    res["sig"]        = my_sig;

    std::string s = res.dump();
    sock.send_bytes(Bytes(s.begin(), s.end()));

    // 5. KDF: klucz sesji wiązany z transkryptem handshake'u
    auto t6 = clk::now();
    Bytes transcript = srv_kyber_pub;
    transcript.insert(transcript.end(), ct.begin(), ct.end());
    Bytes key = Hkdf::derive(ss, transcript, Hkdf::session_info(m_level));
    OPENSSL_cleanse(ss.data(), ss.size());
    auto t7 = clk::now();
    step(on_step, "Session Key Derived (HKDF-SHA256)", ms_between(t6, t7));

    return {std::move(key), trust.fingerprint, trust.state, ms_between(t0, t7)};
}

// ── SERWER ────────────────────────────────────────────────────────

HandshakeResult CryptoManager::server_handshake(Socket& sock,
                                                const StepCallback& on_step) {
    KyberKEM      kem(m_level);
    DilithiumSign signer(m_level);

    // Kyber: efemeryczny per sesja (PFS). DSA: trwała tożsamość z dysku.
    auto t0       = clk::now();
    auto kyber_kp = kem.generate_keypair();
    auto sig_kp   = IdentityManager::load_or_generate(m_level);
    auto t1       = clk::now();
    step(on_step, "Keygen (ML-KEM) + Identity Load (ML-DSA)", ms_between(t0, t1));

    auto srv_sig = signer.sign(kyber_kp.public_key, sig_kp.secret_key);

    // 1. SRV_HELLO
    json hello;
    hello["type"]      = "SRV_HELLO";
    hello["sig_pub"]   = sig_kp.public_key;
    hello["kyber_pub"] = kyber_kp.public_key;
    hello["sig"]       = srv_sig;

    std::string s = hello.dump();
    sock.send_bytes(Bytes(s.begin(), s.end()));

    // 3. CLI_KEX
    auto data = sock.receive_bytes();
    auto j    = json::parse(data.begin(), data.end());

    Bytes cli_sig_pub = j["sig_pub"].get<Bytes>();
    Bytes ct          = j["ciphertext"].get<Bytes>();
    Bytes cli_sig     = j["sig"].get<Bytes>();

    // 4a. Weryfikacja podpisu — ZAWSZE przed dekapsulacją
    auto t4 = clk::now();
    if (!signer.verify(ct, cli_sig, cli_sig_pub))
        throw std::runtime_error("Client Identity Verification FAILED!");
    auto t5 = clk::now();
    step(on_step, "Client Signature Verified (ML-DSA)", ms_between(t4, t5));

    // 4b. TOFU: klient identyfikowany własnym kluczem (brak stałego adresu)
    std::string cli_fp = IdentityManager::fingerprint(cli_sig_pub);
    auto trust = TrustStore::check_and_remember("cli:" + cli_fp, cli_sig_pub,
                                                signer.algo_name());

    // 4c. Dekapsulacja
    auto t6 = clk::now();
    auto ss = kem.decapsulate(ct, kyber_kp.secret_key);
    auto t7 = clk::now();
    step(on_step, "KEM Decapsulation (ML-KEM)", ms_between(t6, t7));

    // 5. KDF: identyczny transkrypt po obu stronach -> identyczny klucz
    auto t8 = clk::now();
    Bytes transcript = kyber_kp.public_key;
    transcript.insert(transcript.end(), ct.begin(), ct.end());
    Bytes key = Hkdf::derive(ss, transcript, Hkdf::session_info(m_level));
    OPENSSL_cleanse(ss.data(), ss.size());
    auto t9 = clk::now();
    step(on_step, "Session Key Derived (HKDF-SHA256)", ms_between(t8, t9));

    return {std::move(key), cli_fp, trust.state, ms_between(t0, t9)};
}
