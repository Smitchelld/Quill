#include <iostream>
#include <chrono>
#include <string>
#include "src/crypto.h"
#include "src/network.h"
#include <iomanip>
#include <sstream>

#define PORT 7777

auto now() { return std::chrono::high_resolution_clock::now(); }

template<typename T>
long ms(T a, T b) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count();
}

// ── UI / LOGGING ───────────────────────────────────────────────

void print_banner() {
    std::cout << "=============================================\n";
    std::cout << "        QuantumShield v0.1\n";
    std::cout << "   Post-Quantum Secure Messenger (PQC)\n";
    std::cout << "=============================================\n\n";
}

void log_step(const std::string& step, long time_ms = -1) {
    std::cout << "[*] " << std::left << std::setw(35) << step;

    if (time_ms >= 0)
        std::cout << " [" << time_ms << " ms]";

    std::cout << "\n";
}

std::string hex_preview(const Bytes& data, size_t max_len = 8) {
    std::ostringstream oss;
    for (size_t i = 0; i < std::min(max_len, data.size()); ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << (int)data[i];
    }
    if (data.size() > max_len) oss << "...";
    return oss.str();
}

// ── SERWER ──────────────────────────────────────────────────────
void run_server() {
    print_banner();

    std::cout << "[SERVER] Waiting for connection on port " << PORT << "...\n";

    int srv = make_server(PORT);
    int cli = accept(srv, nullptr, nullptr);

    std::cout << "[SERVER] Client connected\n\n";

    std::cout << "=== HANDSHAKE (SERVER) ===\n";

    // 1. Keygen
    auto t0 = now();
    auto kp = kyber_keygen();
    auto t1 = now();

    log_step("Kyber-768 key generation", ms(t0, t1));
    log_step("Public key size: " + std::to_string(kp.pub.size()) + " bytes");

    // 2. Send pubkey
    send_msg(cli, kp.pub);
    log_step("Public key sent");

    // 3. Receive ciphertext
    auto ct = recv_msg(cli);
    auto t2 = now();

    log_step("Ciphertext received (" + std::to_string(ct.size()) + " bytes)");

    // 4. Decaps
    auto ss = kyber_decaps(ct, kp.priv);
    auto t3 = now();

    log_step("Decapsulation complete", ms(t2, t3));

    std::cout << "---------------------------------------------\n";
    std::cout << "[OK] Secure session established\n";

    std::cout << "\n=== PERFORMANCE ===\n";
    std::cout << "KeyGen:        " << ms(t0, t1) << " ms\n";
    std::cout << "Decapsulation: " << ms(t2, t3) << " ms\n";
    std::cout << "Total:         " << ms(t0, t3) << " ms\n\n";

    Bytes aes_key(ss.begin(), ss.begin() + 32);

    std::cout << "[SERVER] Waiting for messages...\n";

    // loop
    while (true) {
        auto encrypted = recv_msg(cli);
        if (encrypted.empty()) break;

        try {
            std::cout << "---------------------------------------------\n";
            std::cout << "[ENC]     " << hex_preview(encrypted) << "\n";

            auto plain = aes_decrypt(aes_key, encrypted);

            std::cout << "[DECRYPT] " << plain << "\n";
        }
        catch (std::exception& e) {
            std::cout << "[ERROR] " << e.what() << "\n";
            break;
        }
    }

    close(cli);
    close(srv);
}

// ── KLIENT ──────────────────────────────────────────────────────
void run_client() {
    print_banner();

    std::cout << "[CLIENT] Connecting to server...\n";
    int fd = make_client("127.0.0.1", PORT);
    std::cout << "[CLIENT] Connected\n\n";

    std::cout << "=== HANDSHAKE (CLIENT) ===\n";

    // 1. Receive pubkey
    auto pub = recv_msg(fd);
    auto t0 = now();

    log_step("Public key received (" + std::to_string(pub.size()) + " bytes)");

    // 2. Encaps
    auto [ct, ss] = kyber_encaps(pub);
    auto t1 = now();

    log_step("Encapsulation complete", ms(t0, t1));
    log_step("Ciphertext size: " + std::to_string(ct.size()) + " bytes");

    // 3. Send ciphertext
    send_msg(fd, ct);
    log_step("Ciphertext sent");

    std::cout << "---------------------------------------------\n";
    std::cout << "[OK] Secure session established\n\n";

    Bytes aes_key(ss.begin(), ss.begin() + 32);

    std::cout << "[CLIENT] Type messages (Ctrl+C to exit)\n\n";

    // 🔥 opcjonalny atak
    bool tamper = false;

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "/tamper") {
            tamper = !tamper;
            std::cout << "[MODE] Tamper = " << (tamper ? "ON" : "OFF") << "\n";
            continue;
        }

        if (line.empty()) continue;

        auto encrypted = aes_encrypt(aes_key, line);

        // symulacja ataku
        if (tamper && encrypted.size() > 10) {
            encrypted[10] ^= 0xFF;
        }

        std::cout << "---------------------------------------------\n";
        std::cout << "[PLAIN]  " << line << "\n";
        std::cout << "[ENC]    " << hex_preview(encrypted) << "\n";

        if (tamper)
            std::cout << "[ATTACK] Ciphertext modified\n";

        std::cout << "[SIZE]   " << encrypted.size() << " bytes\n";

        send_msg(fd, encrypted);
    }

    close(fd);
}

// ── MAIN ────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Uzycie: ./Quill server  LUB  ./Quill client\n";
        return 1;
    }
    std::string mode = argv[1];
    if (mode == "server") run_server();
    else if (mode == "client") run_client();
    else std::cerr << "Nieznany tryb: " << mode << "\n";
    return 0;
}