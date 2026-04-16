#include <iostream>
#include <chrono>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <iomanip>
#include <sstream>
#include <vector>
#include <algorithm>

#include "src/crypto/crypto.h"
#include "src/network/network.h"

#define PORT 7777

// ── GLOBAL────────────────────────────────────────
std::atomic<bool> running{true};
std::atomic<int> msg_count{0};
std::mutex send_mtx;
std::mutex cout_mtx;

Bytes client_aes_key;
std::mutex client_session_mtx;

struct ConnectedClient {
    int fd;
    Bytes aes_key;
    std::string name;
};
std::vector<ConnectedClient> server_clients;
std::mutex server_clients_mtx;

// ── UI / LOGGING ───────────────────────────────────────────────
auto now() { return std::chrono::high_resolution_clock::now(); }

template<typename T>
double ms(T a, T b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

void print_banner() {
    std::lock_guard<std::mutex> lock(cout_mtx);
    std::cout << "=============================================\n";
    std::cout << "        QuantumShield v0.3 (Chat Room)\n";
    std::cout << "   Post-Quantum Secure Messenger (PQC)\n";
    std::cout << "=============================================\n\n";
}

void log_step(const std::string& step, double time_ms = -1.0) {
    std::lock_guard<std::mutex> lock(cout_mtx);
    std::cout << "[*] " << std::left << std::setw(35) << step;
    if (time_ms >= 0.0) std::cout << "[" << std::fixed << std::setprecision(2) << time_ms << " ms]";
    std::cout << "\n";
}

std::string hex_preview(const Bytes& data, size_t max_len = 8) {
    std::ostringstream oss;
    for (size_t i = 0; i < std::min(max_len, data.size()); ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    if (data.size() > max_len) oss << "...";
    return oss.str();
}

void safe_send_msg(int fd, const Bytes& data) {
    std::lock_guard<std::mutex> lock(send_mtx);
    send_msg(fd, data);
}

// ── HANDSHAKE ──────────────────────────────────────────────────
Bytes server_handshake(int cli_fd, const std::string& level, const std::string& client_name) {
    {
        std::lock_guard<std::mutex> lock(cout_mtx);
        std::cout << "\n=== KEM (" << client_name << ") | Level: " << level << " ===\n";
    }

    auto t0 = now();
    auto kp = kyber_keygen(level);
    auto t1 = now();
    log_step("Kyber key generation", ms(t0, t1));

    safe_send_msg(cli_fd, kp.pub);

    auto ct = recv_msg(cli_fd);
    auto t2 = now();

    auto ss = kyber_decaps(level, ct, kp.priv);
    auto t3 = now();
    log_step("Decapsulation complete", ms(t2, t3));

    {
        std::lock_guard<std::mutex> lock(cout_mtx);
        std::cout << "\033[1;32m[OK] Secure session established\033[0m\n> " << std::flush;
    }
    return Bytes(ss.begin(), ss.begin() + 32);
}

Bytes client_handshake(int srv_fd, const std::string& level) {
    {
        std::lock_guard<std::mutex> lock(cout_mtx);
        std::cout << "\n=== HANDSHAKE (CLIENT) | Level: " << level << " ===\n";
    }

    auto pub = recv_msg(srv_fd);
    auto t0 = now();
    log_step("Public key received (" + std::to_string(pub.size()) + " bytes)");

    auto [ct, ss] = kyber_encaps(level, pub);
    auto t1 = now();
    log_step("Encapsulation complete", ms(t0, t1));

    safe_send_msg(srv_fd, ct);

    {
        std::lock_guard<std::mutex> lock(cout_mtx);
        std::cout << "\033[1;32m[OK] Secure session established\033[0m\n> " << std::flush;
    }
    return Bytes(ss.begin(), ss.begin() + 32);
}

// ── SERVER THREAD HANDLER ───────────────────────────────────────
void server_client_handler(int cli_fd, int id) {
    std::string client_name = "Client_" + std::to_string(id);

    auto key = server_handshake(cli_fd, "BALANCED", client_name);
    {
        std::lock_guard<std::mutex> lk(server_clients_mtx);
        server_clients.push_back({cli_fd, key, client_name});
    }

    while (running) {
        try {
            auto data = recv_msg(cli_fd);
            if (data.empty()) break;

            std::string raw(data.begin(), data.end());

            if (raw.starts_with("REQ_LEVEL:")) {
                std::string new_level = raw.substr(10);
                std::string cmd = "DO_HANDSHAKE:" + new_level;
                safe_send_msg(cli_fd, Bytes(cmd.begin(), cmd.end()));

                auto new_key = server_handshake(cli_fd, new_level, client_name);
                std::lock_guard<std::mutex> lk(server_clients_mtx);
                for (auto& c : server_clients) {
                    if (c.fd == cli_fd) c.aes_key = new_key;
                }
                continue;
            }

            msg_count++;
            Bytes sender_key;
            {
                std::lock_guard<std::mutex> lk(server_clients_mtx);
                for (auto& c : server_clients) {
                    if (c.fd == cli_fd) { sender_key = c.aes_key; break; }
                }
            }

            auto plain = aes_decrypt(sender_key, data);
            std::string broadcast_msg = "[" + client_name + "]: " + plain;

            {
                std::lock_guard<std::mutex> lock(cout_mtx);
                std::cout << "\n[ENC] " << hex_preview(data) << "\n";
                std::cout << "\033[1;36m" << broadcast_msg << "\033[0m\n> " << std::flush;
            }

            std::lock_guard<std::mutex> lk(server_clients_mtx);
            for (auto& c : server_clients) {
                if (c.fd != cli_fd) {
                    auto enc = aes_encrypt(c.aes_key, broadcast_msg);
                    safe_send_msg(c.fd, enc);
                }
            }
        }
        catch (...) { break; }
    }

    {
        std::lock_guard<std::mutex> lk(server_clients_mtx);
        server_clients.erase(
            std::remove_if(server_clients.begin(), server_clients.end(),
                           [cli_fd](const ConnectedClient& c){ return c.fd == cli_fd; }),
            server_clients.end()
        );
    }
    close(cli_fd);
    std::lock_guard<std::mutex> lock(cout_mtx);
    std::cout << "\n\033[1;31m[!] " << client_name << " disconnected.\033[0m\n> " << std::flush;
}

// ── CLIENT RECEIVER THREAD ───────────────────────────────────────
void client_receiver_thread(int fd) {
    while (running) {
        try {
            auto data = recv_msg(fd);
            if (data.empty()) break;

            std::string raw(data.begin(), data.end());
            if (raw.starts_with("DO_HANDSHAKE:")) {
                std::string new_level = raw.substr(13);
                auto new_key = client_handshake(fd, new_level);
                std::lock_guard<std::mutex> lk(client_session_mtx);
                client_aes_key = new_key;
                continue;
            }

            Bytes key_copy;
            {
                std::lock_guard<std::mutex> lk(client_session_mtx);
                key_copy = client_aes_key;
            }

            auto plain = aes_decrypt(key_copy, data);
            msg_count++;

            {
                std::lock_guard<std::mutex> lock(cout_mtx);
                std::cout << "\n---------------------------------------------\n";
                std::cout << "[ENC]     " << hex_preview(data) << "\n";
                std::cout << "\033[1;36m" << plain << "\033[0m\n> " << std::flush;
            }
        }
        catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(cout_mtx);
            std::cout << "\n\033[1;31m[ERROR] " << e.what() << "\033[0m\n> " << std::flush;
        }
    }
    running = false;
}

// ── MAIN: SERWER ────────────────────────────────────────────────
void run_server() {
    print_banner();
    int srv = make_server(PORT);
    std::cout << "[SERVER] Chat room open on port " << PORT << ". Waiting for clients...\n";

    std::thread([srv]() {
        int id_counter = 1;
        while (running) {
            int cli = accept(srv, nullptr, nullptr);
            if (cli >= 0) {
                std::lock_guard<std::mutex> lock(cout_mtx);
                std::cout << "\n\033[1;32m[+] Client_" << id_counter << " connected!\033[0m\n> " << std::flush;
                std::thread(server_client_handler, cli, id_counter++).detach();
            }
        }
    }).detach();

    std::string line;
    std::cout << "> ";
    while (running) {
        std::getline(std::cin, line);

        if (line == "/help") {
            std::lock_guard<std::mutex> lock(cout_mtx);
            std::cout << "\n\033[1;33m=== COMMANDS (SERVER) ===\033[0m\n"
                      << " \033[1;37m/clear\033[0m  - clears the terminal screen\n"
                      << " \033[1;37m/quit\033[0m   - closes the server\n"
                      << "=========================\n> " << std::flush;
            continue;
        }

        if (line == "/clear") {
            std::cout << "\033[2J\033[1;1H";
            print_banner();
            std::cout << "> " << std::flush;
            continue;
        }

        if (line == "/quit") { running = false; break; }

        if (!line.empty()) {
            msg_count++;
            std::string msg = "[SERVER]: " + line;

            std::lock_guard<std::mutex> lock(cout_mtx);
            std::cout << "---------------------------------------------\n";
            std::cout << "[PLAIN]  " << line << "\n";

            std::lock_guard<std::mutex> lk(server_clients_mtx);
            for (auto& c : server_clients) {
                auto encrypted = aes_encrypt(c.aes_key, msg);
                safe_send_msg(c.fd, encrypted);
                std::cout << "[ENC-> " << c.name << "] " << hex_preview(encrypted) << "\n";
            }
            std::cout << "> " << std::flush;
        }
    }
    close(srv);
}

// ── MAIN: KLIENT ────────────────────────────────────────────────
void run_client() {
    print_banner();
    std::cout << "[CLIENT] Connecting to server...\n";
    int fd = make_client("127.0.0.1", PORT);
    std::cout << "[CLIENT] Connected to Chat Room!\n";

    auto initial_key = client_handshake(fd, "BALANCED");
    {
        std::lock_guard<std::mutex> lk(client_session_mtx);
        client_aes_key = initial_key;
    }

    std::thread rx_thread(client_receiver_thread, fd);

    bool tamper = false;
    std::string line;
    std::cout << "> ";

    while (running) {
        std::getline(std::cin, line);

        if (line == "/help") {
            std::lock_guard<std::mutex> lock(cout_mtx);
            std::cout << "\n\033[1;33m=== COMMANDS (CLIENT) ===\033[0m\n"
                      << " \033[1;37m/level <L>\033[0m  - FAST, BALANCED, MAX\n"
                      << " \033[1;37m/tamper\033[0m     - MITM attack simulation\n"
                      << " \033[1;37m/clear\033[0m      - clears screen\n"
                      << " \033[1;37m/quit\033[0m       - disconnect\n"
                      << "=========================\n> " << std::flush;
            continue;
        }

        if (line == "/tamper") {
            tamper = !tamper;
            std::lock_guard<std::mutex> lock(cout_mtx);
            std::cout << "[MODE] Tamper = " << (tamper ? "ON" : "OFF") << "\n> " << std::flush;
            continue;
        }

        if (line == "/clear") {
            std::cout << "\033[2J\033[1;1H";
            print_banner();
            std::cout << "> " << std::flush;
            continue;
        }

        if (line.starts_with("/level ")) {
            std::string new_level = line.substr(7);
            if (new_level != "FAST" && new_level != "BALANCED" && new_level != "MAX") {
                std::lock_guard<std::mutex> lock(cout_mtx);
                std::cout << "\033[1;31m[ERROR] Use: FAST, BALANCED, MAX\033[0m\n> " << std::flush;
                continue;
            }
            std::string cmd = "REQ_LEVEL:" + new_level;
            safe_send_msg(fd, Bytes(cmd.begin(), cmd.end()));
            continue;
        }

        if (line == "/quit") { running = false; break; }

        if (!line.empty()) {
            Bytes key_copy;
            {
                std::lock_guard<std::mutex> lk(client_session_mtx);
                key_copy = client_aes_key;
            }
            auto encrypted = aes_encrypt(key_copy, line);

            if (tamper && encrypted.size() > 10) encrypted[10] ^= 0xFF;

            safe_send_msg(fd, encrypted);

            std::lock_guard<std::mutex> lock(cout_mtx);
            std::cout << "---------------------------------------------\n";
            std::cout << "[PLAIN]  " << line << "\n";
            std::cout << "[ENC]    " << hex_preview(encrypted) << "\n";
            if (tamper) std::cout << "\033[1;31m[ATTACK] Ciphertext modified!\033[0m\n";
            std::cout << "> " << std::flush;
        }
    }
    close(fd);
    rx_thread.detach();
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: ./Quill server OR ./Quill client\n";
        return 1;
    }
    if (std::string(argv[1]) == "server") run_server();
    else run_client();
    return 0;
}