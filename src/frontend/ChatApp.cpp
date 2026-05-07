#include "ChatApp.h"
#include "Theme.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>

using clk = std::chrono::high_resolution_clock;

// ══════════════════════════════════════════════════════════════════
//  KONSTRUKTOR / DESTRUKTOR
// ══════════════════════════════════════════════════════════════════

ChatApp::ChatApp() {
    m_rooms["general"] = {};
    m_room_logs["general"] = {};
}

ChatApp::~ChatApp() {
    m_connected = false;
    if (m_client) m_client->close_socket();
    if (m_server) m_server->close_socket();

    std::lock_guard lk(m_clients_mtx);
    for (auto& c : m_clients)
        if (c.sock) c.sock->close_socket();
}

// ── HELPERY ───────────────────────────────────────────────────────

void ChatApp::log(const std::string& text, ImVec4 color, const std::string& room) {
    std::lock_guard lock(m_log_mtx);
    m_room_logs[room].push_back({text, color});
    if (m_room_logs[room].size() > 500)
        m_room_logs[room].pop_front();
}

void ChatApp::hs_step(const std::string& label, double time_ms) {
    std::lock_guard lock(m_hs_mtx);
    m_hs_steps.push_back({label, time_ms});
}

void ChatApp::hs_clear() {
    std::lock_guard lock(m_hs_mtx);
    m_hs_steps.clear();
    m_hs_total_ms = 0.0;
}

std::string ChatApp::hex_preview(const Bytes& data, size_t n) {
    std::ostringstream oss;
    for (size_t i = 0; i < std::min(n, data.size()); ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    if (data.size() > n) oss << "...";
    return oss.str();
}

double ChatApp::ms(clk::time_point a, clk::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

// ── HANDSHAKE (Poprawiony JSON - brak type_error 302) ──────────────

Bytes ChatApp::do_client_handshake(Socket& sock, const std::string& level) {
    hs_clear();
    log("=== HANDSHAKE START (CLIENT) | " + level + " ===", Theme::yellow(), m_current_room);

    KyberKEM      kem(level);
    DilithiumSign signer(level);

    auto data = sock.receive_bytes();
    auto j    = json::parse(data.begin(), data.end());

    // Pobieramy jako Bytes (std::vector<uint8_t>) - to naprawia błąd 302
    Bytes srv_sig_pub   = j["sig_pub"].get<Bytes>();
    Bytes srv_kyber_pub = j["kyber_pub"].get<Bytes>();
    Bytes srv_sig       = j["sig"].get<Bytes>();

    auto t0 = clk::now();
    if (!signer.verify(srv_kyber_pub, srv_sig, srv_sig_pub))
        throw std::runtime_error("Server Identity Verification FAILED!");
    auto t1 = clk::now();
    hs_step("Server Signature Verified (ML-DSA)", ms(t0, t1));

    auto t2 = clk::now();
    auto [ct, ss] = kem.encapsulate(srv_kyber_pub);
    auto t3 = clk::now();
    hs_step("KEM Encapsulation (ML-KEM)", ms(t2, t3));

    auto t4        = clk::now();
    auto my_sig_kp = signer.generate_keypair();
    auto my_sig    = signer.sign(ct, my_sig_kp.secret_key);
    auto t5        = clk::now();
    hs_step("Ciphertext Signed (ML-DSA)", ms(t4, t5));

    json res;
    res["type"]       = "CLI_KEX";
    res["sig_pub"]    = my_sig_kp.public_key; // JSON obsłuży wektor automatycznie
    res["ciphertext"] = ct;
    res["sig"]        = my_sig;
    res["room"]       = m_current_room;

    std::string s = res.dump();
    sock.send_bytes(Bytes(s.begin(), s.end()));

    m_hs_total_ms = ms(t0, t5);
    return Bytes(ss.begin(), ss.begin() + 32);
}

Bytes ChatApp::do_server_handshake(Socket& sock, const std::string& level) {
    KyberKEM      kem(level);
    DilithiumSign signer(level);

    auto t0       = clk::now();
    auto kyber_kp = kem.generate_keypair();
    auto sig_kp   = signer.generate_keypair();
    auto t1       = clk::now();
    hs_step("Keygen (ML-KEM + ML-DSA)", ms(t0, t1));

    auto srv_sig = signer.sign(kyber_kp.public_key, sig_kp.secret_key);

    json hello;
    hello["type"]      = "SRV_HELLO";
    hello["sig_pub"]   = sig_kp.public_key;
    hello["kyber_pub"] = kyber_kp.public_key;
    hello["sig"]       = srv_sig;

    std::string s = hello.dump();
    sock.send_bytes(Bytes(s.begin(), s.end()));

    auto data = sock.receive_bytes();
    auto j    = json::parse(data.begin(), data.end());

    Bytes cli_sig_pub = j["sig_pub"].get<Bytes>();
    Bytes ct          = j["ciphertext"].get<Bytes>();
    Bytes cli_sig     = j["sig"].get<Bytes>();

    auto t4 = clk::now();
    if (!signer.verify(ct, cli_sig, cli_sig_pub))
        throw std::runtime_error("Client Identity Verification FAILED!");
    auto t5 = clk::now();
    hs_step("Client Signature Verified (ML-DSA)", ms(t4, t5));

    auto t6 = clk::now();
    auto ss = kem.decapsulate(ct, kyber_kp.secret_key);
    auto t7 = clk::now();
    hs_step("KEM Decapsulation (ML-KEM)", ms(t6, t7));

    m_hs_total_ms = ms(t0, t7);
    return Bytes(ss.begin(), ss.begin() + 32);
}

// ── POKOJE ────────────────────────────────────────────────────────

void ChatApp::create_room(const std::string& room) {
    std::lock_guard lk(m_rooms_mtx);
    if (m_rooms.find(room) == m_rooms.end()) {
        m_rooms[room] = {};
        m_room_logs[room] = {};
        log("[*] Room #" + room + " created.", Theme::yellow(), "general");
    }
}

void ChatApp::join_room(const std::string& room) {
    json j;
    j["type"] = "JOIN";
    j["room"] = room;
    std::string s = j.dump();
    if (m_client) {
        m_client->send_bytes(Bytes(s.begin(), s.end()));
        m_current_room = room;
        std::lock_guard lk(m_log_mtx);
        if (m_room_logs.find(room) == m_room_logs.end())
            m_room_logs[room] = {};
    }
}

void ChatApp::broadcast_to_room(const std::string& room, const std::string& msg, std::shared_ptr<Socket> exclude) {
    std::lock_guard lk(m_clients_mtx);
    for (auto& c : m_clients) {
        if (c.room == room && c.sock != exclude) {
            auto enc = AesGcm::encrypt(c.aes_key, msg);
            json bcast;
            bcast["type"]    = "CHAT";
            bcast["nonce"]   = enc.nonce;
            bcast["payload"] = enc.ciphertext;
            bcast["sender"]  = "Network";
            bcast["room"]    = room;
            std::string bs = bcast.dump();
            c.sock->send_bytes(Bytes(bs.begin(), bs.end()));
        }
    }
}

// ── KOMUNIKACJA CZATOWA ───────────────────────────────────────────

void ChatApp::send_chat_msg(const std::string& text) {
    if (m_mode == AppMode::CLIENT && m_connected) {
        Bytes key_copy;
        { std::lock_guard lk(m_session_mtx); key_copy = m_session_key; }

        auto enc = AesGcm::encrypt(key_copy, text);

        // Funkcja Tamper (symulacja ataku)
        if (m_tamper && enc.ciphertext.size() > 4)
            enc.ciphertext[4] ^= 0xFF;

        json j;
        j["type"]    = "CHAT";
        j["nonce"]   = enc.nonce;
        j["payload"] = enc.ciphertext;
        j["sender"]  = "Client";
        j["room"]    = m_current_room;

        std::string s = j.dump();
        m_client->send_bytes(Bytes(s.begin(), s.end()));

        log("[YOU]: " + text, Theme::primary(), m_current_room);
        m_msg_count++;
    }
    else if (m_mode == AppMode::SERVER) {
        std::string msg = "[SERVER]: " + text;
        broadcast_to_room(m_current_room, msg);
        log(msg, Theme::yellow(), m_current_room);
        m_msg_count++;
    }
}

// ── LOGIKA SERWERA ────────────────────────────────────────────────

void ChatApp::start_server() {
    try {
        m_server    = std::make_unique<NetworkServer>(m_port);
        m_mode      = AppMode::SERVER;
        m_connected = true;
        create_room("general");
        log("QuantumShield Server ONLINE", Theme::green(), "general");

        std::thread([this]() {
            int id = 1;
            while (m_connected) {
                try {
                    int fd    = m_server->accept_client();
                    auto sock = std::make_shared<Socket>(fd);
                    std::thread(&ChatApp::server_client_handler, this, sock, id++).detach();
                } catch (...) { break; }
            }
        }).detach();
    } catch (const std::exception& e) {
        log(std::string("Server failed: ") + e.what(), Theme::red(), "general");
    }
}

void ChatApp::server_client_handler(std::shared_ptr<Socket> sock, int id) {
    std::string name = "Client_" + std::to_string(id);
    std::string room = "general";

    try {
        Bytes key = do_server_handshake(*sock, m_security_level);
        {
            std::lock_guard lk(m_clients_mtx);
            m_clients.push_back({sock, key, name, room});
        }
        {
            std::lock_guard lk(m_rooms_mtx);
            m_rooms[room].insert(name);
        }
        log("[+] " + name + " connected.", Theme::green(), room);

        while (m_connected) {
            auto data = sock->receive_bytes();
            auto j    = json::parse(data.begin(), data.end());
            std::string type = j["type"];

            if (type == "REQ_LEVEL") {
                std::string lvl = j["level"];
                json ack; ack["type"] = "DO_HANDSHAKE"; ack["level"] = lvl;
                sock->send_bytes(Bytes(ack.dump().begin(), ack.dump().end()));
                Bytes new_key = do_server_handshake(*sock, lvl);
                std::lock_guard lk(m_clients_mtx);
                for(auto& c : m_clients) if(c.sock == sock) c.aes_key = new_key;
                continue;
            }

            if (type == "JOIN") {
                std::string new_room = j["room"];
                create_room(new_room);
                {
                    std::lock_guard lk(m_rooms_mtx);
                    m_rooms[room].erase(name);
                    m_rooms[new_room].insert(name);
                }
                {
                    std::lock_guard lk(m_clients_mtx);
                    for (auto& c : m_clients) if (c.sock == sock) c.room = new_room;
                }
                room = new_room;
                continue;
            }

            if (type == "CHAT") {
                Bytes s_key;
                {
                    std::lock_guard lk(m_clients_mtx);
                    for (auto& c : m_clients) if (c.sock == sock) s_key = c.aes_key;
                }
                std::string plain = AesGcm::decrypt(s_key, j["nonce"].get<Bytes>(), j["payload"].get<Bytes>());
                std::string msg   = "[" + name + "]: " + plain;
                log(msg, Theme::blue_text(), room);
                broadcast_to_room(room, msg, sock);
                m_msg_count++;
            }
        }
    } catch (...) {}

    // Cleanup
    std::lock_guard lk(m_clients_mtx);
    m_clients.erase(std::remove_if(m_clients.begin(), m_clients.end(), [&](const ConnectedClient& c){ return c.sock == sock; }), m_clients.end());
}

// ── LOGIKA KLIENTA ────────────────────────────────────────────────

void ChatApp::start_client() {
    m_mode = AppMode::CLIENT;
    std::thread([this]() {
        try {
            m_client = std::make_unique<NetworkClient>();
            m_client->connect_to(m_host_buf, m_port);

            m_session_key = do_client_handshake(*m_client, m_security_level);
            m_connected = true;
            log("PQC Secure Tunnel Established", Theme::green(), m_current_room);

            while (m_connected) {
                auto data = m_client->receive_bytes();
                auto j    = json::parse(data.begin(), data.end());
                std::string type = j["type"];

                if (type == "DO_HANDSHAKE") {
                    m_session_key = do_client_handshake(*m_client, j["level"]);
                    continue;
                }

                if (type == "CHAT") {
                    std::string room = j.value("room", "general");
                    std::string plain = AesGcm::decrypt(m_session_key, j["nonce"].get<Bytes>(), j["payload"].get<Bytes>());
                    log(plain, Theme::blue_text(), room);
                    m_msg_count++;
                }
            }
        } catch (const std::exception& e) {
            log(std::string("Connection lost: ") + e.what(), Theme::red(), m_current_room);
            m_connected = false;
        }
    }).detach();
}

// ── BENCHMARKI I SZACUNKI BEZPIECZEŃSTWA (Logika) ─────────────────

void ChatApp::run_benchmarks() {
    if (m_bench_running) return;
    m_bench_running = true;
    std::thread([this]() {
        std::vector<std::string> levels = {"FAST", "BALANCED", "MAX"};
        for (auto& lvl : levels) {
            auto res = benchmark_level(lvl);
            std::lock_guard lk(m_bench_mtx);
            m_benchmarks.push_back(res);
        }
        m_bench_running = false;
    }).detach();
}

BenchmarkResult ChatApp::benchmark_level(const std::string& level) {
    BenchmarkResult r; r.level = level; const int ITERS = 1000;
    KyberKEM kem(level); DilithiumSign sig(level);

    auto t0 = clk::now();
    for(int i=0; i<ITERS; i++) {
        auto kp = kem.generate_keypair();
        auto [ct, ss] = kem.encapsulate(kp.public_key);
        kem.decapsulate(ct, kp.secret_key);
    }
    r.total_hs_ms = ms(t0, clk::now()) / ITERS; // Uproszczony pomiar dla demo
    r.done = true;
    return r;
}

std::vector<SecurityEstimate> ChatApp::build_security_estimates(const std::string& level) {
    std::vector<SecurityEstimate> est;
    est.push_back({"ML-KEM-" + level, "2^128+ operations", "Quantum-Safe (NIST)", "SECURE", Theme::green()});
    est.push_back({"RSA-2048", "2^112 operations", "Broken (Shor's Algorithm)", "VULNERABLE", Theme::red()});
    return est;
}