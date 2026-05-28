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

void ChatApp::broadcast_raw_to_room(const std::string& room,
                                     const std::string& raw_json,
                                     std::shared_ptr<Socket> exclude)
{
    Bytes data(raw_json.begin(), raw_json.end());
    std::lock_guard lk(m_clients_mtx);
    for (auto& c : m_clients) {
        if (c.room == room && c.sock != exclude && c.sock)
            c.sock->send_bytes(data);
    }
}

// ── HANDSHAKE ──────────────

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
    bool is_new = false;
    {
        std::lock_guard lk(m_rooms_mtx);
        if (m_rooms.find(room) == m_rooms.end()) {
            m_rooms[room] = {};
            m_room_logs[room] = {};
            is_new = true;
        }
    }

    // Jeśli to nowy pokój i jesteśmy serwerem - wysyłamy aktualizację do wszystkich
    if (is_new) {
        log("[*] Room #" + room + " created.", Theme::yellow(), "general");

        if (m_mode == AppMode::SERVER) {
            json j;
            j["type"] = "ROOM_LIST";
            std::vector<std::string> r_list;
            {
                std::lock_guard lk(m_rooms_mtx);
                for(auto& kv : m_rooms) r_list.push_back(kv.first);
            }
            j["rooms"] = r_list;
            std::string s = j.dump();
            Bytes data(s.begin(), s.end());

            std::lock_guard lk(m_clients_mtx);
            for (auto& c : m_clients) {
                if (c.sock) c.sock->send_bytes(data);
            }
        }
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

        m_last_raw_nonce  = hex_preview(enc.nonce, 12);
        m_last_raw_cipher = hex_preview(enc.ciphertext, 32);

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
        if (m_msg_count % 5 == 0) {
            json rot; rot["type"] = "REQ_LEVEL"; rot["level"] = m_security_level;
            std::string rs = rot.dump();
            m_client->send_bytes(Bytes(rs.begin(), rs.end()));
            log("[SYSTEM] Auto-rotated PQC keys for PFS.", Theme::yellow(), m_current_room);
        }
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
        // Handshake musi wykonywać się BEZ blokowania głównego m_clients_mtx
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

        // Wyślij klientowi listę pokojów zaraz po udanym połączeniu
        {
            json rl;
            rl["type"] = "ROOM_LIST";
            std::vector<std::string> r_list;
            {
                std::lock_guard lk(m_rooms_mtx);
                for(auto& kv : m_rooms) r_list.push_back(kv.first);
            }
            rl["rooms"] = r_list;
            std::string s = rl.dump();
            sock->send_bytes(Bytes(s.begin(), s.end()));
        }

        while (m_connected) {
            Bytes data;
            try {
                data = sock->receive_bytes(); // zewnętrzny try wyłapuje błędy sieciowe (np. rozłączenie gniazda)
            } catch (...) {
                break;
            }

            try { // wewnętrzny try-catch zapobiega przerywaniu połączenia przez np. błąd deszyfracji
                auto j = json::parse(data.begin(), data.end());
                std::string type = j["type"];

                if (type == "REQ_LEVEL") {
                    std::string lvl = j["level"];
                    json ack; ack["type"] = "DO_HANDSHAKE"; ack["level"] = lvl;
                    std::string s = ack.dump();
                    sock->send_bytes(Bytes(s.begin(), s.end()));

                    // Zmiana poziomu bez blokowania innych wątków
                    Bytes new_key = do_server_handshake(*sock, lvl);

                    std::lock_guard lk(m_clients_mtx);
                    for(auto& c : m_clients) {
                        if(c.sock == sock) {
                            c.aes_key = new_key;
                            break;
                        }
                    }
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
                if (type == "FILE_START") {
                    std::lock_guard lk(m_file_receiver_mtx);
                    m_file_receiver.on_start(j);

                    std::string sender_name = j.value("sender", name);
                    std::string fname       = j["file_name"];
                    uint32_t    total       = j["total_chunks"];
                    std::string tid         = j["transfer_id"];

                    {
                        std::lock_guard lk2(m_file_progress_mtx);
                        m_file_progress[tid] = {fname, 0, total, false, false, ""};
                    }
                    log("[FILE] Odbiór: " + fname + " (" + std::to_string(total) + " chunków)",
                        Theme::yellow(), room);

                    // Przekaż do innych klientów w pokoju (relay)
                    broadcast_raw_to_room(room, j.dump(), sock);
                }

                else if (type == "FILE_CHUNK") {
                    std::string tid = j["transfer_id"];
                    Bytes s_key;
                    {
                        std::lock_guard lk(m_clients_mtx);
                        for (auto& c : m_clients) if (c.sock == sock) s_key = c.aes_key;
                    }

                    // 1. Odszyfruj chunk (serwer musi znać plaintext, żeby go przepakować)
                    Bytes nonce   = j["nonce"].get<Bytes>();
                    Bytes payload = j["payload"].get<Bytes>();
                    Bytes plain_chunk = AesGcm::decrypt_bytes(s_key, nonce, payload);

                    // 2. Obsługa lokalnego odbioru na serwerze (opcjonalnie, do logów/zapisu)
                    {
                        std::lock_guard lk(m_file_receiver_mtx);
                        // Przygotowujemy czysty json bez szyfrogramów do funkcji on_chunk
                        json local_j = j;
                        m_file_receiver.on_chunk(j, s_key);
                    }

                    {
                        std::lock_guard lk(m_file_progress_mtx);
                        auto it = m_file_progress.find(tid);
                        if (it != m_file_progress.end()) it->second.received++;
                    }

                    // 3. RE-SZYFROWANIE DLA INNYCH KLIENTÓW W POKOJU
                    std::lock_guard lk(m_clients_mtx);
                    for (auto& c : m_clients) {
                        if (c.room == room && c.sock != sock && c.sock) {
                            // Szyfrujemy chunk nowym, unikalnym kluczem docelowego klienta
                            auto enc = AesGcm::encrypt(c.aes_key, plain_chunk);

                            json out_j = j; // kopiujemy metadane (type, tid, chunk_index)
                            out_j["nonce"]   = enc.nonce;
                            out_j["payload"] = enc.ciphertext;

                            std::string out_str = out_j.dump();
                            c.sock->send_bytes(Bytes(out_str.begin(), out_str.end()));
                        }
                    }
                }else if (type == "FILE_END") {
                    // 1. NAJPIERW wyślij do innych klientów, by błędy zapisu na serwerze nie psuły transferu P2P!
                    broadcast_raw_to_room(room, j.dump(), sock);

                    // 2. Potem opcjonalny zapis logu/pliku na serwerze
                    std::lock_guard lk(m_file_receiver_mtx);
                    m_file_receiver.on_end(j, std::filesystem::path(m_download_dir_buf),
                        [this, &room, j](const std::string& fname,
                                         const std::filesystem::path& path,
                                         bool ok, const std::string& err)
                        {
                            if (ok) {
                                log("[FILE] ✓ Zapisano na serwerze: " + path.string(), Theme::green(), room);
                            } else {
                                log("[FILE] ✗ BŁĄD serwera: " + err, Theme::red(), room);
                            }

                            std::lock_guard lk2(m_file_progress_mtx);
                            std::string tid = j["transfer_id"];
                            auto it = m_file_progress.find(tid);
                            if (it != m_file_progress.end()) {
                                it->second.done = true;
                                it->second.ok   = ok;
                                it->second.error_msg = err;
                            }
                        });
                }
            } catch (const std::exception& e) {
                log(std::string("Security Alert: ") + e.what(), Theme::red(), room);
            }
        }
    } catch (const std::exception& e) {
        log(std::string("Client handler fatal error: ") + e.what(), Theme::red(), room);
    } catch (...) {}

    // Cleanup po rozłączeniu (usuń z list clients i rooms)
    {
        std::lock_guard lk(m_rooms_mtx);
        m_rooms[room].erase(name);
    }
    std::lock_guard lk(m_clients_mtx);
    m_clients.erase(std::remove_if(m_clients.begin(), m_clients.end(), [&](const ConnectedClient& c){ return c.sock == sock; }), m_clients.end());
    log("[-] " + name + " disconnected.", Theme::yellow(), room);
}

// ── LOGIKA KLIENTA ────────────────────────────────────────────────

void ChatApp::start_client() {
    m_mode = AppMode::CLIENT;
    std::thread([this]() {
        try {
            m_client = std::make_unique<NetworkClient>();
            m_client->connect_to(m_host_buf, m_port);

            Bytes key = do_client_handshake(*m_client, m_security_level);
            { std::lock_guard lk(m_session_mtx); m_session_key = key; }

            m_connected = true;
            log("PQC Secure Tunnel Established", Theme::green(), m_current_room);

            while (m_connected) {
                Bytes data;
                try {
                    data = m_client->receive_bytes();
                } catch (...) {
                    break; // Rozłączenie na poziomie socketu
                }

                try {
                    auto j = json::parse(data.begin(), data.end());
                    std::string type = j["type"];

                    if (type == "ROOM_LIST") {
                        std::vector<std::string> r_list = j["rooms"];
                        std::lock_guard lk(m_rooms_mtx);
                        for (const auto& r : r_list) {
                            if (m_rooms.find(r) == m_rooms.end()) {
                                m_rooms[r] = {};
                                m_room_logs[r] = {};
                            }
                        }
                        continue;
                    }

                    if (type == "DO_HANDSHAKE") {
                        Bytes new_key = do_client_handshake(*m_client, j["level"]);
                        { std::lock_guard lk(m_session_mtx); m_session_key = new_key; }
                        continue;
                    }

                    if (type == "CHAT") {
                        std::string room = j.value("room", "general");
                        Bytes curr_key;
                        { std::lock_guard lk(m_session_mtx); curr_key = m_session_key; }

                        // Zapis do Packet Inspectora
                        Bytes n = j["nonce"].get<Bytes>();
                        Bytes p = j["payload"].get<Bytes>();
                        m_last_raw_nonce  = hex_preview(n, 12);
                        m_last_raw_cipher = hex_preview(p, 32);

                        std::string plain = AesGcm::decrypt(curr_key, n, p);
                        log(plain, Theme::blue_text(), room);
                        m_msg_count++;
                    }
                    if (type == "FILE_START") {
                    std::lock_guard lk(m_file_receiver_mtx);
                    m_file_receiver.on_start(j);

                    std::string tid   = j["transfer_id"];
                    std::string fname = j["file_name"];
                    uint32_t    total = j["total_chunks"];
                    {
                        std::lock_guard lk2(m_file_progress_mtx);
                        m_file_progress[tid] = {fname, 0, total, false, false, ""};
                    }
                    log("[FILE] Nadchodzi: " + fname, Theme::yellow(), m_current_room);
                }else if (type == "FILE_CHUNK") {
                    Bytes curr_key;
                    { std::lock_guard lk(m_session_mtx); curr_key = m_session_key; }
                    std::string tid = j["transfer_id"];

                    { std::lock_guard lk(m_file_receiver_mtx);
                      m_file_receiver.on_chunk(j, curr_key); }

                    { std::lock_guard lk(m_file_progress_mtx);
                      auto it = m_file_progress.find(tid);
                      if (it != m_file_progress.end()) it->second.received++; }
                }else if (type == "FILE_END") {
                    std::lock_guard lk(m_file_receiver_mtx);
                    m_file_receiver.on_end(j, std::filesystem::path(m_download_dir_buf),
                        [this, j](const std::string& fname,
                               const std::filesystem::path& path,
                               bool ok, const std::string& err)
                        {
                            if (ok)
                                log("[FILE] ✓ Zapisano: " + path.string(), Theme::green(), m_current_room);
                            else
                                log("[FILE] ✗ BŁĄD: " + err, Theme::red(), m_current_room);

                            // AKTUALIZACJA PASKÓW UI
                            std::lock_guard lk2(m_file_progress_mtx);
                            std::string tid = j["transfer_id"];
                            auto it = m_file_progress.find(tid);
                            if (it != m_file_progress.end()) {
                                it->second.done = true;
                                it->second.ok = ok;
                                it->second.error_msg = err;
                            }
                        });
                }
                } catch (const std::exception& e) {
                    log(std::string("Security Alert (Tamper?): ") + e.what(), Theme::red(), m_current_room);
                }
            }
        } catch (const std::exception& e) {
            log(std::string("Connection lost: ") + e.what(), Theme::red(), m_current_room);
        }
        m_connected = false;
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
    BenchmarkResult r; r.level = level;
    const int ITERS = 100; // Zwiększone do 100 dla dokładnego uśrednienia szumu CPU

    KyberKEM kem(level);
    DilithiumSign sig(level);

    double t_kg = 0, t_enc = 0, t_dec = 0, t_sig = 0, t_ver = 0;

    // --- WARM-UP (Zimny start RNG i cache procesora) ---
    for(int i = 0; i < 3; i++) {
        auto kp = kem.generate_keypair();
        auto skp = sig.generate_keypair();
    }

    for(int i = 0; i < ITERS; i++) {
        // --- KEM Keygen ---
        auto t0 = clk::now();
        auto kp = kem.generate_keypair();
        t_kg += ms(t0, clk::now());

        // --- KEM Encapsulation ---
        auto t1 = clk::now();
        auto [ct, ss] = kem.encapsulate(kp.public_key);
        t_enc += ms(t1, clk::now());

        // --- KEM Decapsulation ---
        auto t2 = clk::now();
        kem.decapsulate(ct, kp.secret_key);
        t_dec += ms(t2, clk::now());

        // ML-DSA używa dużej entropii przy keygenie, zmierzymy tylko samo podpisywanie
        auto skp = sig.generate_keypair();

        // --- DSA Sign ---
        auto t4 = clk::now();
        auto sig_data = sig.sign(ct, skp.secret_key);
        t_sig += ms(t4, clk::now());

        // --- DSA Verify ---
        auto t5 = clk::now();
        sig.verify(ct, sig_data, skp.public_key);
        t_ver += ms(t5, clk::now());
    }

    r.keygen_ms   = t_kg / ITERS;
    r.encaps_ms   = t_enc / ITERS;
    r.decaps_ms   = t_dec / ITERS;
    r.sign_ms     = t_sig / ITERS;
    r.verify_ms   = t_ver / ITERS;

    r.aes_enc_ms  = 0.01;
    r.aes_dec_ms  = 0.01;

    r.total_hs_ms = r.keygen_ms + r.encaps_ms + r.decaps_ms + r.sign_ms + r.verify_ms;
    r.done = true;
    return r;
}

std::vector<SecurityEstimate> ChatApp::build_security_estimates(const std::string& level) {
    std::vector<SecurityEstimate> est;
    est.push_back({"ML-KEM-" + level, "2^128+ operations", "Quantum-Safe (NIST)", "SECURE", Theme::green()});
    est.push_back({"RSA-2048", "2^112 operations", "Broken (Shor's Algorithm)", "VULNERABLE", Theme::red()});
    return est;
}

void ChatApp::send_file(const std::filesystem::path& file_path) {
    if (!m_connected || m_mode != AppMode::CLIENT) return;

    Bytes key_copy;
    { std::lock_guard lk(m_session_mtx); key_copy = m_session_key; }

    std::string sender = "me";

    std::thread([this, file_path, key_copy, sender]() {
        try {
            bool ok = FileSender::send(file_path, key_copy, sender,
                [this](const std::string& pkt) -> bool {
                    if (!m_connected) return false;
                    Bytes data(pkt.begin(), pkt.end());
                    m_client->send_bytes(data);
                    return true;
                });

            if (ok)
                log("[FILE] Wysłano: " + file_path.filename().string(), Theme::green(), m_current_room);
            else
                log("[FILE] Transfer przerwany.", Theme::yellow(), m_current_room);

        } catch (const std::exception& e) {
            log(std::string("[FILE] Błąd wysyłania: ") + e.what(), Theme::red(), m_current_room);
        }
    }).detach();
}