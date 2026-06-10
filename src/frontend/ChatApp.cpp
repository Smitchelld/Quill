#include "ChatApp.h"
#include "Theme.h"
#include "../crypto/CryptoManager.h"
#include <openssl/crypto.h>
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

std::string ChatApp::security_level() const {
    std::lock_guard lk(m_security_level_mtx);
    return m_security_level;
}

void ChatApp::set_security_level(std::string level) {
    std::lock_guard lk(m_security_level_mtx);
    m_security_level = std::move(level);
}

ChatApp::~ChatApp() {
    m_connected = false;
    if (m_client) m_client->close_socket();
    if (m_server) m_server->close_socket();

    {
        std::lock_guard lk(m_clients_mtx);
        for (auto& c : m_clients)
            if (c.sock) c.sock->close_socket();
    }

    // Higiena pamięci przy zamknięciu: cleanse kluczy i passphrase'a
    ProfileManager::logout();
    cleanse_login_buffers();
}

// ── PROFIL / LOGOWANIE ────────────────────────────────────────────

void ChatApp::cleanse_login_buffers() {
    OPENSSL_cleanse(m_login_pass_buf,     sizeof(m_login_pass_buf));
    OPENSSL_cleanse(m_new_prof_pass1_buf, sizeof(m_new_prof_pass1_buf));
    OPENSSL_cleanse(m_new_prof_pass2_buf, sizeof(m_new_prof_pass2_buf));
}

void ChatApp::do_login(const std::string& name, const std::string& passphrase) {
    try {
        ProfileInfo info = ProfileManager::unlock(name, passphrase);
        m_logged_in         = true;
        m_profile_name      = info.name;
        m_my_fingerprint    = info.fingerprint;
        m_profile_encrypted = info.encrypted;
        m_login_error.clear();
        m_login_info.clear();
        cleanse_login_buffers();
        log("Zalogowano jako '" + info.name + "' | fingerprint: " + info.fingerprint,
            Theme::green());
        if (!info.encrypted)
            log("UWAGA: klucz tozsamosci NIE jest chroniony passphrase'em",
                Theme::yellow());
    } catch (const std::exception& e) {
        m_login_error = e.what();
    }
}

void ChatApp::do_create_profile(const std::string& name,
                                const std::string& pass1, const std::string& pass2) {
    if (pass1.size() < ProfileManager::MIN_PASSPHRASE_LEN) {
        m_login_error = "Passphrase musi miec minimum " +
            std::to_string(ProfileManager::MIN_PASSPHRASE_LEN) + " znakow";
        return;
    }
    if (pass1 != pass2) {
        m_login_error = "Passphrase'y nie sa identyczne";
        return;
    }
    try {
        ProfileInfo info = ProfileManager::create(name, pass1);
        m_logged_in         = true;
        m_profile_name      = info.name;
        m_my_fingerprint    = info.fingerprint;
        m_profile_encrypted = info.encrypted;
        m_login_error.clear();
        m_login_info.clear();
        m_profiles_dirty = true;
        cleanse_login_buffers();
        log("Utworzono profil '" + info.name + "' | fingerprint: " + info.fingerprint,
            Theme::green());
        log("Przekaz swoj fingerprint rozmowcom kanalem zaufanym (out-of-band)",
            Theme::secondary());
        if (!info.encrypted)
            log("UWAGA: profil bez passphrase'a — klucz lezy na dysku plaintextem",
                Theme::yellow());
    } catch (const std::exception& e) {
        m_login_error = e.what();
    }
}

void ChatApp::do_logout() {
    // Wylogowanie tylko gdy nie ma aktywnej sesji sieciowej —
    // klucze sa potrzebne do rotacji PFS w trakcie polaczenia
    if (m_mode != AppMode::NONE) return;
    ProfileManager::logout();
    m_logged_in = false;
    m_profile_name.clear();
    m_my_fingerprint.clear();
    m_profiles_dirty = true;
    m_selected_profile = -1;
    {
        std::lock_guard lk(m_trust_mtx);
        m_has_peer_trust = false;
        m_peer_id.clear();
        m_peer_fp.clear();
    }
    m_trust_list_dirty = true;
    cleanse_login_buffers();
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

Bytes ChatApp::chat_aad(uint64_t seq) {
    std::string s = "CHAT|" + std::to_string(seq);
    return Bytes(s.begin(), s.end());
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

// ── HANDSHAKE (cienkie wrappery — cała kryptografia w CryptoManager) ──

Bytes ChatApp::do_client_handshake(Socket& sock, const std::string& level) {
    hs_clear();
    log("=== HANDSHAKE START (CLIENT) | " + level + " ===", Theme::yellow(), m_current_room);

    std::string peer_id = "srv:" + std::string(m_host_buf) + ":" + std::to_string(m_port);
    CryptoManager cm(level);

    HandshakeResult res;
    try {
        res = cm.client_handshake(sock, peer_id,
            [this](const std::string& label, double t) { hs_step(label, t); });
    } catch (const TofuMismatchError& e) {
        log("!!! SERVER KEY CHANGED — POSSIBLE MITM !!!", Theme::red(), m_current_room);
        log("  expected: " + e.expected_fp, Theme::red(), m_current_room);
        log("  received: " + e.received_fp, Theme::red(), m_current_room);
        log("  Jesli zmiana jest oczekiwana: Tools > Trusted Peers > Remove, polacz ponownie.",
            Theme::yellow(), m_current_room);
        throw;
    }

    {
        std::lock_guard lk(m_trust_mtx);
        m_has_peer_trust = true;
        m_peer_trust     = res.peer_trust;
        m_peer_id        = peer_id;
        m_peer_fp        = res.peer_fingerprint;
    }
    m_trust_list_dirty = true;

    log("Server fingerprint: " + res.peer_fingerprint +
        "  [" + TrustStore::state_name(res.peer_trust) + "]",
        res.peer_trust == TrustState::VERIFIED ? Theme::green() : Theme::yellow(),
        m_current_room);
    if (res.peer_trust == TrustState::UNVERIFIED)
        log("Pierwszy kontakt z tym serwerem — porownaj fingerprint out-of-band "
            "i oznacz VERIFIED.", Theme::yellow(), m_current_room);

    m_hs_total_ms = res.total_ms;
    return res.session_key;
}

Bytes ChatApp::do_server_handshake(Socket& sock, const std::string& level) {
    CryptoManager cm(level);
    HandshakeResult res = cm.server_handshake(sock,
        [this](const std::string& label, double t) { hs_step(label, t); });

    m_trust_list_dirty = true;
    log("Client fingerprint: " + res.peer_fingerprint +
        "  [" + TrustStore::state_name(res.peer_trust) + "]",
        res.peer_trust == TrustState::VERIFIED ? Theme::green() : Theme::yellow());

    m_hs_total_ms = res.total_ms;
    return res.session_key;
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
            uint64_t seq = ++c.send_seq;          // monotoniczny per odbiorca
            auto enc = AesGcm::encrypt(c.aes_key, msg, chat_aad(seq));
            json bcast;
            bcast["type"]    = "CHAT";
            bcast["seq"]     = seq;
            bcast["nonce"]   = enc.nonce;
            bcast["payload"] = enc.ciphertext;
            bcast["sender"]  = "Network";
            bcast["room"]    = room;
            std::string bs = bcast.dump();
            c.sock->send_bytes(Bytes(bs.begin(), bs.end()));
        }
    }
}

// ── PFS (serwer) ──────────────────────────────────────────────────

void ChatApp::perform_pfs_rotation(std::shared_ptr<Socket> sock,
                                   const std::string& level) {
    std::string room = "general";
    {
        std::lock_guard lk(m_clients_mtx);
        for (auto& c : m_clients)
            if (c.sock == sock) { room = c.room; break; }
    }

    json ack;
    ack["type"]  = "DO_HANDSHAKE";
    ack["level"] = level;
    std::string s = ack.dump();
    sock->send_bytes(Bytes(s.begin(), s.end()));

    Bytes new_key = do_server_handshake(*sock, level);

    {
        std::lock_guard lk(m_clients_mtx);
        for (auto& c : m_clients) {
            if (c.sock == sock) {
                c.aes_key  = new_key;
                c.send_seq = 0;
                c.recv_seq = 0;
                break;
            }
        }
    }
    log("[SYSTEM] PFS key rotated.", Theme::yellow(), room);
}

void ChatApp::request_pfs_rotation(const std::string& room) {
    std::lock_guard lk(m_clients_mtx);
    for (auto& c : m_clients) {
        if (c.room == room && c.sock)
            c.pending_pfs_rotation = true;
    }
}

bool ChatApp::take_pending_pfs_rotation(const std::shared_ptr<Socket>& sock) {
    std::lock_guard lk(m_clients_mtx);
    for (auto& c : m_clients) {
        if (c.sock == sock && c.pending_pfs_rotation) {
            c.pending_pfs_rotation = false;
            return true;
        }
    }
    return false;
}

// ── KOMUNIKACJA CZATOWA ───────────────────────────────────────────

void ChatApp::send_chat_msg(const std::string& text) {
    if (m_mode == AppMode::CLIENT && m_connected) {
        Bytes key_copy;
        { std::lock_guard lk(m_session_mtx); key_copy = m_session_key; }

        uint64_t seq = ++m_send_seq;
        auto enc = AesGcm::encrypt(key_copy, text, chat_aad(seq));

        m_last_raw_nonce  = hex_preview(enc.nonce, 12);
        m_last_raw_cipher = hex_preview(enc.ciphertext, 32);

        // Funkcja Tamper (symulacja ataku)
        if (m_tamper && enc.ciphertext.size() > 4)
            enc.ciphertext[4] ^= 0xFF;

        json j;
        j["type"]    = "CHAT";
        j["seq"]     = seq;
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
            request_pfs_rotation(m_current_room);
            log("[SYSTEM] Auto-rotating PFS keys for clients in #" + m_current_room + "...",
                Theme::yellow(), m_current_room);
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
        Bytes key = do_server_handshake(*sock, security_level());

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
            // Rotacja PFS inicjowana przez serwer (auto co N wiadomości) — tylko w tym wątku
            if (take_pending_pfs_rotation(sock)) {
                try {
                    perform_pfs_rotation(sock, security_level());
                } catch (const std::exception& e) {
                    log(std::string("PFS rotation failed: ") + e.what(),
                        Theme::red(), room);
                }
                continue;
            }

            std::optional<Bytes> data_opt;
            try {
                // Timeout pozwala obsłużyć pending_pfs_rotation bez czekania na klienta
                data_opt = sock->try_receive_bytes(500);
            } catch (...) {
                break;
            }
            if (!data_opt) continue;

            Bytes data = std::move(*data_opt);

            try { // wewnętrzny try-catch zapobiega przerywaniu połączenia przez np. błąd deszyfracji
                auto j = json::parse(data.begin(), data.end());
                std::string type = j["type"];

                if (type == "REQ_LEVEL") {
                    perform_pfs_rotation(sock, j["level"]);
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
                    uint64_t seq = j.value("seq", uint64_t{0});
                    Bytes s_key;
                    uint64_t last_seq = 0;
                    {
                        std::lock_guard lk(m_clients_mtx);
                        for (auto& c : m_clients)
                            if (c.sock == sock) { s_key = c.aes_key; last_seq = c.recv_seq; }
                    }
                    // AAD wiąże seq z szyfrogramem — najpierw deszyfrujemy z AAD
                    // dla zadeklarowanego seq (podmiana seq psuje tag GCM)
                    std::string plain = AesGcm::decrypt(s_key, j["nonce"].get<Bytes>(),
                                                        j["payload"].get<Bytes>(), chat_aad(seq));
                    // Anty-replay: seq musi rosnąć (fail-closed)
                    if (seq <= last_seq)
                        throw std::runtime_error("Replay detected (seq " +
                            std::to_string(seq) + " <= " + std::to_string(last_seq) + ")");
                    {
                        std::lock_guard lk(m_clients_mtx);
                        for (auto& c : m_clients) if (c.sock == sock) c.recv_seq = seq;
                    }
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
                    uint32_t idx  = j["chunk_index"].get<uint32_t>();
                    Bytes nonce   = j["nonce"].get<Bytes>();
                    Bytes payload = j["payload"].get<Bytes>();
                    Bytes plain_chunk = AesGcm::decrypt_bytes(
                        s_key, nonce, payload, FileSender::chunk_aad(tid, idx));

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
                            auto enc = AesGcm::encrypt(
                                c.aes_key, plain_chunk, FileSender::chunk_aad(tid, idx));

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

            Bytes key = do_client_handshake(*m_client, security_level());
            { std::lock_guard lk(m_session_mtx); m_session_key = key; }
            m_send_seq = 0; m_recv_seq = 0;  // świeży licznik dla nowej sesji

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
                        m_send_seq = 0; m_recv_seq = 0;  // reset po rotacji PFS
                        continue;
                    }

                    if (type == "CHAT") {
                        std::string room = j.value("room", "general");
                        uint64_t seq = j.value("seq", uint64_t{0});
                        Bytes curr_key;
                        { std::lock_guard lk(m_session_mtx); curr_key = m_session_key; }

                        // Zapis do Packet Inspectora
                        Bytes n = j["nonce"].get<Bytes>();
                        Bytes p = j["payload"].get<Bytes>();
                        m_last_raw_nonce  = hex_preview(n, 12);
                        m_last_raw_cipher = hex_preview(p, 32);

                        std::string plain = AesGcm::decrypt(curr_key, n, p, chat_aad(seq));
                        // Anty-replay (fail-closed)
                        if (seq <= m_recv_seq)
                            throw std::runtime_error("Replay detected (seq " +
                                std::to_string(seq) + " <= " + std::to_string(m_recv_seq.load()) + ")");
                        m_recv_seq = seq;
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