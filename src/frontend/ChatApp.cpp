#include "ChatApp.h"
#include "Theme.h"
#include "../crypto/CryptoManager.h"
#include <openssl/crypto.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <chrono>



using clk = std::chrono::high_resolution_clock;


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

    ProfileManager::logout();
    cleanse_login_buffers();
}


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

void ChatApp::disconnect_session() {
    m_connected = false;
    if (m_client) {
        m_client->close_socket();
        m_client.reset();
    }
    if (m_server) {
        m_server->close_socket();
        m_server.reset();
    }
    {
        std::lock_guard lk(m_clients_mtx);
        for (auto& c : m_clients)
            if (c.sock) c.sock->close_socket();
        m_clients.clear();
    }
    {
        std::lock_guard lk(m_rooms_mtx);
        m_rooms.clear();
        m_rooms["general"] = {};
        m_room_logs.clear();
        m_room_logs["general"] = {};
        m_current_room = "general";
    }
    m_room_protected.clear();
    m_pending_join_room.clear();
    OPENSSL_cleanse(m_join_room_pass_buf, sizeof(m_join_room_pass_buf));
    m_mode = AppMode::NONE;
    m_send_seq = 0;
    m_recv_seq = 0;
    {
        std::lock_guard lk(m_session_mtx);
        if (!m_session_key.empty())
            OPENSSL_cleanse(m_session_key.data(), m_session_key.size());
        m_session_key.clear();
    }
    {
        std::lock_guard lk(m_trust_mtx);
        m_has_peer_trust = false;
        m_peer_id.clear();
        m_peer_fp.clear();
    }
    hs_clear();
}

void ChatApp::do_logout() {
    disconnect_session();
    ProfileManager::logout();
    m_logged_in = false;
    m_profile_name.clear();
    m_my_fingerprint.clear();
    m_profiles_dirty = true;
    m_selected_profile = -1;
    m_trust_list_dirty = true;
    m_delete_modal_open = false;
    cleanse_login_buffers();
    OPENSSL_cleanse(m_delete_pass_buf, sizeof(m_delete_pass_buf));
}

void ChatApp::do_delete_profile(const std::string& passphrase) {
    try {
        std::string name = m_profile_name;
        disconnect_session();
        ProfileManager::remove(name, passphrase);
        m_logged_in = false;
        m_profile_name.clear();
        m_my_fingerprint.clear();
        m_profiles_dirty = true;
        m_selected_profile = -1;
        m_delete_modal_open = false;
        cleanse_login_buffers();
        OPENSSL_cleanse(m_delete_pass_buf, sizeof(m_delete_pass_buf));
        m_login_info = "Profil '" + name + "' usuniety.";
        m_login_error.clear();
    } catch (const std::exception& e) {
        m_login_error = e.what();
    }
}

void ChatApp::submit_new_room() {
    if (m_new_room_buf[0] == '\0') return;
    std::string r(m_new_room_buf);
    std::string pass(m_new_room_pass_buf);

    {
        std::lock_guard lk(m_rooms_mtx);
        if (m_rooms.count(r)) {
            log("[ROOM] Pokoj #" + r + " juz istnieje.", Theme::red(), m_current_room);
            return;
        }
    }

    if (m_mode == AppMode::SERVER) {
        if (!create_room(r, pass))
            log("[ROOM] Pokoj #" + r + " juz istnieje.", Theme::red(), m_current_room);
    } else if (m_mode == AppMode::CLIENT && m_connected && m_client) {
        if (!pass.empty()) {
            json j;
            j["type"]     = "CREATE_ROOM";
            j["room"]     = r;
            j["password"] = pass;
            client_send(j.dump());
        }
        join_room(r, pass);
    }
    m_new_room_buf[0] = '\0';
    OPENSSL_cleanse(m_new_room_pass_buf, sizeof(m_new_room_pass_buf));
}

void ChatApp::apply_server_security_level(const std::string& level) {
    if (m_mode != AppMode::SERVER) return;
    set_security_level(level);

        // PFS rotation must run in client handler thread (not UI).
    {
        std::lock_guard lk(m_clients_mtx);
        for (auto& c : m_clients) {
            if (c.sock) {
                c.pending_pfs_level    = level;
                c.pending_pfs_rotation = true;
            }
        }
    }
    log("[SYSTEM] Zmiana poziomu PQC na " + level +
        " — re-handshake klientow w toku...", Theme::yellow(), m_current_room);
}

void ChatApp::load_persisted_rooms() {
    try {
        for (const auto& r : RoomStore::list()) {
            std::lock_guard lk(m_rooms_mtx);
            m_rooms[r.name] = {};
            if (m_room_logs.find(r.name) == m_room_logs.end())
                m_room_logs[r.name] = {};
            m_room_protected[r.name] = r.password_protected;
        }
    } catch (const std::exception& e) {
        log(std::string("[ROOM] ") + e.what(), Theme::red(), "general");
    }
}

void ChatApp::broadcast_room_list() {
    if (m_mode != AppMode::SERVER) return;

    json rl;
    rl["type"] = "ROOM_LIST";
    json rooms = json::array();
    {
        std::lock_guard lk(m_rooms_mtx);
        for (const auto& [name, _] : m_rooms) {
            json r;
            r["name"] = name;
            bool prot = false;
            try { prot = RoomStore::is_protected(name); } catch (...) {}
            r["protected"] = prot;
            m_room_protected[name] = prot;
            rooms.push_back(std::move(r));
        }
    }
    rl["rooms"] = rooms;
    std::string s = rl.dump();
    Bytes data(s.begin(), s.end());

    std::lock_guard lk(m_clients_mtx);
    for (auto& c : m_clients) {
        if (c.sock) c.sock->send_bytes(data);
    }
}

void ChatApp::client_send(const Bytes& data) {
    if (!m_client) return;
    std::lock_guard lk(m_client_send_mtx);
    m_client->send_bytes(data);
}

void ChatApp::client_send(const std::string& s) {
    client_send(Bytes(s.begin(), s.end()));
}

void ChatApp::send_display_name() {
    if (!m_client || !m_connected) return;
    json j;
    j["type"]         = "SET_DISPLAY_NAME";
    j["display_name"] = m_profile_name;
    client_send(j.dump());
}


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


Bytes ChatApp::do_client_handshake(Socket& sock, const std::string& level,
                                   bool server_rehandshake) {
    if (!server_rehandshake) {
        hs_clear();
        log("=== HANDSHAKE START (CLIENT) | " + level + " ===",
            Theme::yellow(), m_current_room);
    }

    std::string peer_id = "srv:" + std::string(m_host_buf) + ":" + std::to_string(m_port);
    CryptoManager cm(level);

    HandshakeResult res;
    try {
        res = cm.client_handshake(sock, peer_id,
            [this](const std::string& label, double t) { hs_step(label, t); },
            server_rehandshake);
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


bool ChatApp::create_room(const std::string& room, const std::string& password) {
    {
        std::lock_guard lk(m_rooms_mtx);
        if (m_rooms.count(room))
            return false;
    }
    if (m_mode == AppMode::SERVER && RoomStore::exists(room))
        return false;

    {
        std::lock_guard lk(m_rooms_mtx);
        m_rooms[room] = {};
        m_room_logs[room] = {};
    }

    if (m_mode == AppMode::SERVER) {
        try {
            RoomStore::add(room, password);
            m_room_protected[room] = !password.empty();
        } catch (const std::exception& e) {
            std::lock_guard lk(m_rooms_mtx);
            m_rooms.erase(room);
            m_room_logs.erase(room);
            log(std::string("[ROOM] ") + e.what(), Theme::red(), "general");
            return false;
        }
        log("[*] Room #" + room + " created." +
            (password.empty() ? "" : " (chroniony haslem)"),
            Theme::yellow(), "general");
        broadcast_room_list();
    } else {
        log("[*] Room #" + room + " created.", Theme::yellow(), "general");
    }
    return true;
}

void ChatApp::delete_room(const std::string& room) {
    if (room == "general") {
        log("[ROOM] Nie mozna usunac pokoju #general.", Theme::red(), m_current_room);
        return;
    }
    {
        std::lock_guard lk(m_rooms_mtx);
        if (!m_rooms.count(room)) {
            log("[ROOM] Pokoj #" + room + " nie istnieje.", Theme::red(), m_current_room);
            return;
        }
    }

    if (m_mode == AppMode::SERVER) {
        try {
            RoomStore::remove(room);
        } catch (const std::exception& e) {
            log(std::string("[ROOM] ") + e.what(), Theme::red(), m_current_room);
            return;
        }
    }

    {
        std::lock_guard lk(m_rooms_mtx);
        m_rooms.erase(room);
        m_room_protected.erase(room);
    }

    if (m_mode == AppMode::SERVER) {
        json ev;
        ev["type"] = "ROOM_DELETED";
        ev["room"] = room;
        std::string evs = ev.dump();
        Bytes evb(evs.begin(), evs.end());

        std::lock_guard lk(m_clients_mtx);
        for (auto& c : m_clients) {
            if (c.room == room) {
                c.room = "general";
                if (c.sock) c.sock->send_bytes(evb);
            }
        }
        broadcast_room_list();
    }

    if (m_current_room == room)
        m_current_room = "general";

    log("[ROOM] Usunieto pokoj #" + room + ".", Theme::yellow(), "general");
}

void ChatApp::join_room(const std::string& room, const std::string& password) {
    if (m_mode == AppMode::CLIENT && m_connected && m_client) {
        bool need_pass = false;
        auto it = m_room_protected.find(room);
        if (it != m_room_protected.end())
            need_pass = it->second;
        if (need_pass && password.empty()) {
            m_pending_join_room = room;
            return;
        }
        json j;
        j["type"] = "JOIN";
        j["room"] = room;
        if (!password.empty())
            j["password"] = password;
        client_send(j.dump());
        m_current_room = room;
        m_pending_join_room.clear();
        OPENSSL_cleanse(m_join_room_pass_buf, sizeof(m_join_room_pass_buf));
        std::lock_guard lk(m_log_mtx);
        if (m_room_logs.find(room) == m_room_logs.end())
            m_room_logs[room] = {};
    } else if (m_mode == AppMode::SERVER) {
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
            uint64_t seq = ++c.send_seq;
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
    log("[SYSTEM] Klucz sesji odswiezony (PQC " + level + ").",
        Theme::yellow(), room);
}

void ChatApp::request_pfs_rotation(const std::string& room) {
    std::lock_guard lk(m_clients_mtx);
    for (auto& c : m_clients) {
        if (c.room == room && c.sock)
            c.pending_pfs_rotation = true;
    }
}

bool ChatApp::take_pending_pfs_rotation(const std::shared_ptr<Socket>& sock,
                                        std::string& out_level) {
    std::lock_guard lk(m_clients_mtx);
    for (auto& c : m_clients) {
        if (c.sock == sock && c.pending_pfs_rotation) {
            c.pending_pfs_rotation = false;
            out_level = c.pending_pfs_level.empty() ? security_level() : c.pending_pfs_level;
            c.pending_pfs_level.clear();
            return true;
        }
    }
    return false;
}


void ChatApp::send_chat_msg(const std::string& text) {
    if (m_mode == AppMode::CLIENT && m_connected) {
        Bytes key_copy;
        { std::lock_guard lk(m_session_mtx); key_copy = m_session_key; }

        uint64_t seq = ++m_send_seq;
        auto enc = AesGcm::encrypt(key_copy, text, chat_aad(seq));

        m_last_raw_nonce  = hex_preview(enc.nonce, 12);
        m_last_raw_cipher = hex_preview(enc.ciphertext, 32);

        if (m_tamper && enc.ciphertext.size() > 4)
            enc.ciphertext[4] ^= 0xFF;

        json j;
        j["type"]    = "CHAT";
        j["seq"]     = seq;
        j["nonce"]   = enc.nonce;
        j["payload"] = enc.ciphertext;
        j["sender"]  = m_profile_name;
        j["room"]    = m_current_room;

        client_send(j.dump());

        log("[YOU]: " + text, Theme::primary(), m_current_room);
        m_msg_count++;
    }
    else if (m_mode == AppMode::SERVER) {
        std::string msg = "[" + m_profile_name + "]: " + text;
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


void ChatApp::start_server() {
    try {
        m_server    = std::make_unique<NetworkServer>(m_port);
        m_mode      = AppMode::SERVER;
        m_connected = true;
        load_persisted_rooms();
        create_room("general");
        log("QuantumShield Server ONLINE (host: " + m_profile_name + ")",
            Theme::green(), "general");

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
    (void)id;
    std::string name = "...";
    std::string room = "general";

    try {
        json cfg;
        cfg["type"]  = "SERVER_CONFIG";
        cfg["level"] = security_level();
        std::string cs = cfg.dump();
        sock->send_bytes(Bytes(cs.begin(), cs.end()));

        Bytes key = do_server_handshake(*sock, security_level());

        {
            std::lock_guard lk(m_clients_mtx);
            m_clients.push_back({sock, key, name, room});
        }
        {
            std::lock_guard lk(m_rooms_mtx);
            m_rooms[room].insert(name);
        }
        log("[+] Klient polaczony (oczekiwanie na nick...).", Theme::green(), room);

        {
            json rl;
            rl["type"] = "ROOM_LIST";
            json rooms = json::array();
            {
                std::lock_guard lk(m_rooms_mtx);
                for (const auto& [rname, _] : m_rooms) {
                    json r;
                    r["name"] = rname;
                    bool prot = false;
                    try { prot = RoomStore::is_protected(rname); } catch (...) {}
                    r["protected"] = prot;
                    rooms.push_back(std::move(r));
                }
            }
            rl["rooms"] = rooms;
            std::string s = rl.dump();
            sock->send_bytes(Bytes(s.begin(), s.end()));
        }

        while (m_connected) {
            std::string pfs_level;
            if (take_pending_pfs_rotation(sock, pfs_level)) {
                try {
                    perform_pfs_rotation(sock, pfs_level);
                } catch (const std::exception& e) {
                    log(std::string("PFS rotation failed: ") + e.what(),
                        Theme::red(), room);
                }
                continue;
            }

            std::optional<Bytes> data_opt;
            try {
                data_opt = sock->try_receive_bytes(500);
            } catch (...) {
                break;
            }
            if (!data_opt) continue;

            Bytes data = std::move(*data_opt);

            try {
                auto j = json::parse(data.begin(), data.end());
                std::string type = j["type"];

                if (type == "REQ_LEVEL" || type == "REQ_PFS") {
                    perform_pfs_rotation(sock, security_level());
                    continue;
                }

                if (type == "SET_DISPLAY_NAME") {
                    std::string new_name = j.value("display_name", "");
                    if (new_name.empty() || new_name.size() > 32) continue;
                    std::string old_name = name;
                    name = new_name;
                    {
                        std::lock_guard lk(m_rooms_mtx);
                        if (old_name != "...") m_rooms[room].erase(old_name);
                        m_rooms[room].insert(name);
                    }
                    {
                        std::lock_guard lk(m_clients_mtx);
                        for (auto& c : m_clients) if (c.sock == sock) c.name = name;
                    }
                    log("[+] " + name + " dolaczyl.", Theme::green(), room);
                    continue;
                }

                if (type == "CREATE_ROOM") {
                    std::string new_room = j["room"];
                    std::string pass     = j.value("password", "");
                    json reply;
                    if (create_room(new_room, pass)) {
                        reply["type"] = "ROOM_CREATED";
                        reply["room"] = new_room;
                    } else {
                        reply["type"] = "ROOM_EXISTS";
                        reply["room"] = new_room;
                    }
                    std::string os = reply.dump();
                    sock->send_bytes(Bytes(os.begin(), os.end()));
                    continue;
                }

                if (type == "JOIN") {
                    std::string new_room = j["room"];
                    std::string pass     = j.value("password", "");
                    if (!RoomStore::exists(new_room))
                        create_room(new_room, "");
                    if (RoomStore::is_protected(new_room) &&
                        !RoomStore::verify_password(new_room, pass)) {
                        json deny;
                        deny["type"] = "JOIN_DENIED";
                        deny["room"] = new_room;
                        std::string ds = deny.dump();
                        sock->send_bytes(Bytes(ds.begin(), ds.end()));
                        log("[!] " + name + " — zle haslo do #" + new_room,
                            Theme::red(), room);
                        continue;
                    }
                    {
                        std::lock_guard lk(m_rooms_mtx);
                        if (name != "...") m_rooms[room].erase(name);
                        m_rooms[new_room].insert(name);
                    }
                    {
                        std::lock_guard lk(m_clients_mtx);
                        for (auto& c : m_clients) if (c.sock == sock) c.room = new_room;
                    }
                    room = new_room;
                    log("[*] " + name + " -> #" + new_room, Theme::yellow(), room);
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
                                        // Decrypt with chat AAD before replay check (seq tampering breaks GCM tag).
                    std::string plain = AesGcm::decrypt(s_key, j["nonce"].get<Bytes>(),
                                                        j["payload"].get<Bytes>(), chat_aad(seq));
                                        // Anti-replay: seq must increase (fail-closed).
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
                    std::string tid = j["transfer_id"];
                    {
                        std::lock_guard lk(m_file_origin_mtx);
                        m_file_origin_sock[tid] = sock;
                    }

                    std::lock_guard lk(m_file_receiver_mtx);
                    m_file_receiver.on_start(j);

                    std::string sender_name = j.value("sender", name);
                    std::string fname       = j["file_name"];
                    uint32_t    total       = j["total_chunks"];

                    {
                        std::lock_guard lk2(m_file_progress_mtx);
                        m_file_progress[tid] = {fname, 0, total, false, false, ""};
                    }
                    log("[FILE] Odbiór: " + fname + " (" + std::to_string(total) + " chunków)",
                        Theme::yellow(), room);

                    broadcast_raw_to_room(room, j.dump(), sock);
                }

                else if (type == "FILE_CHUNK") {
                    // Decrypt on server so relay can re-encrypt per recipient session key.
                    std::string tid = j["transfer_id"];
                    Bytes s_key;
                    {
                        std::lock_guard lk(m_clients_mtx);
                        for (auto& c : m_clients) if (c.sock == sock) s_key = c.aes_key;
                    }

                    uint32_t idx  = j["chunk_index"].get<uint32_t>();
                    Bytes nonce   = j["nonce"].get<Bytes>();
                    Bytes payload = j["payload"].get<Bytes>();
                    Bytes plain_chunk = AesGcm::decrypt_bytes(
                        s_key, nonce, payload, FileSender::chunk_aad(tid, idx));

                    uint32_t before = 0, after = 0;
                    {
                        std::lock_guard lk(m_file_receiver_mtx);
                        before = m_file_receiver.progress(tid).first;
                        m_file_receiver.on_chunk(j, s_key);
                        after = m_file_receiver.progress(tid).first;
                    }

                    if (after > before) {
                        std::lock_guard lk(m_file_progress_mtx);
                        auto it = m_file_progress.find(tid);
                        if (it != m_file_progress.end()) it->second.received++;
                    }
                    try_complete_incoming_file(tid, room);

                    std::lock_guard lk(m_clients_mtx);
                    for (auto& c : m_clients) {
                        if (c.room == room && c.sock != sock && c.sock) {
                            auto enc = AesGcm::encrypt(
                                c.aes_key, plain_chunk, FileSender::chunk_aad(tid, idx));

                            json out_j = j;
                            out_j["nonce"]   = enc.nonce;
                            out_j["payload"] = enc.ciphertext;

                            std::string out_str = out_j.dump();
                            c.sock->send_bytes(Bytes(out_str.begin(), out_str.end()));
                        }
                    }
                }else if (type == "FILE_END") {
                    // Relay FILE_END before local save so P2P isn't blocked by server disk errors.
                    broadcast_raw_to_room(room, j.dump(), sock);

                    std::string tid = j["transfer_id"];
                    FileEndStatus st;
                    json nack;
                    {
                        std::lock_guard lk(m_file_receiver_mtx);
                        st = m_file_receiver.on_end(j, std::filesystem::path(m_download_dir_buf),
                            [this, &room, tid](const std::string& fname,
                                               const std::filesystem::path& path,
                                               bool ok, const std::string& err)
                            {
                                if (ok) {
                                    log("[FILE] ✓ Zapisano na serwerze: " + path.string(),
                                        Theme::green(), room);
                                } else {
                                    log("[FILE] ✗ BŁĄD serwera: " + err, Theme::red(), room);
                                }

                                std::lock_guard lk2(m_file_progress_mtx);
                                auto it = m_file_progress.find(tid);
                                if (it != m_file_progress.end()) {
                                    it->second.done = true;
                                    it->second.ok   = ok;
                                    it->second.error_msg = err;
                                }
                            });
                        if (st == FileEndStatus::NeedsNack)
                            nack = m_file_receiver.make_nack(tid);
                    }
                    if (st == FileEndStatus::NeedsNack) {
                        log("[FILE] NACK → nadawca: brakuje " +
                            std::to_string(nack["missing"].size()) + " chunków",
                            Theme::yellow(), room);
                        std::shared_ptr<Socket> origin;
                        {
                            std::lock_guard lk(m_file_origin_mtx);
                            auto it = m_file_origin_sock.find(tid);
                            if (it != m_file_origin_sock.end()) origin = it->second.lock();
                        }
                        if (origin) {
                            std::string s = nack.dump();
                            origin->send_bytes(Bytes(s.begin(), s.end()));
                        }
                    }
                }
                else if (type == "FILE_NACK") {
                    std::string tid = j["transfer_id"];
                    bool server_origin = false;
                    {
                        std::lock_guard lk(m_server_file_mtx);
                        server_origin = m_server_file_origins.count(tid) > 0;
                    }
                    if (server_origin) {
                        auto missing = j["missing"].get<std::vector<uint32_t>>();
                        retransmit_server_file_chunks(tid, sock, missing);
                        log("[FILE] Retransmisja (serwer) " +
                            std::to_string(missing.size()) + " chunkow do " + name,
                            Theme::yellow(), room);
                    } else {
                        std::shared_ptr<Socket> origin;
                        {
                            std::lock_guard lk(m_file_origin_mtx);
                            auto it = m_file_origin_sock.find(tid);
                            if (it != m_file_origin_sock.end()) origin = it->second.lock();
                        }
                        if (origin && origin != sock) {
                            std::string s = j.dump();
                            origin->send_bytes(Bytes(s.begin(), s.end()));
                            log("[FILE] NACK przekazany do nadawcy (" + tid + ")",
                                Theme::yellow(), room);
                        }
                    }
                }
            } catch (const std::exception& e) {
                log(std::string("Security Alert: ") + e.what(), Theme::red(), room);
            }
        }
    } catch (const std::exception& e) {
        log(std::string("Client handler fatal error: ") + e.what(), Theme::red(), room);
    } catch (...) {}

    {
        std::lock_guard lk(m_rooms_mtx);
        m_rooms[room].erase(name);
    }
    std::lock_guard lk(m_clients_mtx);
    m_clients.erase(std::remove_if(m_clients.begin(), m_clients.end(), [&](const ConnectedClient& c){ return c.sock == sock; }), m_clients.end());
    log("[-] " + name + " disconnected.", Theme::yellow(), room);
}


void ChatApp::start_client() {
    m_mode = AppMode::CLIENT;
    std::thread([this]() {
        try {
            m_client = std::make_unique<NetworkClient>();
            m_client->connect_to(m_host_buf, m_port);

            auto cfg_data = m_client->receive_bytes();
            auto cfg      = json::parse(cfg_data.begin(), cfg_data.end());
            if (cfg.value("type", "") == "SERVER_CONFIG") {
                std::string srv_level = cfg.at("level").get<std::string>();
                set_security_level(srv_level);
                log("Poziom serwera: " + srv_level, Theme::blue_text(), m_current_room);
            }

            Bytes key = do_client_handshake(*m_client, security_level());
            { std::lock_guard lk(m_session_mtx); m_session_key = key; }
            m_send_seq = 0; m_recv_seq = 0;

            m_connected = true;
            send_display_name();
            log("PQC Secure Tunnel Established", Theme::green(), m_current_room);

            while (m_connected) {
                Bytes data;
                try {
                    data = m_client->receive_bytes();
                } catch (...) {
                    break;
                }

                try {
                    auto j = json::parse(data.begin(), data.end());
                    std::string type = j["type"];

                    if (type == "ROOM_LIST") {
                        std::lock_guard lk(m_rooms_mtx);
                        for (const auto& entry : j["rooms"]) {
                            std::string rname;
                            bool prot = false;
                            if (entry.is_string()) {
                                rname = entry.get<std::string>();
                            } else {
                                rname = entry.at("name").get<std::string>();
                                prot  = entry.value("protected", false);
                            }
                            if (m_rooms.find(rname) == m_rooms.end()) {
                                m_rooms[rname] = {};
                                m_room_logs[rname] = {};
                            }
                            m_room_protected[rname] = prot;
                        }
                        continue;
                    }

                    if (type == "JOIN_DENIED") {
                        std::string denied = j.value("room", "?");
                        log("[!] Odmowa dolaczenia do #" + denied +
                            " (zle haslo?)", Theme::red(), m_current_room);
                        continue;
                    }

                    if (type == "DO_HANDSHAKE") {
                        std::string lvl = j.at("level").get<std::string>();
                        set_security_level(lvl);
                        try {
                            Bytes new_key = do_client_handshake(*m_client, lvl, true);
                            { std::lock_guard lk(m_session_mtx); m_session_key = new_key; }
                            m_send_seq = 0; m_recv_seq = 0;
                            log("[SYSTEM] Nowy klucz sesji (PQC " + lvl + ")",
                                Theme::yellow(), m_current_room);
                        } catch (const std::exception& e) {
                            log(std::string("[SYSTEM] Re-handshake failed: ") + e.what(),
                                Theme::red(), m_current_room);
                        }
                        continue;
                    }

                    if (type == "ROOM_CREATED") {
                        std::string rname = j.value("room", "");
                        log("[*] Pokoj #" + rname + " utworzony na serwerze.",
                            Theme::green(), m_current_room);
                        continue;
                    }

                    if (type == "ROOM_EXISTS") {
                        std::string rname = j.value("room", "?");
                        log("[ROOM] Pokoj #" + rname + " juz istnieje.",
                            Theme::red(), m_current_room);
                        continue;
                    }

                    if (type == "ROOM_DELETED") {
                        std::string rname = j.value("room", "");
                        {
                            std::lock_guard lk(m_rooms_mtx);
                            m_rooms.erase(rname);
                            m_room_protected.erase(rname);
                        }
                        if (m_current_room == rname)
                            m_current_room = "general";
                        log("[ROOM] Pokoj #" + rname + " zostal usuniety.",
                            Theme::yellow(), m_current_room);
                        continue;
                    }

                    if (type == "CHAT") {
                        std::string room = j.value("room", "general");
                        uint64_t seq = j.value("seq", uint64_t{0});
                        Bytes curr_key;
                        { std::lock_guard lk(m_session_mtx); curr_key = m_session_key; }

                        Bytes n = j["nonce"].get<Bytes>();
                        Bytes p = j["payload"].get<Bytes>();
                        m_last_raw_nonce  = hex_preview(n, 12);
                        m_last_raw_cipher = hex_preview(p, 32);

                        std::string plain = AesGcm::decrypt(curr_key, n, p, chat_aad(seq));
                        // Anti-replay: seq must increase (fail-closed).
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

                    uint32_t before = 0, after = 0;
                    {
                        std::lock_guard lk(m_file_receiver_mtx);
                        before = m_file_receiver.progress(tid).first;
                        m_file_receiver.on_chunk(j, curr_key);
                        after = m_file_receiver.progress(tid).first;
                    }

                    if (after > before) {
                        std::lock_guard lk(m_file_progress_mtx);
                        auto it = m_file_progress.find(tid);
                        if (it != m_file_progress.end()) it->second.received++;
                    }
                    try_complete_incoming_file(tid, m_current_room);
                }else if (type == "FILE_END") {
                    std::string tid = j["transfer_id"];
                    FileEndStatus st;
                    json nack;
                    {
                        std::lock_guard lk(m_file_receiver_mtx);
                        st = m_file_receiver.on_end(j, std::filesystem::path(m_download_dir_buf),
                            [this, tid](const std::string& fname,
                                        const std::filesystem::path& path,
                                        bool ok, const std::string& err)
                            {
                                if (ok)
                                    log("[FILE] ✓ Zapisano: " + path.string(),
                                        Theme::green(), m_current_room);
                                else
                                    log("[FILE] ✗ BŁĄD: " + err, Theme::red(), m_current_room);

                                std::lock_guard lk2(m_file_progress_mtx);
                                auto it = m_file_progress.find(tid);
                                if (it != m_file_progress.end()) {
                                    it->second.done = true;
                                    it->second.ok = ok;
                                    it->second.error_msg = err;
                                }
                            });
                        if (st == FileEndStatus::NeedsNack)
                            nack = m_file_receiver.make_nack(tid);
                    }
                    if (st == FileEndStatus::NeedsNack) {
                        log("[FILE] NACK: proszę o " +
                            std::to_string(nack["missing"].size()) + " chunków",
                            Theme::yellow(), m_current_room);
                        send_file_nack(nack);
                    }
                }else if (type == "FILE_NACK") {
                    handle_outbound_nack(j);
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
    const int ITERS = 100;

    KyberKEM kem(level);
    DilithiumSign sig(level);

    double t_kg = 0, t_enc = 0, t_dec = 0, t_sig = 0, t_ver = 0;

    for(int i = 0; i < 3; i++) {
        auto kp = kem.generate_keypair();
        auto skp = sig.generate_keypair();
    }

    for(int i = 0; i < ITERS; i++) {
        auto t0 = clk::now();
        auto kp = kem.generate_keypair();
        t_kg += ms(t0, clk::now());

        auto t1 = clk::now();
        auto [ct, ss] = kem.encapsulate(kp.public_key);
        t_enc += ms(t1, clk::now());

        auto t2 = clk::now();
        kem.decapsulate(ct, kp.secret_key);
        t_dec += ms(t2, clk::now());

        auto skp = sig.generate_keypair();

        auto t4 = clk::now();
        auto sig_data = sig.sign(ct, skp.secret_key);
        t_sig += ms(t4, clk::now());

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

void ChatApp::retain_outbound_session(FileSenderSession session) {
    const std::string tid = session.transfer_id();
    {
        std::lock_guard lk(m_outbound_mtx);
        m_outbound_sessions[tid] = std::move(session);
    }
    std::thread([this, tid]() {
        std::this_thread::sleep_for(std::chrono::minutes(2));
        std::lock_guard lk(m_outbound_mtx);
        m_outbound_sessions.erase(tid);
        std::lock_guard lk2(m_file_origin_mtx);
        m_file_origin_sock.erase(tid);
        std::lock_guard lk3(m_server_file_mtx);
        m_server_file_origins.erase(tid);
    }).detach();
}

void ChatApp::retransmit_server_file_chunks(const std::string& transfer_id,
                                            const std::shared_ptr<Socket>& dest,
                                            const std::vector<uint32_t>& indices)
{
    if (indices.empty() || !dest) return;

    Bytes dest_key;
    {
        std::lock_guard lk(m_clients_mtx);
        for (auto& c : m_clients)
            if (c.sock == dest) { dest_key = c.aes_key; break; }
    }
    if (dest_key.empty()) return;

    std::lock_guard lk(m_outbound_mtx);
    auto it = m_outbound_sessions.find(transfer_id);
    if (it == m_outbound_sessions.end()) return;

    for (uint32_t idx : indices) {
        std::string pkt = it->second.build_chunk_json(idx, dest_key).dump();
        dest->send_bytes(Bytes(pkt.begin(), pkt.end()));
    }
}

void ChatApp::send_file_nack(const json& nack) {
    if (!m_connected || !m_client) return;
    client_send(nack.dump());
}

void ChatApp::handle_outbound_nack(const json& j) {
    std::string tid = j["transfer_id"];
    auto missing = j["missing"].get<std::vector<uint32_t>>();
    if (missing.empty()) return;

    std::lock_guard lk(m_outbound_mtx);
    auto it = m_outbound_sessions.find(tid);
    if (it == m_outbound_sessions.end()) return;

    auto send_cb = [this](const std::string& pkt) -> bool {
        if (!m_connected || !m_client) return false;
        client_send(pkt);
        return true;
    };

    if (it->second.retransmit(missing, send_cb))
        log("[FILE] Retransmisja " + std::to_string(missing.size()) + " chunków",
            Theme::yellow(), m_current_room);
}

void ChatApp::try_complete_incoming_file(const std::string& transfer_id,
                                         const std::string& room)
{
    std::lock_guard lk(m_file_receiver_mtx);
    m_file_receiver.try_finalize(transfer_id, std::filesystem::path(m_download_dir_buf),
        [this, transfer_id, room](const std::string& fname,
                                  const std::filesystem::path& path,
                                  bool ok, const std::string& err)
        {
            if (ok)
                log("[FILE] ✓ Zapisano: " + path.string(), Theme::green(), room);
            else
                log("[FILE] ✗ BŁĄD: " + err, Theme::red(), room);

            std::lock_guard lk2(m_file_progress_mtx);
            auto it = m_file_progress.find(transfer_id);
            if (it != m_file_progress.end()) {
                it->second.done = true;
                it->second.ok = ok;
                it->second.error_msg = err;
            }
        });
}

void ChatApp::send_file(const std::filesystem::path& file_path) {
    if (!m_connected) return;
    if (m_mode != AppMode::CLIENT && m_mode != AppMode::SERVER) return;

    constexpr uintmax_t kMaxFileBytes = 100u * 1024u * 1024u;
    std::error_code ec;
    const auto fsize = std::filesystem::file_size(file_path, ec);
    if (ec) {
        log("[FILE] Nie mozna odczytac rozmiaru pliku.", Theme::red(), m_current_room);
        return;
    }
    if (fsize > kMaxFileBytes) {
        log("[FILE] Plik za duzy (max 100 MB).", Theme::red(), m_current_room);
        return;
    }

    if (m_mode == AppMode::SERVER) {
        bool has_recipients = false;
        {
            std::lock_guard lk(m_clients_mtx);
            for (auto& c : m_clients)
                if (c.room == m_current_room && c.sock) { has_recipients = true; break; }
        }
        if (!has_recipients) {
            log("[FILE] Brak klientow w pokoju #" + m_current_room + ".",
                Theme::red(), m_current_room);
            return;
        }
    }

    Bytes key_copy;
    if (m_mode == AppMode::CLIENT) {
        std::lock_guard lk(m_session_mtx);
        key_copy = m_session_key;
    }

    std::string sender = m_profile_name;
    std::string room   = m_current_room;
    const bool as_server = (m_mode == AppMode::SERVER);

    std::thread([this, file_path, key_copy, sender, room, as_server]() {
        std::string tid;
        try {
            FileSenderSession session =
                FileSenderSession::open(file_path, key_copy, sender);

            tid = session.transfer_id();
            const uint32_t total = session.total_chunks();
            const std::string fname = file_path.filename().string();

            {
                std::lock_guard lk(m_file_progress_mtx);
                m_file_progress[tid] = {fname, 0, total, false, false, ""};
            }
            log("[FILE] Wysylanie: " + fname + " (" +
                std::to_string(total) + " chunkow)", Theme::yellow(), room);

            bool ok = false;

            if (as_server) {
                {
                    std::lock_guard lk(m_server_file_mtx);
                    m_server_file_origins.insert(tid);
                }

                auto broadcast = [this, &room](const std::string& pkt) -> bool {
                    if (!m_connected) return false;
                    broadcast_raw_to_room(room, pkt, nullptr);
                    return true;
                };

                ok = session.send_start(broadcast);
                for (uint32_t i = 0; ok && i < total; ++i) {
                    std::vector<std::shared_ptr<Socket>> targets;
                    std::vector<Bytes> keys;
                    {
                        std::lock_guard lk(m_clients_mtx);
                        for (auto& c : m_clients) {
                            if (c.room == room && c.sock) {
                                targets.push_back(c.sock);
                                keys.push_back(c.aes_key);
                            }
                        }
                    }
                    if (targets.empty()) { ok = false; break; }

                    for (size_t t = 0; t < targets.size(); ++t) {
                        std::string pkt =
                            session.build_chunk_json(i, keys[t]).dump();
                        targets[t]->send_bytes(Bytes(pkt.begin(), pkt.end()));
                    }

                    {
                        std::lock_guard lk(m_file_progress_mtx);
                        auto it = m_file_progress.find(tid);
                        if (it != m_file_progress.end())
                            it->second.received = i + 1;
                    }
                    if ((i + 1) % 8 == 0)
                        std::this_thread::sleep_for(std::chrono::milliseconds(2));
                }
                if (ok)
                    ok = session.send_end(broadcast);
            } else {
                auto send_cb = [this](const std::string& pkt) -> bool {
                    if (!m_connected || !m_client) return false;
                    client_send(pkt);
                    return true;
                };

                ok = session.send_start(send_cb);
                for (uint32_t i = 0; ok && i < total; ++i) {
                    ok = session.send_chunk(i, send_cb);
                    {
                        std::lock_guard lk(m_file_progress_mtx);
                        auto it = m_file_progress.find(tid);
                        if (it != m_file_progress.end())
                            it->second.received = i + 1;
                    }
                    if ((i + 1) % 8 == 0)
                        std::this_thread::sleep_for(std::chrono::milliseconds(2));
                }
                if (ok)
                    ok = session.send_end(send_cb);
            }

            retain_outbound_session(std::move(session));

            {
                std::lock_guard lk(m_file_progress_mtx);
                auto it = m_file_progress.find(tid);
                if (it != m_file_progress.end()) {
                    it->second.done = true;
                    it->second.ok   = ok;
                    if (!ok)
                        it->second.error_msg = "Polaczenie przerwane podczas wysylania";
                }
            }

            if (ok)
                log("[FILE] Wyslano: " + fname, Theme::green(), room);
            else
                log("[FILE] Transfer przerwany.", Theme::yellow(), room);

        } catch (const std::exception& e) {
            if (!tid.empty()) {
                std::lock_guard lk(m_file_progress_mtx);
                auto it = m_file_progress.find(tid);
                if (it != m_file_progress.end()) {
                    it->second.done = true;
                    it->second.ok   = false;
                    it->second.error_msg = e.what();
                }
            }
            log(std::string("[FILE] Blad wysylania: ") + e.what(), Theme::red(), room);
        }
    }).detach();
}
