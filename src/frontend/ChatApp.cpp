#include "ChatApp.h"
#include "Theme.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

using clk = std::chrono::high_resolution_clock;

// ══════════════════════════════════════════════════════════════════
//  KONSTRUKTOR / DESTRUKTOR
// ══════════════════════════════════════════════════════════════════

ChatApp::ChatApp() = default;

ChatApp::~ChatApp() {
    m_connected = false;
    if (m_client) m_client->close_socket();
    if (m_server) m_server->close_socket();

    std::lock_guard lk(m_clients_mtx);
    for (auto& c : m_clients) {
        if (c.sock) c.sock->close_socket();
    }
}

// ══════════════════════════════════════════════════════════════════
//  HELPERY (LOGOWANIE, CZAS, HEX)
// ══════════════════════════════════════════════════════════════════

void ChatApp::log(const std::string& text, ImVec4 color) {
    std::lock_guard lock(m_log_mtx);
    m_log.push_back({text, color});
    if (m_log.size() > 500) m_log.pop_front();
}

void ChatApp::hs_step(const std::string& label, double time_ms) {
    std::lock_guard lock(m_hs_mtx);
    m_hs_steps.push_back({label, time_ms});
}

double ms(clk::time_point a, clk::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

std::string ChatApp::hex_preview(const Bytes& data, size_t n) {
    std::ostringstream oss;
    for (size_t i = 0; i < std::min(n, data.size()); ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    if (data.size() > n) oss << "...";
    return oss.str();
}

// ══════════════════════════════════════════════════════════════════
//  PROTOKÓŁ HANDSHAKE (JSON + ML-KEM + ML-DSA)
// ══════════════════════════════════════════════════════════════════

Bytes ChatApp::do_client_handshake(Socket& sock, const std::string& level) {
    log("Starting Handshake...", Theme::yellow());

    KyberKEM kem(level);
    DilithiumSign signer(level);

    // 1. Odbierz ServerHello
    auto data = sock.receive_bytes();
    auto j = json::parse(data.begin(), data.end());

    Bytes srv_sig_pub   = j["sig_pub"].get<json::binary_t>();
    Bytes srv_kyber_pub = j["kyber_pub"].get<json::binary_t>();
    Bytes srv_sig       = j["sig"].get<json::binary_t>();

    // 2. Weryfikuj podpis serwera
    auto t0 = clk::now();
    if (!signer.verify(srv_kyber_pub, srv_sig, srv_sig_pub)) {
        throw std::runtime_error("Server Identity Verification Failed!");
    }
    auto t1 = clk::now();
    hs_step("Server Signature Verified (ML-DSA)", ms(t0, t1));

    // 3. Enkapsulacja klucza Kyber
    auto t2 = clk::now();
    auto [ct, ss] = kem.encapsulate(srv_kyber_pub);
    auto t3 = clk::now();
    hs_step("KEM Encapsulation (ML-KEM)", ms(t2, t3));

    // 4. Podpisz szyfrogram (ClientKeyExchange)
    auto my_sig_kp = signer.generate_keypair();
    auto my_sig = signer.sign(ct, my_sig_kp.secret_key);

    // 5. Wyślij JSON do serwera
    json res;
    res["type"] = "CLI_KEX";
    res["sig_pub"] = json::binary(my_sig_kp.public_key);
    res["ciphertext"] = json::binary(ct);
    res["sig"] = json::binary(my_sig);

    std::string s = res.dump();
    sock.send_bytes(Bytes(s.begin(), s.end()));

    return Bytes(ss.begin(), ss.begin() + 32);
}

Bytes ChatApp::do_server_handshake(Socket& sock, const std::string& level) {
    KyberKEM kem(level);
    DilithiumSign signer(level);

    // 1. Generuj klucze
    auto t0 = clk::now();
    auto kyber_kp = kem.generate_keypair();
    auto sig_kp   = signer.generate_keypair();
    auto t1 = clk::now();
    hs_step("Keygen complete", ms(t0, t1));

    // 2. Serwer podpisuje swój klucz
    auto srv_sig  = signer.sign(kyber_kp.public_key, sig_kp.secret_key);

    // 3. Wyślij ServerHello (JSON)
    json hello;
    hello["type"] = "SRV_HELLO";
    hello["sig_pub"] = json::binary(sig_kp.public_key);
    hello["kyber_pub"] = json::binary(kyber_kp.public_key);
    hello["sig"] = json::binary(srv_sig);

    std::string s = hello.dump();
    sock.send_bytes(Bytes(s.begin(), s.end()));

    // 4. Odbierz odpowiedź klienta
    auto data = sock.receive_bytes();
    auto j = json::parse(data.begin(), data.end());

    Bytes cli_sig_pub = j["sig_pub"].get<json::binary_t>();
    Bytes ct          = j["ciphertext"].get<json::binary_t>();
    Bytes cli_sig     = j["sig"].get<json::binary_t>();

    // 5. Weryfikuj klienta
    if (!signer.verify(ct, cli_sig, cli_sig_pub)) {
        throw std::runtime_error("Client Identity Verification Failed!");
    }
    hs_step("Client Signature Verified");

    // 6. Dekapsulacja
    auto ss = kem.decapsulate(ct, kyber_kp.secret_key);
    return Bytes(ss.begin(), ss.begin() + 32);
}

// ══════════════════════════════════════════════════════════════════
//  KOMUNIKACJA CZATOWA
// ══════════════════════════════════════════════════════════════════

void ChatApp::send_chat_msg(const std::string& text) {
    if (m_mode == AppMode::CLIENT && m_connected) {
        auto enc = AesGcm::encrypt(m_session_key, text);

        json j;
        j["type"] = "CHAT";
        j["nonce"] = json::binary(enc.nonce);
        j["payload"] = json::binary(enc.ciphertext);
        j["sender"] = "Client";

        std::string s = j.dump();
        m_client->send_bytes(Bytes(s.begin(), s.end()));
        log("[YOU]: " + text, Theme::primary());
    }
    else if (m_mode == AppMode::SERVER) {
        std::lock_guard lk(m_clients_mtx);
        for (auto& c : m_clients) {
            auto enc = AesGcm::encrypt(c.aes_key, text);
            json j;
            j["type"] = "CHAT";
            j["nonce"] = json::binary(enc.nonce);
            j["payload"] = json::binary(enc.ciphertext);
            j["sender"] = "Server";
            std::string s = j.dump();
            c.sock->send_bytes(Bytes(s.begin(), s.end()));
        }
        log("[SERVER]: " + text, Theme::yellow());
    }
}

// ══════════════════════════════════════════════════════════════════
//  LOGIKA SIECIOWA (MULTI-CLIENT)
// ══════════════════════════════════════════════════════════════════

void ChatApp::start_server() {
    try {
        m_server = std::make_unique<NetworkServer>(m_port);
        m_mode = AppMode::SERVER;
        m_connected = true;
        log("QuantumShield Server active on port " + std::to_string(m_port), Theme::green());

        std::thread([this]() {
            int id = 1;
            while (m_connected) {
                try {
                    int fd = m_server->accept_client();
                    auto sock = std::make_shared<Socket>(fd);
                    std::thread(&ChatApp::server_client_handler, this, sock, id++).detach();
                } catch (...) { break; }
            }
        }).detach();
    } catch (const std::exception& e) {
        log(std::string("Server failed: ") + e.what(), Theme::red());
    }
}

void ChatApp::server_client_handler(std::shared_ptr<Socket> sock, int id) {
    std::string name = "Client_" + std::to_string(id);
    try {
        Bytes key = do_server_handshake(*sock, m_security_level);
        {
            std::lock_guard lk(m_clients_mtx);
            m_clients.push_back({sock, key, name});
        }
        log("[+] " + name + " connected and encrypted.", Theme::green());

        while (m_connected) {
            auto data = sock->receive_bytes();
            auto j = json::parse(data.begin(), data.end());

            if (j["type"] == "CHAT") {
                Bytes nonce = j["nonce"].get<json::binary_t>();
                Bytes payload = j["payload"].get<json::binary_t>();
                std::string plain = AesGcm::decrypt(key, nonce, payload);

                log("[" + name + "]: " + plain, Theme::blue_text());

                // Broadcast do innych
                std::lock_guard lk(m_clients_mtx);
                for(auto& c : m_clients) {
                    if (c.sock != sock) {
                        auto enc = AesGcm::encrypt(c.aes_key, "["+name+"]: "+plain);
                        json bcast;
                        bcast["type"] = "CHAT";
                        bcast["nonce"] = json::binary(enc.nonce);
                        bcast["payload"] = json::binary(enc.ciphertext);
                        bcast["sender"] = "Network";
                        std::string s = bcast.dump();
                        c.sock->send_bytes(Bytes(s.begin(), s.end()));
                    }
                }
            }
        }
    } catch (...) {}

    // Cleanup
    std::lock_guard lk(m_clients_mtx);
    m_clients.erase(std::remove_if(m_clients.begin(), m_clients.end(),
        [&](const ConnectedClient& c){ return c.sock == sock; }), m_clients.end());
    log("[-] " + name + " disconnected.", Theme::red());
}

void ChatApp::start_client() {
    m_mode = AppMode::CLIENT;
    std::thread([this]() {
        try {
            m_client = std::make_unique<NetworkClient>();
            m_client->connect_to(m_host_buf, m_port);

            auto t0 = clk::now();
            m_session_key = do_client_handshake(*m_client, m_security_level);
            auto t1 = clk::now();

            m_connected = true;
            log("Secure tunnel established in " + std::to_string(ms(t0, t1)) + "ms", Theme::green());

            // Recv Loop
            while (m_connected) {
                auto data = m_client->receive_bytes();
                auto j = json::parse(data.begin(), data.end());
                if (j["type"] == "CHAT") {
                    std::string plain = AesGcm::decrypt(m_session_key,
                        j["nonce"].get<json::binary_t>(),
                        j["payload"].get<json::binary_t>());
                    log(plain, Theme::blue_text());
                }
            }
        } catch (const std::exception& e) {
            log(std::string("Connection lost: ") + e.what(), Theme::red());
            m_connected = false;
        }
    }).detach();
}

// ════════════════════════════════════════════════════════════════
//  ChatApp — metody renderowania
// ════════════════════════════════════════════════════════════════

// ── STATUS BAR ────────────────────────────────────────────────────

void ChatApp::render_status_bar() {
    if (m_connected) {
        ImGui::TextColored(Theme::green(), "●");
        ImGui::SameLine();
        ImGui::TextColored(Theme::primary(), "QuantumShield");
        ImGui::SameLine();
        ImGui::TextColored(Theme::dim(), "|");
        ImGui::SameLine();
        ImGui::TextColored(Theme::blue_text(), "%s", m_security_level.c_str());
        ImGui::SameLine();
        ImGui::TextColored(Theme::secondary(), "AES-256-GCM + Kyber");
        ImGui::SameLine();
        ImGui::TextColored(Theme::dim(), "|");
        ImGui::SameLine();
        ImGui::TextColored(Theme::dim(), "msgs: %d", m_msg_count.load());
    } else {
        ImGui::TextColored(Theme::dim(), "●");
        ImGui::SameLine();
        ImGui::TextColored(Theme::secondary(), "QuantumShield");
        ImGui::SameLine();
        ImGui::TextColored(Theme::dim(), "— disconnected");
    }
    ImGui::Separator();
}

// ── SETUP PANEL ───────────────────────────────────────────────────

void ChatApp::render_setup_panel() {
    ImGui::Spacing();
    ImGui::Spacing();

    float center = ImGui::GetContentRegionAvail().x * 0.5f - 160.0f;
    ImGui::SetCursorPosX(center);

    ImGui::BeginChild("setup_card", {320.0f, 0.0f}, true);

    ImGui::TextColored(Theme::secondary(), "HOST");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputText("##host", m_host_buf, sizeof(m_host_buf));

    ImGui::Spacing();
    ImGui::TextColored(Theme::secondary(), "PORT");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputInt("##port", &m_port, 0);

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::TextColored(Theme::secondary(), "SECURITY LEVEL");
    ImGui::Spacing();
    float btn_w = (ImGui::GetContentRegionAvail().x - 8.0f) / 3.0f;
    for (auto& lvl : {"FAST", "BALANCED", "MAX"}) {
        bool sel = (m_security_level == lvl);
        if (sel) ImGui::PushStyleColor(ImGuiCol_Button,        Theme::accent());
        if (sel) ImGui::PushStyleColor(ImGuiCol_ButtonHovered, Theme::accent());
        if (ImGui::Button(lvl, {btn_w, 28})) m_security_level = lvl;
        if (sel) ImGui::PopStyleColor(2);
        ImGui::SameLine(0, 4);
    }
    ImGui::NewLine();

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (ImGui::Button("  START SERVER  ",
                      {ImGui::GetContentRegionAvail().x, 32}))
        start_server();

    ImGui::Spacing();
    if (ImGui::Button("  CONNECT AS CLIENT  ",
                      {ImGui::GetContentRegionAvail().x, 32}))
        start_client();

    ImGui::EndChild();
}

// ── CHAT PANEL ────────────────────────────────────────────────────

void ChatApp::render_chat_panel(float width, float height) {
    ImGui::BeginChild("chat_panel", {width, height}, true);

    ImGui::TextColored(Theme::dim(), "SESSION LOG");
    ImGui::SameLine(width - 80.0f);
    std::string mode_str = (m_mode == AppMode::SERVER) ? "SERVER" : "CLIENT";
    ImGui::TextColored(Theme::blue_text(), "%s", mode_str.c_str());
    ImGui::Separator();
    ImGui::Spacing();

    {
        std::lock_guard lock(m_log_mtx);
        for (auto& entry : m_log) {
            ImGui::TextColored(entry.color, "%s", entry.text.c_str());
        }
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
            ImGui::SetScrollHereY(1.0f);
    }

    ImGui::EndChild();
}

// ── HANDSHAKE PANEL ───────────────────────────────────────────────

void ChatApp::render_handshake_panel(float width, float height) {
    ImGui::BeginChild("hs_panel", {width, height}, true);

    ImGui::TextColored(Theme::dim(), "HANDSHAKE STEPS");
    ImGui::Separator();
    ImGui::Spacing();

    {
        std::lock_guard lock(m_hs_mtx);
        if (m_hs_steps.empty()) {
            ImGui::TextColored(Theme::dim(), "(no steps yet)");
        } else {
            int i = 1;
            for (auto& step : m_hs_steps) {
                ImGui::TextColored(Theme::dim(), "%d.", i);
                ImGui::SameLine();

                if (step.time_ms >= 0.0) {
                    ImGui::TextColored(Theme::primary(), "%s", step.label.c_str());
                    ImGui::SameLine();
                    ImGui::TextColored(Theme::green(), "%.2f ms", step.time_ms);
                } else {
                    ImGui::TextColored(Theme::secondary(), "%s", step.label.c_str());
                }
                ImGui::Separator();
                i++;
            }
        }
    }

    if (m_mode == AppMode::CLIENT && m_connected) {
        ImGui::Spacing();
        ImGui::TextColored(Theme::dim(), "CHANGE LEVEL");
        ImGui::Spacing();

        float bw = (width - 28.0f - 8.0f) / 3.0f;
        for (auto& lvl : {"FAST", "BALANCED", "MAX"}) {
            bool sel = (m_security_level == lvl);
            if (sel) ImGui::PushStyleColor(ImGuiCol_Button,        Theme::accent());
            if (sel) ImGui::PushStyleColor(ImGuiCol_ButtonHovered, Theme::accent());

            if (ImGui::Button(lvl, {bw, 24})) {
                m_security_level = lvl;
                std::string cmd = "REQ_LEVEL:" + m_security_level;
                if (m_client) m_client->send_bytes(Bytes(cmd.begin(), cmd.end()));
            }

            if (sel) ImGui::PopStyleColor(2);
            ImGui::SameLine(0, 4);
        }
        ImGui::NewLine();

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // ── TAMPER button  ──
        bool tamper_active_this_frame = m_tamper;

        if (tamper_active_this_frame) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4{0.35f, 0.06f, 0.06f, 1.0f});
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4{0.45f, 0.08f, 0.08f, 1.0f});
            ImGui::PushStyleColor(ImGuiCol_Text,          Theme::red());
        }

        if (ImGui::Button(tamper_active_this_frame ? "TAMPER  ON" : "TAMPER OFF", {width - 28.0f, 26})) {
            m_tamper = !m_tamper; // Zmiana stanu następuje, ale zmienna _this_frame pamięta stary stan
        }

        if (tamper_active_this_frame) {
            ImGui::PopStyleColor(3); // Idealne dopasowanie liczby Pop() do Push()
        }

        if (m_tamper) {
            ImGui::Spacing();
            ImGui::TextColored(Theme::red(), "! MITM simulation active");
        }
    }

    ImGui::SetCursorPosY(height - 48.0f);
    ImGui::Separator();
    ImGui::TextColored(Theme::dim(), "msgs");
    ImGui::SameLine();
    ImGui::TextColored(Theme::primary(), "%d", m_msg_count.load());

    ImGui::SameLine(0, 20);
    ImGui::TextColored(Theme::dim(), "clients");
    ImGui::SameLine();
    ImGui::TextColored(Theme::primary(), "%d", (int)m_clients.size());

    ImGui::EndChild();
}

// ── INPUT BAR ─────────────────────────────────────────────────────

void ChatApp::render_input_bar() {
    ImGui::Separator();

    bool can_send = m_connected &&
                    (m_mode == AppMode::CLIENT ||
                    (m_mode == AppMode::SERVER && !m_clients.empty()));

    if (!can_send) {
        ImGui::TextColored(Theme::dim(), "  waiting for connection...");
        return;
    }

    float send_w   = 80.0f;
    float input_w  = ImGui::GetContentRegionAvail().x - send_w - 8.0f;

    ImGui::SetNextItemWidth(input_w);
    bool send = ImGui::InputText("##input", m_input_buf, sizeof(m_input_buf),
                                 ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();

    ImGui::PushStyleColor(ImGuiCol_Button,        Theme::accent());
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4{0.216f,0.522f,1.0f,1.0f});
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4{0.08f,0.35f,0.75f,1.0f});
    send |= ImGui::Button("Send", {send_w, 0});
    ImGui::PopStyleColor(3);

    if (send && m_input_buf[0] != '\0') {
        send_chat_msg(std::string(m_input_buf));
        m_input_buf[0] = '\0';
        ImGui::SetKeyboardFocusHere(-1);
    }
}