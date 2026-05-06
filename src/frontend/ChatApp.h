#ifndef QUILL_CHATAPP_H
#define QUILL_CHATAPP_H

#include "imgui.h"
#include <nlohmann/json.hpp>

#include "../crypto/KyberKEM.h"
#include "../crypto/DilithiumSign.h"
#include "../crypto/AesGcm.h"
#include "../network/NetworkServer.h"
#include "../network/NetworkClient.h"

#include <thread>
#include <mutex>
#include <deque>
#include <string>
#include <vector>
#include <atomic>
#include <chrono>
#include <memory>

using json = nlohmann::json;

// ── TRYBY I STRUKTURY ──────────────────────────────────────────────

enum class AppMode { NONE, SERVER, CLIENT };

struct ChatMessage {
    std::string text;
    ImVec4      color;
};

struct HandshakeStep {
    std::string label;
    double      time_ms;
};

struct ConnectedClient {
    std::shared_ptr<Socket> sock;
    Bytes                   aes_key;
    std::string             name;
};

class ChatApp {
public:
    ChatApp();
    ~ChatApp();
    void render();

private:
    AppMode m_mode = AppMode::NONE;

    // Połączenia
    std::unique_ptr<NetworkServer> m_server;
    std::unique_ptr<NetworkClient> m_client;
    std::vector<ConnectedClient>   m_clients;
    std::mutex                     m_clients_mtx;

    // Klucze sesji
    Bytes m_session_key;
    std::mutex m_session_mtx;
    std::atomic<bool> m_connected{false};

    // UI & Logi
    std::deque<ChatMessage>   m_log;
    std::mutex                m_log_mtx;
    std::deque<HandshakeStep> m_hs_steps;
    std::mutex                m_hs_mtx;

    char m_input_buf[2048]{};
    char m_host_buf[64]{"127.0.0.1"};
    int  m_port = 7777;
    std::string m_security_level = "BALANCED";
    bool m_tamper = false;
    std::atomic<int> m_msg_count{0};

    // Logika sieciowa
    void start_server();
    void start_client();
    void send_chat_msg(const std::string& text);
    void recv_loop_client();
    void server_client_handler(std::shared_ptr<Socket> sock, int id);

    // Handshake
    Bytes do_client_handshake(Socket& sock, const std::string& level);
    Bytes do_server_handshake(Socket& sock, const std::string& level);

    // Renderowanie UI (fragmenty)
    void render_setup_panel();
    void render_status_bar();
    void render_chat_panel(float width, float height);
    void render_handshake_panel(float width, float height);
    void render_input_bar();

    // Helpery
    void log(const std::string& text, ImVec4 color = {0.85f, 0.85f, 0.85f, 1.0f});
    void hs_step(const std::string& label, double time_ms = -1.0);
    static std::string hex_preview(const Bytes& data, size_t n = 8);
};

#endif