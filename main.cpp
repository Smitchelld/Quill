#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>

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
#include <deque>

#include "src/crypto/crypto.h"
#include "src/frontend/Theme.h"
#include "src/network/network.h"

#define PORT 7777

// ══════════════════════════════════════════════════════════════════
//  CAŁY TEN BLOK BEZ ZMIAN — identyczny z CLI
// ══════════════════════════════════════════════════════════════════

std::atomic<bool> running{true};
std::atomic<int>  msg_count{0};
std::mutex        send_mtx;

Bytes       client_aes_key;
std::mutex  client_session_mtx;

struct ConnectedClient {
    int    fd;
    Bytes  aes_key;
    std::string name;
};
std::vector<ConnectedClient> server_clients;
std::mutex                   server_clients_mtx;

auto now_tp() { return std::chrono::high_resolution_clock::now(); }

template<typename T>
double ms(T a, T b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

std::string hex_preview(const Bytes& data, size_t max_len = 8) {
    std::ostringstream oss;
    for (size_t i = 0; i < std::min(max_len, data.size()); ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    if (data.size() > max_len) oss << "...";
    return oss.str();
}

void safe_send_msg(int fd, const Bytes& data) {
    std::lock_guard<std::mutex> lock(send_mtx);
    send_msg(fd, data);
}

// ── HANDSHAKE (bez zmian) ──────────────────────────────────────
Bytes server_handshake(int cli_fd, const std::string& level, const std::string& client_name);
Bytes client_handshake(int srv_fd, const std::string& level);

// ══════════════════════════════════════════════════════════════════
//  NOWE: struktury UI
// ══════════════════════════════════════════════════════════════════

enum class Mode { NONE, SERVER, CLIENT };

struct LogEntry {
    std::string text;
    ImVec4      color;
};

struct HandshakeStep {
    std::string label;
    double      time_ms;   // -1 = pending
};

// Globalny stan UI (dostęp z wątków przez mutex)
static Mode              g_mode        = Mode::NONE;
static std::deque<LogEntry>   g_log;
static std::mutex             g_log_mtx;
static std::deque<HandshakeStep> g_hs_steps;
static std::mutex                g_hs_mtx;
static bool              g_connected   = false;
static bool              g_tamper      = false;
static std::string       g_security_level = "BALANCED";
static int               g_sock_fd     = -1;
static int               g_srv_fd      = -1;

// Pomocnicze: dodaj linię do logu czatu
static void ui_log(const std::string& text,
                   ImVec4 color = {0.85f, 0.85f, 0.85f, 1.0f}) {
    std::lock_guard lock(g_log_mtx);
    g_log.push_back({text, color});
    if (g_log.size() > 500) g_log.pop_front();
}

static void ui_hs_step(const std::string& label, double time_ms = -1.0) {
    std::lock_guard lock(g_hs_mtx);
    g_hs_steps.push_back({label, time_ms});
}

// ══════════════════════════════════════════════════════════════════
//  HANDSHAKE — ta sama logika, logi idą do UI zamiast cout
// ══════════════════════════════════════════════════════════════════

Bytes server_handshake(int cli_fd, const std::string& level,
                       const std::string& client_name) {
    ui_log("=== KEM (" + client_name + ") | Level: " + level + " ===",
           {1.0f, 0.85f, 0.2f, 1.0f});
    {
        std::lock_guard lock(g_hs_mtx);
        g_hs_steps.clear();
    }

    auto t0 = now_tp();
    auto kp = kyber_keygen(level);
    auto t1 = now_tp();
    ui_hs_step("Kyber key generation", ms(t0, t1));

    safe_send_msg(cli_fd, kp.pub);

    auto ct = recv_msg(cli_fd);
    auto t2 = now_tp();

    auto ss  = kyber_decaps(level, ct, kp.priv);
    auto t3  = now_tp();
    ui_hs_step("Ciphertext received + decapsulation", ms(t2, t3));

    ui_log("[OK] Secure session established", {0.2f, 0.9f, 0.4f, 1.0f});
    g_connected = true;
    return Bytes(ss.begin(), ss.begin() + 32);
}

Bytes client_handshake(int srv_fd, const std::string& level) {
    ui_log("=== HANDSHAKE (CLIENT) | Level: " + level + " ===",
           {1.0f, 0.85f, 0.2f, 1.0f});
    {
        std::lock_guard lock(g_hs_mtx);
        g_hs_steps.clear();
    }

    auto pub = recv_msg(srv_fd);
    ui_hs_step("Public key received (" + std::to_string(pub.size()) + " B)");

    auto t0 = now_tp();
    auto [ct, ss] = kyber_encaps(level, pub);
    auto t1 = now_tp();
    ui_hs_step("Encapsulation complete", ms(t0, t1));

    safe_send_msg(srv_fd, ct);
    ui_log("[OK] Secure session established", {0.2f, 0.9f, 0.4f, 1.0f});
    g_connected = true;
    return Bytes(ss.begin(), ss.begin() + 32);
}

// ══════════════════════════════════════════════════════════════════
//  SERVER / CLIENT THREADS — identyczna logika jak w CLI
// ══════════════════════════════════════════════════════════════════

void server_client_handler(int cli_fd, int id) {
    std::string client_name = "Client_" + std::to_string(id);
    auto key = server_handshake(cli_fd, "BALANCED", client_name);
    {
        std::lock_guard lk(server_clients_mtx);
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
                std::lock_guard lk(server_clients_mtx);
                for (auto& c : server_clients)
                    if (c.fd == cli_fd) c.aes_key = new_key;
                continue;
            }

            msg_count++;
            Bytes sender_key;
            {
                std::lock_guard lk(server_clients_mtx);
                for (auto& c : server_clients)
                    if (c.fd == cli_fd) { sender_key = c.aes_key; break; }
            }

            auto plain = aes_decrypt(sender_key, data);
            std::string broadcast_msg = "[" + client_name + "]: " + plain;

            ui_log("[ENC] " + hex_preview(data), {0.5f, 0.5f, 0.5f, 1.0f});
            ui_log(broadcast_msg, {0.4f, 0.9f, 1.0f, 1.0f});

            std::lock_guard lk(server_clients_mtx);
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
        std::lock_guard lk(server_clients_mtx);
        server_clients.erase(
            std::remove_if(server_clients.begin(), server_clients.end(),
                [cli_fd](const ConnectedClient& c){ return c.fd == cli_fd; }),
            server_clients.end());
    }
    close(cli_fd);
    ui_log("[!] " + client_name + " disconnected.", {1.0f, 0.3f, 0.3f, 1.0f});
}

void client_receiver_thread(int fd) {
    while (running) {
        try {
            auto data = recv_msg(fd);
            if (data.empty()) break;

            std::string raw(data.begin(), data.end());
            if (raw.starts_with("DO_HANDSHAKE:")) {
                std::string new_level = raw.substr(13);
                auto new_key = client_handshake(fd, new_level);
                std::lock_guard lk(client_session_mtx);
                client_aes_key = new_key;
                continue;
            }

            Bytes key_copy;
            {
                std::lock_guard lk(client_session_mtx);
                key_copy = client_aes_key;
            }
            auto plain = aes_decrypt(key_copy, data);
            msg_count++;

            ui_log("[ENC] " + hex_preview(data), {0.5f, 0.5f, 0.5f, 1.0f});
            ui_log(plain, {0.4f, 0.9f, 1.0f, 1.0f});
        }
        catch (const std::exception& e) {
            ui_log(std::string("[ERROR] ") + e.what(), {1.0f, 0.3f, 0.3f, 1.0f});
        }
    }
    running = false;
}

// ══════════════════════════════════════════════════════════════════
//  ImGui RENDER — zastępuje run_server() / run_client()
// ══════════════════════════════════════════════════════════════════

static char s_input_buf[2048]{};
static char s_host_buf[64]{"127.0.0.1"};
static int  s_port = PORT;

static void render_ui() {
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->Pos);
    ImGui::SetNextWindowSize(vp->Size);
    ImGui::Begin("QuantumShield", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoBringToFrontOnFocus);

    // ── TYTUŁ ────────────────────────────────────────────────────
    ImGui::TextColored({0.4f, 0.9f, 1.0f, 1.0f},
        "QuantumShield v0.4  |  Post-Quantum Secure Messenger");
    ImGui::SameLine(0, 40);
    if (g_connected)
        ImGui::TextColored({0.2f,0.9f,0.4f,1}, "[CONNECTED] AES-256-GCM | Kyber-%s",
                           g_security_level.c_str());
    else
        ImGui::TextColored({0.6f,0.6f,0.6f,1}, "[DISCONNECTED]");
    ImGui::Separator();

    // ── TRYB WYBORU (tylko przed połączeniem) ────────────────────
    if (g_mode == Mode::NONE) {
        ImGui::Spacing();
        ImGui::Text("Uruchom jako:");
        ImGui::SameLine();
        if (ImGui::Button("  SERVER  ")) {
            g_mode = Mode::SERVER;
            ui_log("[SERVER] Chat room open on port " + std::to_string(PORT),
                   {1.0f,0.85f,0.2f,1.0f});
            g_srv_fd = make_server(PORT);
            std::thread([](){
                int id = 1;
                while (running) {
                    int cli = accept(g_srv_fd, nullptr, nullptr);
                    if (cli >= 0) {
                        ui_log("[+] Client_" + std::to_string(id) + " connected!",
                               {0.2f,0.9f,0.4f,1.0f});
                        std::thread(server_client_handler, cli, id++).detach();
                    }
                }
            }).detach();
        }
        ImGui::SameLine();
        if (ImGui::Button("  CLIENT  ")) {
            g_mode = Mode::CLIENT;
            std::thread([](){
                try {
                    ui_log("[CLIENT] Connecting to " + std::string(s_host_buf) +
                           ":" + std::to_string(s_port) + "...");
                    g_sock_fd = make_client(s_host_buf, s_port);
                    auto key  = client_handshake(g_sock_fd, g_security_level);
                    {
                        std::lock_guard lk(client_session_mtx);
                        client_aes_key = key;
                    }
                    std::thread(client_receiver_thread, g_sock_fd).detach();
                } catch (const std::exception& e) {
                    ui_log(std::string("[ERROR] ") + e.what(),
                           {1.0f,0.3f,0.3f,1.0f});
                    g_mode = Mode::NONE;
                }
            }).detach();
        }
        ImGui::Spacing();
        ImGui::InputText("Host", s_host_buf, sizeof(s_host_buf));
        ImGui::InputInt("Port", &s_port);
        ImGui::Separator();
    }

    // ── SECURITY LEVEL ───────────────────────────────────────────
    if (g_mode == Mode::CLIENT && g_connected) {
        ImGui::Text("Security level:");
        ImGui::SameLine();
        for (auto& lvl : {"FAST", "BALANCED", "MAX"}) {
            bool sel = (g_security_level == lvl);
            if (sel) ImGui::PushStyleColor(ImGuiCol_Button, {0.2f,0.6f,0.9f,1.0f});
            if (ImGui::Button(lvl)) {
                g_security_level = lvl;
                std::string cmd = "REQ_LEVEL:" + g_security_level;
                safe_send_msg(g_sock_fd, Bytes(cmd.begin(), cmd.end()));
            }
            if (sel) ImGui::PopStyleColor();
            ImGui::SameLine();
        }

        // tamper toggle
        ImGui::SameLine(0, 30);
        ImGui::TextColored({0.6f,0.6f,0.6f,1}, "|");
        ImGui::SameLine();
        if (g_tamper)
            ImGui::PushStyleColor(ImGuiCol_Button, {0.8f,0.2f,0.2f,1.0f});
        if (ImGui::Button(g_tamper ? "TAMPER: ON" : "TAMPER: OFF"))
            g_tamper = !g_tamper;
        if (g_tamper) ImGui::PopStyleColor();
        ImGui::Separator();
    }

    // ── LAYOUT: CZAT (lewo) + HANDSHAKE VIZ (prawo) ─────────────
    float panel_w = ImGui::GetContentRegionAvail().x * 0.65f;
    float hs_w    = ImGui::GetContentRegionAvail().x - panel_w - 8.0f;
    float avail_h = ImGui::GetContentRegionAvail().y - 40.0f;

    // CZAT
    ImGui::BeginChild("chat_panel", {panel_w, avail_h}, true);
    {
        std::lock_guard lock(g_log_mtx);
        for (auto& entry : g_log)
            ImGui::TextColored(entry.color, "%s", entry.text.c_str());
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
            ImGui::SetScrollHereY(1.0f);
    }
    ImGui::EndChild();

    ImGui::SameLine();

    // HANDSHAKE VISUALIZER
    ImGui::BeginChild("hs_panel", {hs_w, avail_h}, true);
    ImGui::TextColored({1.0f,0.85f,0.2f,1.0f}, "Handshake steps");
    ImGui::Separator();
    {
        std::lock_guard lock(g_hs_mtx);
        int i = 1;
        for (auto& step : g_hs_steps) {
            if (step.time_ms >= 0.0)
                ImGui::TextColored({0.4f,0.9f,0.4f,1.0f},
                    "%d. %s\n   %.2f ms", i, step.label.c_str(), step.time_ms);
            else
                ImGui::TextColored({0.7f,0.7f,0.7f,1.0f},
                    "%d. %s", i, step.label.c_str());
            ImGui::Spacing();
            i++;
        }
        if (g_hs_steps.empty())
            ImGui::TextColored({0.5f,0.5f,0.5f,1.0f}, "(brak)");
    }
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextColored({0.6f,0.6f,0.6f,1.0f}, "Msgs: %d", msg_count.load());
    ImGui::EndChild();

    // ── INPUT ────────────────────────────────────────────────────
    ImGui::Separator();
    bool can_send = g_connected &&
                    (g_mode == Mode::CLIENT || !server_clients.empty());
    if (!can_send) ImGui::BeginDisabled();

    ImGui::SetNextItemWidth(panel_w - 70.0f);
    bool send = ImGui::InputText("##input", s_input_buf, sizeof(s_input_buf),
                                 ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    send |= ImGui::Button("Wyslij");

    if (send && s_input_buf[0] != '\0') {
        std::string line(s_input_buf);
        s_input_buf[0] = '\0';
        ImGui::SetKeyboardFocusHere(-1);

        if (g_mode == Mode::CLIENT) {
            Bytes key_copy;
            {
                std::lock_guard lk(client_session_mtx);
                key_copy = client_aes_key;
            }
            auto enc = aes_encrypt(key_copy, line);
            if (g_tamper && enc.size() > 10) enc[10] ^= 0xFF;
            safe_send_msg(g_sock_fd, enc);

            ui_log("[PLAIN] " + line, {0.85f,0.85f,0.85f,1.0f});
            ui_log("[ENC]   " + hex_preview(enc), {0.5f,0.5f,0.5f,1.0f});
            if (g_tamper)
                ui_log("[ATTACK] Ciphertext modified!", {1.0f,0.3f,0.3f,1.0f});

        } else if (g_mode == Mode::SERVER) {
            std::string msg = "[SERVER]: " + line;
            std::lock_guard lk(server_clients_mtx);
            for (auto& c : server_clients) {
                auto enc = aes_encrypt(c.aes_key, msg);
                safe_send_msg(c.fd, enc);
            }
            ui_log(msg, {1.0f,0.85f,0.2f,1.0f});
        }
    }

    if (!can_send) ImGui::EndDisabled();

    ImGui::End();
}

// ══════════════════════════════════════════════════════════════════
//  MAIN
// ══════════════════════════════════════════════════════════════════

int main() {
    if (!glfwInit()) return 1;
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    GLFWwindow* window = glfwCreateWindow(1100, 700, "QuantumShield", nullptr, nullptr);
    if (!window) return 1;
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    Theme::Apply();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    while (!glfwWindowShouldClose(window) && running) {
        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        render_ui();

        ImGui::Render();
        int w, h;
        glfwGetFramebufferSize(window, &w, &h);
        glViewport(0, 0, w, h);
        glClearColor(0.1f, 0.1f, 0.12f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    if (g_srv_fd  >= 0) close(g_srv_fd);
    if (g_sock_fd >= 0) close(g_sock_fd);
    return 0;
}