#include "ChatApp.h"
#include "Theme.h"
#include <algorithm>

// ══════════════════════════════════════════════════════════════════
//  ChatAppRender.cpp
//  Logika sieciowa i kryptograficzna → ChatApp.cpp
// ══════════════════════════════════════════════════════════════════

void ChatApp::render() {
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->Pos);
    ImGui::SetNextWindowSize(vp->Size);
    ImGui::Begin("QuantumShield", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_MenuBar);

    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("Tools")) {
            if (ImGui::MenuItem("Benchmarks",         nullptr, m_show_benchmarks))
                m_show_benchmarks = !m_show_benchmarks;
            if (ImGui::MenuItem("Security Estimates",  nullptr, m_show_security))
                m_show_security   = !m_show_security;
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }

    render_status_bar();

    if (m_mode == AppMode::NONE) {
        render_setup_panel();
    } else {
        float avail_h = ImGui::GetContentRegionAvail().y - 44.0f;
        float rooms_w = 130.0f;
        float hs_w    = 220.0f;
        float chat_w  = ImGui::GetContentRegionAvail().x - rooms_w - hs_w - 16.0f;

        render_rooms_sidebar(rooms_w, avail_h);
        ImGui::SameLine();
        render_chat_panel(chat_w, avail_h);
        ImGui::SameLine();
        render_handshake_panel(hs_w, avail_h);
        render_input_bar();
    }

    if (m_show_benchmarks) render_benchmark_window();
    if (m_show_security)   render_security_window();

    ImGui::End();
}

// ── STATUS BAR ────────────────────────────────────────────────────

void ChatApp::render_status_bar() {
    if (m_connected) {
        ImGui::TextColored(Theme::green(),     "●"); ImGui::SameLine();
        ImGui::TextColored(Theme::primary(),   "QuantumShield"); ImGui::SameLine();
        ImGui::TextColored(Theme::dim(),       "|"); ImGui::SameLine();
        ImGui::TextColored(Theme::blue_text(), "%s", m_security_level.c_str()); ImGui::SameLine();
        ImGui::TextColored(Theme::secondary(), "ML-KEM + ML-DSA + AES-256-GCM"); ImGui::SameLine();
        ImGui::TextColored(Theme::dim(),       "|"); ImGui::SameLine();
        ImGui::TextColored(Theme::dim(),       "msgs: %d", m_msg_count.load()); ImGui::SameLine();
        ImGui::TextColored(Theme::dim(),       "|"); ImGui::SameLine();
        ImGui::TextColored(Theme::dim(),       "room: #%s", m_current_room.c_str());
    } else {
        ImGui::TextColored(Theme::dim(),       "●"); ImGui::SameLine();
        ImGui::TextColored(Theme::secondary(), "QuantumShield — disconnected");
    }
    ImGui::Separator();
}

// ── SETUP PANEL ───────────────────────────────────────────────────

void ChatApp::render_setup_panel() {
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

    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
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
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    if (ImGui::Button("  START SERVER  ",   {ImGui::GetContentRegionAvail().x, 32}))
        start_server();
    ImGui::Spacing();
    if (ImGui::Button("  CONNECT AS CLIENT  ", {ImGui::GetContentRegionAvail().x, 32}))
        start_client();

    ImGui::EndChild();
}

// ── ROOMS SIDEBAR ─────────────────────────────────────────────────

void ChatApp::render_rooms_sidebar(float width, float height) {
    ImGui::BeginChild("rooms_sidebar", {width, height}, true);
    ImGui::TextColored(Theme::dim(), "ROOMS");
    ImGui::Separator();
    ImGui::Spacing();

    {
        std::lock_guard lk(m_rooms_mtx);
        for (auto& [room, members] : m_rooms) {
            bool sel = (room == m_current_room);
            if (sel) ImGui::PushStyleColor(ImGuiCol_Button, Theme::accent());
            std::string label = "#" + room;
            if (ImGui::Button(label.c_str(), {width - 16.0f, 24})) {
                if (m_mode == AppMode::CLIENT && m_connected)
                    join_room(room);
                else
                    m_current_room = room;
            }
            if (sel) ImGui::PopStyleColor();
            ImGui::TextColored(Theme::dim(), "  %d members", (int)members.size());
            ImGui::Spacing();
        }
    }

    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextColored(Theme::dim(), "New room:");
    ImGui::SetNextItemWidth(width - 16.0f);
    if (ImGui::InputText("##newroom", m_new_room_buf, sizeof(m_new_room_buf),
                         ImGuiInputTextFlags_EnterReturnsTrue)) {
        if (m_new_room_buf[0] != '\0') {
            std::string r(m_new_room_buf);
            if (m_mode == AppMode::SERVER)
                create_room(r);
            else if (m_mode == AppMode::CLIENT && m_connected)
                join_room(r);
            m_new_room_buf[0] = '\0';
        }
    }

    ImGui::EndChild();
}

// ── CHAT PANEL ────────────────────────────────────────────────────

void ChatApp::render_chat_panel(float width, float height) {
    ImGui::BeginChild("chat_panel", {width, height}, true);

    ImGui::TextColored(Theme::dim(), "SESSION LOG");
    ImGui::SameLine(width - 90.0f);
    ImGui::TextColored(Theme::blue_text(), "#%s", m_current_room.c_str());
    ImGui::Separator();
    ImGui::Spacing();

    {
        std::lock_guard lock(m_log_mtx);
        auto it = m_room_logs.find(m_current_room);
        if (it != m_room_logs.end())
            for (auto& entry : it->second)
                ImGui::TextColored(entry.color, "%s", entry.text.c_str());
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
                ImGui::TextColored(Theme::dim(), "%d.", i++); ImGui::SameLine();
                if (step.time_ms >= 0.0) {
                    ImGui::TextColored(Theme::primary(), "%s", step.label.c_str());
                    ImGui::TextColored(Theme::green(),   "   %.2f ms", step.time_ms);
                } else {
                    ImGui::TextColored(Theme::secondary(), "%s", step.label.c_str());
                }
                ImGui::Separator();
            }
        }
    }

    if (m_mode == AppMode::CLIENT && m_connected) {
        ImGui::Spacing();
        ImGui::TextColored(Theme::dim(), "CHANGE LEVEL");
        float bw = (width - 28.0f - 8.0f) / 3.0f;
        for (auto& lvl : {"FAST", "BALANCED", "MAX"}) {
            bool sel = (m_security_level == lvl);
            if (sel) ImGui::PushStyleColor(ImGuiCol_Button,        Theme::accent());
            if (sel) ImGui::PushStyleColor(ImGuiCol_ButtonHovered, Theme::accent());
            if (ImGui::Button(lvl, {bw, 22})) {
                m_security_level = lvl;
                json j;
                j["type"]  = "REQ_LEVEL";
                j["level"] = lvl;
                std::string s = j.dump();
                if (m_client) m_client->send_bytes(Bytes(s.begin(), s.end()));
            }
            if (sel) ImGui::PopStyleColor(2);
            ImGui::SameLine(0, 4);
        }
        ImGui::NewLine();
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

        bool ta = m_tamper;
        if (ta) {
            ImGui::PushStyleColor(ImGuiCol_Button,        {0.35f,0.06f,0.06f,1.f});
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, {0.45f,0.08f,0.08f,1.f});
            ImGui::PushStyleColor(ImGuiCol_Text,          Theme::red());
        }
        if (ImGui::Button(ta ? "TAMPER  ON" : "TAMPER OFF", {width - 28.f, 24}))
            m_tamper = !m_tamper;
        if (ta) ImGui::PopStyleColor(3);
        if (m_tamper)
            ImGui::TextColored(Theme::red(), "! MITM sim active");
    }

    ImGui::SetCursorPosY(height - 52.0f);
    ImGui::Separator();
    ImGui::TextColored(Theme::dim(), "msgs");    ImGui::SameLine();
    ImGui::TextColored(Theme::primary(), "%d",  m_msg_count.load());
    ImGui::SameLine(0, 16);
    ImGui::TextColored(Theme::dim(), "clients"); ImGui::SameLine();
    ImGui::TextColored(Theme::primary(), "%d",  (int)m_clients.size());
    if (m_hs_total_ms > 0) {
        ImGui::TextColored(Theme::dim(), "hs"); ImGui::SameLine();
        ImGui::TextColored(Theme::green(), "%.1f ms", m_hs_total_ms);
    }

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

    float send_w  = 80.0f;
    float input_w = ImGui::GetContentRegionAvail().x - send_w - 8.0f;

    ImGui::SetNextItemWidth(input_w);
    bool send = ImGui::InputText("##input", m_input_buf, sizeof(m_input_buf),
                                 ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Button,        Theme::accent());
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, {0.216f,0.522f,1.f,1.f});
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  {0.08f,0.35f,0.75f,1.f});
    send |= ImGui::Button("Send", {send_w, 0});
    ImGui::PopStyleColor(3);

    if (send && m_input_buf[0] != '\0') {
        send_chat_msg(std::string(m_input_buf));
        m_input_buf[0] = '\0';
        ImGui::SetKeyboardFocusHere(-1);
    }
}

// ── BENCHMARK WINDOW ──────────────────────────────────────────────

void ChatApp::render_benchmark_window() {
    ImGui::SetNextWindowSize({660, 420}, ImGuiCond_Once);
    ImGui::Begin("Benchmarks", &m_show_benchmarks);

    if (m_bench_running) {
        ImGui::TextColored(Theme::yellow(), "Running benchmarks (10 iters each)...");
    } else {
        if (ImGui::Button("Run Benchmarks")) run_benchmarks();
    }

    ImGui::Spacing(); ImGui::Separator();

    std::lock_guard lk(m_bench_mtx);
    if (m_benchmarks.empty()) {
        ImGui::TextColored(Theme::dim(), "No results yet — click Run Benchmarks.");
    } else {
        ImGui::TextColored(Theme::secondary(),
            "%-12s %9s %9s %9s %9s %9s %9s %11s",
            "Level","Keygen","Encaps","Decaps","Sign","Verify","AES-enc","HS Total");
        ImGui::Separator();

        for (auto& r : m_benchmarks) {
            if (!r.done) {
                ImGui::TextColored(Theme::dim(), "%s  ...", r.level.c_str());
                continue;
            }
            ImVec4 col = (r.level == "FAST")     ? Theme::green()
                       : (r.level == "BALANCED")  ? Theme::blue_text()
                                                   : Theme::yellow();
            ImGui::TextColored(col,
                "%-12s %7.2fms %7.2fms %7.2fms %7.2fms %7.2fms %7.2fms %9.2fms",
                r.level.c_str(),
                r.keygen_ms, r.encaps_ms, r.decaps_ms,
                r.sign_ms,   r.verify_ms, r.aes_enc_ms,
                r.total_hs_ms);
        }

        if (m_benchmarks.size() == 3 && m_benchmarks[2].done) {
            ImGui::Spacing(); ImGui::Separator();
            ImGui::TextColored(Theme::secondary(), "Handshake time comparison:");
            double max_hs = 0;
            for (auto& r : m_benchmarks) max_hs = std::max(max_hs, r.total_hs_ms);
            for (auto& r : m_benchmarks) {
                ImVec4 col = (r.level == "FAST")    ? Theme::green()
                           : (r.level == "BALANCED") ? Theme::blue_text()
                                                      : Theme::yellow();
                float frac = (float)(r.total_hs_ms / max_hs);
                ImGui::TextColored(col, "%-10s", r.level.c_str());
                ImGui::SameLine();
                ImGui::PushStyleColor(ImGuiCol_PlotHistogram, col);
                ImGui::ProgressBar(frac, {-1, 14},
                    (std::to_string((int)r.total_hs_ms) + " ms").c_str());
                ImGui::PopStyleColor();
            }
        }
    }
    ImGui::End();
}

// ── SECURITY ESTIMATES WINDOW ─────────────────────────────────────

void ChatApp::render_security_window() {
    ImGui::SetNextWindowSize({700, 400}, ImGuiCond_Once);
    ImGui::Begin("Security Estimates", &m_show_security);

    ImGui::TextColored(Theme::secondary(),
        "Szacowany czas złamania — poziom: %s", m_security_level.c_str());
    ImGui::Spacing();
    ImGui::TextColored(Theme::dim(),
        "Zakładamy: klasyczny superkomputer = 10^15 op/s, "
        "komputer kwantowy = 10^12 op/s (2030+)");
    ImGui::Separator();
    ImGui::Spacing();

    auto estimates = build_security_estimates(m_security_level);
    for (auto& e : estimates) {
        ImGui::TextColored(Theme::blue_text(), "%s", e.algorithm.c_str());
        ImGui::TextColored(Theme::dim(),      "  Klasyczny:  "); ImGui::SameLine();
        ImGui::TextColored(Theme::secondary(),"%s", e.classical_supercomputer.c_str());
        ImGui::TextColored(Theme::dim(),      "  Kwantowy:   "); ImGui::SameLine();
        ImGui::TextColored(Theme::secondary(),"%s", e.quantum_computer.c_str());
        ImGui::TextColored(Theme::dim(),      "  Verdict:    "); ImGui::SameLine();
        ImGui::TextColored(e.verdict_color,   "%s", e.verdict.c_str());
        ImGui::Separator(); ImGui::Spacing();
    }

    ImGui::TextColored(Theme::dim(),
        "Zrodla: NIST FIPS 203/204, CRYSTALS papers, "
        "Bernstein & Lange 'Post-Quantum Cryptography' 2017");
    ImGui::End();
}