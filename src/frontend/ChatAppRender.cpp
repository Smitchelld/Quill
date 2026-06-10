#include "ChatApp.h"
#include "Theme.h"
#include <algorithm>
#include "../../third_party/portable-file-dialogs.h"

// ══════════════════════════════════════════════════════════════════
//  ChatAppRender.cpp
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
            if (ImGui::MenuItem("Trusted Peers",       nullptr, m_show_trusted,
                                m_logged_in))
                m_show_trusted    = !m_show_trusted;
            ImGui::EndMenu();
        }
        if (m_logged_in && ImGui::BeginMenu("Profile")) {
            ImGui::TextColored(Theme::secondary(), "%s", m_profile_name.c_str());
            ImGui::TextColored(Theme::yellow(),    "%s", m_my_fingerprint.c_str());
            if (!m_profile_encrypted)
                ImGui::TextColored(Theme::red(), "klucz bez passphrase'a!");
            ImGui::Separator();
            // Wylogowanie zablokowane w trakcie sesji (klucze potrzebne do PFS)
            if (ImGui::MenuItem("Logout", nullptr, false, m_mode == AppMode::NONE))
                do_logout();
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }

    render_status_bar();

    if (!m_logged_in) {
        render_login_panel();
    } else if (m_mode == AppMode::NONE) {
        render_setup_panel();
    } else {
        float avail_h = ImGui::GetContentRegionAvail().y - 110.0f;
        float rooms_w = 130.0f;
        float hs_w    = 260.0f; // Lekko poszerzone dla Dashboardu
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
    if (m_show_trusted)    render_trusted_window();

    ImGui::End();
}

// ── STATUS BAR ────────────────────────────────────────────────────

void ChatApp::render_status_bar() {
    if (m_logged_in) {
        ImGui::TextColored(Theme::blue_text(), "@%s", m_profile_name.c_str()); ImGui::SameLine();
        ImGui::TextColored(Theme::dim(),       "[%s]", m_my_fingerprint.c_str()); ImGui::SameLine();
        if (!m_profile_encrypted) {
            ImGui::TextColored(Theme::red(), "(!)"); ImGui::SameLine();
        }
        ImGui::TextColored(Theme::dim(), "|"); ImGui::SameLine();
    }
    if (m_connected) {
        ImGui::TextColored(Theme::green(),     "●"); ImGui::SameLine();
        ImGui::TextColored(Theme::primary(),   "QuantumShield"); ImGui::SameLine();
        ImGui::TextColored(Theme::dim(),       "|"); ImGui::SameLine();
        ImGui::TextColored(Theme::blue_text(), "%s", security_level().c_str()); ImGui::SameLine();
        ImGui::TextColored(Theme::secondary(), "ML-KEM + ML-DSA + AES-GCM"); ImGui::SameLine();
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

// ── LOGIN PANEL ───────────────────────────────────────────────────

void ChatApp::render_login_panel() {
    if (m_profiles_dirty) {
        m_profiles = ProfileManager::list();
        m_profiles_dirty = false;
        if (m_selected_profile >= (int)m_profiles.size())
            m_selected_profile = -1;
    }

    ImGui::Spacing();
    float center = ImGui::GetContentRegionAvail().x * 0.5f - 180.0f;
    ImGui::SetCursorPosX(center);
    ImGui::BeginChild("login_card", {360.0f, 0.0f}, true);

    ImGui::TextColored(Theme::primary(), "QUILL — IDENTITY");
    ImGui::TextColored(Theme::dim(),
        "Logowanie odblokowuje klucz tozsamosci na tym\n"
        "urzadzeniu. Uwierzytelnienie wobec peera robi\n"
        "podpis ML-DSA w handshake'u.");
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    // ── ISTNIEJĄCE PROFILE ──
    ImGui::TextColored(Theme::secondary(), "PROFIL");
    if (m_profiles.empty()) {
        ImGui::TextColored(Theme::dim(), "(brak profili — utworz nowy ponizej)");
    } else {
        for (int i = 0; i < (int)m_profiles.size(); ++i) {
            const auto& p = m_profiles[i];
            bool sel = (m_selected_profile == i);
            if (sel) ImGui::PushStyleColor(ImGuiCol_Button, Theme::accent());
            std::string label = p.name + (p.encrypted ? "" : "  (bez hasla)");
            if (ImGui::Button(label.c_str(), {ImGui::GetContentRegionAvail().x, 26}))
                m_selected_profile = i;
            if (sel) ImGui::PopStyleColor();
            if (sel)
                ImGui::TextColored(Theme::dim(), "  %s", p.fingerprint.c_str());
        }

        ImGui::Spacing();
        bool need_pass = m_selected_profile >= 0 &&
                         m_profiles[m_selected_profile].encrypted;
        if (need_pass) {
            ImGui::TextColored(Theme::secondary(), "PASSPHRASE");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputText("##loginpass", m_login_pass_buf, sizeof(m_login_pass_buf),
                             ImGuiInputTextFlags_Password);
        }

        ImGui::BeginDisabled(m_selected_profile < 0);
        if (ImGui::Button("  LOGIN  ", {ImGui::GetContentRegionAvail().x, 30}))
            do_login(m_profiles[m_selected_profile].name,
                     std::string(m_login_pass_buf));
        ImGui::EndDisabled();
    }

    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    // ── NOWY PROFIL ──
    ImGui::TextColored(Theme::secondary(), "NOWY PROFIL");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##newname", "nazwa [a-zA-Z0-9_-]",
                             m_new_prof_name_buf, sizeof(m_new_prof_name_buf));
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##newpass1", "passphrase",
                             m_new_prof_pass1_buf, sizeof(m_new_prof_pass1_buf),
                             ImGuiInputTextFlags_Password);
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##newpass2", "powtorz passphrase",
                             m_new_prof_pass2_buf, sizeof(m_new_prof_pass2_buf),
                             ImGuiInputTextFlags_Password);

    ImGui::TextColored(Theme::dim(),
        "Passphrase: min. %zu znakow, nie sam powtarzajacy sie znak",
        ProfileManager::MIN_PASSPHRASE_LEN);

    if (ImGui::Button("  CREATE PROFILE  ", {ImGui::GetContentRegionAvail().x, 30}))
        do_create_profile(std::string(m_new_prof_name_buf),
                          std::string(m_new_prof_pass1_buf),
                          std::string(m_new_prof_pass2_buf));

    // ── KOMUNIKATY ──
    if (!m_login_error.empty()) {
        ImGui::Spacing();
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + 340.0f);
        ImGui::TextColored(Theme::red(), "%s", m_login_error.c_str());
        ImGui::PopTextWrapPos();
    }
    if (!m_login_info.empty()) {
        ImGui::Spacing();
        ImGui::TextColored(Theme::green(), "%s", m_login_info.c_str());
    }

    ImGui::EndChild();
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
        bool sel = (security_level() == lvl);
        if (sel) ImGui::PushStyleColor(ImGuiCol_Button,        Theme::accent());
        if (sel) ImGui::PushStyleColor(ImGuiCol_ButtonHovered, Theme::accent());
        if (ImGui::Button(lvl, {btn_w, 28})) set_security_level(lvl);
        if (sel) ImGui::PopStyleColor(2);
        ImGui::SameLine(0, 4);
    }

    ImGui::NewLine();
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    ImGui::TextColored(Theme::secondary(), "DOWNLOAD DIRECTORY");

    float browse_btn_w = 80.0f;
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - browse_btn_w - 8.0f);
    ImGui::InputText("##downdir", m_download_dir_buf, sizeof(m_download_dir_buf));

    ImGui::SameLine();
    if (ImGui::Button("Browse##dir", {browse_btn_w, 0})) {
        // Natywne okno wyboru FOLDERU
        auto folder = pfd::select_folder("Wybierz folder pobierania", m_download_dir_buf).result();
        if (!folder.empty()) {
            strncpy(m_download_dir_buf, folder.c_str(), sizeof(m_download_dir_buf) - 1);
            m_download_dir_buf[sizeof(m_download_dir_buf) - 1] = '\0';
        }
    }

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

// ── HANDSHAKE PANEL (Z Dashboardem) ───────────────────────────────

void ChatApp::render_handshake_panel(float width, float height) {
    ImGui::BeginChild("hs_panel", {width, height}, true);

    // ── SECURITY DASHBOARD ──
    ImGui::TextColored(Theme::dim(), "SECURITY DASHBOARD");
    ImGui::Separator();

    CryptoStats stats = get_crypto_stats(security_level());
    if (ImGui::BeginTable("##DashTable", 2)) {
        ImGui::TableSetupColumn("K", ImGuiTableColumnFlags_WidthFixed, 65.0f);
        ImGui::TableSetupColumn("V", ImGuiTableColumnFlags_WidthStretch);

        ImGui::TableNextRow(); ImGui::TableNextColumn();
        ImGui::TextColored(Theme::dim(), "KEM:"); ImGui::TableNextColumn();
        ImGui::TextColored(Theme::green(), "%s", stats.kem_name.c_str());

        ImGui::TableNextRow(); ImGui::TableNextColumn();
        ImGui::TextColored(Theme::dim(), "DSA:"); ImGui::TableNextColumn();
        ImGui::TextColored(Theme::green(), "%s", stats.dsa_name.c_str());

        ImGui::TableNextRow(); ImGui::TableNextColumn();
        ImGui::TextColored(Theme::dim(), "SYM:"); ImGui::TableNextColumn();
        ImGui::TextColored(Theme::green(), "AES-256-GCM");

        ImGui::TableNextRow(); ImGui::TableNextColumn();
        ImGui::TextColored(Theme::dim(), "KEM Pub:"); ImGui::TableNextColumn();
        ImGui::TextColored(Theme::secondary(), "%d B", stats.kem_pub_size);

        ImGui::TableNextRow(); ImGui::TableNextColumn();
        ImGui::TextColored(Theme::dim(), "DSA Sig:"); ImGui::TableNextColumn();
        ImGui::TextColored(Theme::secondary(), "%d B", stats.dsa_sig_size);

        if (m_hs_total_ms > 0) {
            ImGui::TableNextRow(); ImGui::TableNextColumn();
            ImGui::TextColored(Theme::dim(), "Last HS:"); ImGui::TableNextColumn();
            ImGui::TextColored(Theme::accent(), "%.1f ms", m_hs_total_ms);
        }
        ImGui::EndTable();
    }
    ImGui::Spacing();

    // ── HANDSHAKE STEPS ──
    ImGui::TextColored(Theme::dim(), "HANDSHAKE STEPS");
    ImGui::Separator();

    // Panel ze scrollowaniem dla samych kroków handshake'a
    ImGui::BeginChild("hs_steps_list", {width - 16.f, 150.0f}, false);
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
            if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) ImGui::SetScrollHereY(1.0f);
        }
    }
    ImGui::EndChild();
    ImGui::Spacing();

    // ── PEER TRUST (TOFU) ──
    {
        std::lock_guard lk(m_trust_mtx);
        if (m_has_peer_trust) {
            ImGui::TextColored(Theme::dim(), "PEER TRUST");
            ImGui::Separator();

            ImVec4 col = (m_peer_trust == TrustState::VERIFIED) ? Theme::green()
                       : (m_peer_trust == TrustState::KNOWN)    ? Theme::blue_text()
                                                                : Theme::yellow();
            ImGui::TextColored(col, "%s", TrustStore::state_name(m_peer_trust));
            ImGui::TextColored(Theme::dim(), "%s", m_peer_fp.c_str());

            if (m_peer_trust == TrustState::UNVERIFIED)
                ImGui::TextColored(Theme::yellow(),
                    "Porownaj fingerprint z serwerem\nout-of-band, potem potwierdz:");

            if (m_peer_trust != TrustState::VERIFIED) {
                if (ImGui::Button("MARK AS VERIFIED", {width - 16.f, 24})) {
                    try {
                        TrustStore::mark_verified(m_peer_id);
                        m_peer_trust = TrustState::VERIFIED;
                        m_trust_list_dirty = true;
                    } catch (const std::exception& e) {
                        log(std::string("[TRUST] ") + e.what(), Theme::red(), m_current_room);
                    }
                }
            }
            ImGui::Spacing();
        }
    }

    // ── KONTROLA KLIENTA (PFS / TAMPER) ──
    if (m_mode == AppMode::CLIENT && m_connected) {
        ImGui::Separator();

        // Forward Secrecy Button
        if (ImGui::Button("ROTATE SESSION KEY (PFS)", {width - 16.f, 26})) {
            json j; j["type"] = "REQ_LEVEL"; j["level"] = security_level();
            std::string s = j.dump();
            if (m_client) m_client->send_bytes(Bytes(s.begin(), s.end()));
        }
        ImGui::Spacing();

        ImGui::TextColored(Theme::dim(), "CHANGE LEVEL");
        float bw = (width - 28.0f - 8.0f) / 3.0f;
        for (auto& lvl : {"FAST", "BALANCED", "MAX"}) {
            bool sel = (security_level() == lvl);
            if (sel) ImGui::PushStyleColor(ImGuiCol_Button, Theme::accent());
            if (sel) ImGui::PushStyleColor(ImGuiCol_ButtonHovered, Theme::accent());
            if (ImGui::Button(lvl, {bw, 22})) {
                set_security_level(lvl);
                json j; j["type"] = "REQ_LEVEL"; j["level"] = lvl;
                std::string s = j.dump();
                if (m_client) m_client->send_bytes(Bytes(s.begin(), s.end()));
            }
            if (sel) ImGui::PopStyleColor(2);
            ImGui::SameLine(0, 4);
        }
        ImGui::NewLine();
        ImGui::Spacing();

        // Tamper Button (z czerwonym trybem awaryjnym)
        bool ta = m_tamper;
        if (ta) {
            ImGui::PushStyleColor(ImGuiCol_Button,        {0.35f,0.06f,0.06f,1.f});
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, {0.45f,0.08f,0.08f,1.f});
            ImGui::PushStyleColor(ImGuiCol_Text,          Theme::red());
        }
        if (ImGui::Button(ta ? "TAMPER SIMULATION ACTIVE" : "SIMULATE MitM (TAMPER)", {width - 16.f, 26}))
            m_tamper = !m_tamper;
        if (ta) ImGui::PopStyleColor(3);
    }

    ImGui::EndChild();
}

// ── INPUT BAR ─────────────────────────────────────────────────────

void ChatApp::render_input_bar() {
    ImGui::Separator();

    // --- PACKET INSPECTOR ---
    ImGui::BeginChild("hex_view", {ImGui::GetContentRegionAvail().x, 50.0f}, true);
    ImGui::TextColored(Theme::dim(), "WIRE VIEW |"); ImGui::SameLine();
    ImGui::TextColored(Theme::dim(), "NONCE: "); ImGui::SameLine();
    ImGui::TextColored(Theme::yellow(), "%s", m_last_raw_nonce.c_str());

    ImGui::TextColored(Theme::dim(), "          |"); ImGui::SameLine();
    ImGui::TextColored(Theme::dim(), "DATA:  "); ImGui::SameLine();
    ImGui::TextColored(Theme::green(), "%s", m_last_raw_cipher.c_str());
    ImGui::EndChild();
    // ------------------------

    ImGui::Spacing();

    bool can_send = m_connected &&
                    (m_mode == AppMode::CLIENT ||
                    (m_mode == AppMode::SERVER && !m_clients.empty()));

    if (!can_send) {
        ImGui::TextColored(Theme::dim(), "  waiting for connection...");
        return;
    }

 // ── KONTROLKI PLIKÓW I CZATU ────────────────────────────────────
    float btn_w  = 80.0f;
    float path_w = 200.0f;
    // Odejmujemy trzy przyciski (Send, Browse, Send File) i path_w
    float chat_w = ImGui::GetContentRegionAvail().x - (btn_w * 3) - path_w - 32.0f;

    // Pole tekstowe czatu
    ImGui::SetNextItemWidth(chat_w);
    bool send = ImGui::InputText("##input", m_input_buf, sizeof(m_input_buf),
                                 ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();

    // Przycisk wyślij tekst
    ImGui::PushStyleColor(ImGuiCol_Button,        Theme::accent());
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, {0.216f,0.522f,1.f,1.f});
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  {0.08f,0.35f,0.75f,1.f});
    send |= ImGui::Button("Send", {btn_w, 0});
    ImGui::PopStyleColor(3);

    ImGui::SameLine();
    ImGui::TextColored(Theme::dim(), "|");
    ImGui::SameLine();

    // Pole na ścieżkę do pliku
    ImGui::SetNextItemWidth(path_w);
    ImGui::InputTextWithHint("##filepath", "Wybierz plik...", m_filepath_buf, sizeof(m_filepath_buf));
    ImGui::SameLine();

    // PRZYCISK BROWSE... (uruchamia systemowe okno wyboru)
    if (ImGui::Button("Browse...", {btn_w, 0})) {
        // Blokuje wątek do czasu wybrania pliku, używając natywnego okna OS
        auto selection = pfd::open_file("Wybierz plik do wysłania").result();
        if (!selection.empty()) {
            strncpy(m_filepath_buf, selection[0].c_str(), sizeof(m_filepath_buf) - 1);
        }
    }
    ImGui::SameLine();

    // Przycisk wyślij plik
    if (ImGui::Button("Send File", {btn_w, 0})) {
        std::filesystem::path p(m_filepath_buf);
        if (std::filesystem::exists(p) && std::filesystem::is_regular_file(p)) {
            send_file(p);
            m_filepath_buf[0] = '\0'; // wyczyść po wysłaniu
        } else {
            log("[FILE ERROR] Plik nie istnieje: " + std::string(m_filepath_buf), Theme::red(), m_current_room);
        }
    }

    if (send && m_input_buf[0] != '\0') {
        send_chat_msg(std::string(m_input_buf));
        m_input_buf[0] = '\0';
        ImGui::SetKeyboardFocusHere(-1);
    }

    // ── PASKI POSTĘPU TRANSFERU ─────────────────────────────────────
    std::lock_guard lk(m_file_progress_mtx);
    for (auto it = m_file_progress.begin(); it != m_file_progress.end(); ) {
        auto& p = it->second;

        ImGui::Spacing();
        ImGui::TextColored(Theme::yellow(), "[FILE] %s", p.file_name.c_str());
        ImGui::SameLine();

        if (p.done) {
            if (p.ok) {
                ImGui::TextColored(Theme::green(), "✓ Ukończono");
            } else {
                ImGui::TextColored(Theme::red(), "✗ Błąd: %s", p.error_msg.c_str());
            }
            // Zamknięcie elementu zakończonego transferu z listy
            ImGui::SameLine();
            if (ImGui::Button(("X##" + it->first).c_str())) {
                it = m_file_progress.erase(it);
                continue;
            }
        } else {
            // Obliczanie postępu
            float fraction = (float)p.received / (float)(p.total > 0 ? p.total : 1);
            char buf[64];
            snprintf(buf, sizeof(buf), "%d / %d chunks", p.received, p.total);
            ImGui::ProgressBar(fraction, ImVec2(-1.0f, 0.0f), buf);
        }
        ++it;
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

// ── TRUSTED PEERS WINDOW (known_hosts) ────────────────────────────

void ChatApp::render_trusted_window() {
    ImGui::SetNextWindowSize({640, 360}, ImGuiCond_Once);
    ImGui::Begin("Trusted Peers (known_hosts)", &m_show_trusted);

    if (m_trust_list_dirty) {
        try {
            m_trust_list = TrustStore::list();
        } catch (const std::exception& e) {
            ImGui::TextColored(Theme::red(), "%s", e.what());
            ImGui::End();
            return;
        }
        m_trust_list_dirty = false;
    }

    ImGui::TextColored(Theme::dim(),
        "TOFU: pierwszy kontakt zapisuje klucz peera. Zmiana klucza = blokada.\n"
        "VERIFIED ustawiaj wylacznie po porownaniu fingerprintu out-of-band.");
    ImGui::Separator();
    ImGui::Spacing();

    if (m_trust_list.empty()) {
        ImGui::TextColored(Theme::dim(), "(brak zapamietanych peerow)");
    } else if (ImGui::BeginTable("##trust", 4,
                   ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH)) {
        ImGui::TableSetupColumn("Peer",        ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Fingerprint", ImGuiTableColumnFlags_WidthFixed, 200.f);
        ImGui::TableSetupColumn("Status",      ImGuiTableColumnFlags_WidthFixed, 90.f);
        ImGui::TableSetupColumn("",            ImGuiTableColumnFlags_WidthFixed, 130.f);
        ImGui::TableHeadersRow();

        for (const auto& e : m_trust_list) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextColored(Theme::primary(), "%s", e.peer_id.c_str());
            ImGui::TextColored(Theme::dim(),     "%s", e.algo.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(Theme::yellow(), "%s", e.fingerprint.c_str());

            ImGui::TableNextColumn();
            if (e.verified) ImGui::TextColored(Theme::green(),     "VERIFIED");
            else            ImGui::TextColored(Theme::blue_text(), "KNOWN");

            ImGui::TableNextColumn();
            if (!e.verified) {
                if (ImGui::Button(("Verify##" + e.peer_id).c_str())) {
                    try { TrustStore::mark_verified(e.peer_id); } catch (...) {}
                    m_trust_list_dirty = true;
                }
                ImGui::SameLine();
            }
            if (ImGui::Button(("Remove##" + e.peer_id).c_str())) {
                try { TrustStore::remove(e.peer_id); } catch (...) {}
                m_trust_list_dirty = true;
            }
        }
        ImGui::EndTable();
    }

    ImGui::End();
}

// ── SECURITY ESTIMATES WINDOW ─────────────────────────────────────

void ChatApp::render_security_window() {
    ImGui::SetNextWindowSize({700, 400}, ImGuiCond_Once);
    ImGui::Begin("Security Estimates", &m_show_security);

    ImGui::TextColored(Theme::secondary(),
        "Szacowany czas złamania — poziom: %s", security_level().c_str());
    ImGui::Spacing();
    ImGui::TextColored(Theme::dim(),
        "Zakładamy: klasyczny superkomputer = 10^15 op/s, "
        "komputer kwantowy = 10^12 op/s (2030+)");
    ImGui::Separator();
    ImGui::Spacing();

    auto estimates = build_security_estimates(security_level());
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

// ── POMOCNICZE (Rozmiary dla UI) ──────────────────────────────────

CryptoStats ChatApp::get_crypto_stats(const std::string& level) {
    if (level == "FAST")     return {"ML-KEM-512",  "ML-DSA-44", 800,  2420};
    if (level == "MAX")      return {"ML-KEM-1024", "ML-DSA-87", 1568, 4627};
    return {"ML-KEM-768", "ML-DSA-65", 1184, 3309}; // BALANCED (Default)
}