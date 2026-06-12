#ifndef QUILL_CHATAPP_H
#define QUILL_CHATAPP_H

#include "imgui.h"
#include "../crypto/KyberKEM.h"
#include "../crypto/DilithiumSign.h"
#include "../crypto/AesGcm.h"
#include "../network/NetworkServer.h"
#include "../network/NetworkClient.h"
#include "../network/Socket.h"
#include "../crypto/ProfileManager.h"
#include "../crypto/RoomStore.h"
#include "../crypto/TrustStore.h"
#include <nlohmann/json.hpp>
#include "../protocol/FileTransfer.h"

#include <thread>
#include <mutex>
#include <deque>
#include <string>
#include <vector>
#include <atomic>
#include <chrono>
#include <map>
#include <set>

using json  = nlohmann::json;
using Bytes = std::vector<uint8_t>;

enum class AppMode { NONE, SERVER, CLIENT };

struct ChatMessage {
    std::string text;
    ImVec4      color;
};

struct HandshakeStep {
    std::string label;
    double      time_ms;
};

struct SecurityEstimate {
    std::string algorithm;
    std::string classical_supercomputer;
    std::string quantum_computer;
    std::string verdict;
    ImVec4      verdict_color;
};

struct BenchmarkResult {
    std::string level;
    double      keygen_ms;
    double      encaps_ms;
    double      decaps_ms;
    double      sign_ms;
    double      verify_ms;
    double      aes_enc_ms;
    double      aes_dec_ms;
    double      total_hs_ms;
    bool        done = false;
};

struct CryptoStats {
    std::string kem_name;
    std::string dsa_name;
    int         kem_pub_size;
    int         dsa_sig_size;
};

struct ConnectedClient {
    std::shared_ptr<Socket> sock;
    Bytes                   aes_key;
    std::string             name;
    std::string             room = "general";
    uint64_t                send_seq = 0;
    uint64_t                recv_seq = 0;
    bool                    pending_pfs_rotation = false;
    std::string             pending_pfs_level;
};

class ChatApp {
public:
    ChatApp();
    ~ChatApp();
    void render();

private:
    AppMode     m_mode      = AppMode::NONE;

    bool        m_logged_in = false;
    std::string m_profile_name;
    std::string m_my_fingerprint;
    bool        m_profile_encrypted = false;

    std::vector<ProfileInfo> m_profiles;
    int         m_selected_profile = -1;
    bool        m_profiles_dirty   = true;
    char        m_login_pass_buf[256]{};
    char        m_new_prof_name_buf[64]{};
    char        m_new_prof_pass1_buf[256]{};
    char        m_new_prof_pass2_buf[256]{};
    std::string m_login_error;
    std::string m_login_info;

    std::mutex  m_trust_mtx;
    bool        m_has_peer_trust = false;
    TrustState  m_peer_trust = TrustState::UNVERIFIED;
    std::string m_peer_id;
    std::string m_peer_fp;

    bool                    m_show_trusted = false;
    std::vector<TrustEntry> m_trust_list;
    bool                    m_trust_list_dirty = true;

    Bytes       m_session_key;
    std::mutex  m_session_mtx;
    std::atomic<bool> m_connected{false};

    std::atomic<uint64_t> m_send_seq{0};
    std::atomic<uint64_t> m_recv_seq{0};

    std::unique_ptr<NetworkServer>       m_server;
    std::vector<ConnectedClient>         m_clients;
    std::mutex                           m_clients_mtx;

    std::unique_ptr<NetworkClient>  m_client;
    std::mutex                      m_client_send_mtx;

    std::map<std::string, std::set<std::string>> m_rooms;
    std::mutex                                    m_rooms_mtx;
    std::string  m_current_room = "general";

    std::map<std::string, std::deque<ChatMessage>> m_room_logs;
    std::mutex                                      m_log_mtx;

    std::deque<HandshakeStep> m_hs_steps;
    std::mutex                m_hs_mtx;
    double                    m_hs_total_ms = 0.0;

    std::vector<BenchmarkResult> m_benchmarks;
    std::mutex                   m_bench_mtx;
    bool                         m_bench_running = false;
    bool                         m_show_benchmarks = false;

    bool m_show_security = false;

    char        m_input_buf[2048]{};
    char        m_host_buf[64]{"127.0.0.1"};
    int         m_port           = 7777;
    mutable std::mutex m_security_level_mtx;
    std::string        m_security_level = "BALANCED";
    bool        m_tamper         = false;
    std::atomic<int> m_msg_count{0};

    char        m_new_room_buf[64]{};
    char        m_new_room_pass_buf[64]{};
    char        m_join_room_pass_buf[64]{};
    char        m_delete_pass_buf[256]{};
    bool        m_delete_modal_open   = false;
    std::string m_pending_join_room;
    std::map<std::string, bool> m_room_protected;

    std::string m_last_raw_nonce = "N/A";
    std::string m_last_raw_cipher = "N/A";

    char m_filepath_buf[512]{};
    char m_download_dir_buf[512]{"received_files"};

    FileReceiver              m_file_receiver;
    std::mutex                m_file_receiver_mtx;

    struct FileTransferProgress {
        std::string  file_name;
        uint32_t     received   = 0;
        uint32_t     total      = 0;
        bool         done       = false;
        bool         ok         = false;
        std::string  error_msg;
    };
    std::map<std::string, FileTransferProgress> m_file_progress;
    std::mutex                                  m_file_progress_mtx;

    std::map<std::string, FileSenderSession>    m_outbound_sessions;
    std::mutex                                  m_outbound_mtx;

    std::map<std::string, std::weak_ptr<Socket>> m_file_origin_sock;
    std::mutex                                   m_file_origin_mtx;

    std::set<std::string> m_server_file_origins;
    std::mutex            m_server_file_mtx;

    void render_login_panel();
    void render_setup_panel();
    void render_status_bar();
    void render_chat_panel(float width, float height);
    void render_handshake_panel(float width, float height);
    void render_input_bar();
    void render_benchmark_window();
    void render_security_window();
    void render_trusted_window();
    void render_rooms_sidebar(float width, float height);

    void do_login(const std::string& name, const std::string& passphrase);
    void do_create_profile(const std::string& name,
                           const std::string& pass1, const std::string& pass2);
    void do_logout();
    void do_delete_profile(const std::string& passphrase);
    void disconnect_session();
    void cleanse_login_buffers();
    void load_persisted_rooms();
    void broadcast_room_list();
    void send_display_name();
    void apply_server_security_level(const std::string& level);
    void submit_new_room();
    void delete_room(const std::string& room);
    void client_send(const Bytes& data);
    void client_send(const std::string& s);
    void start_server();
    void start_client();
    void send_chat_msg(const std::string& text);
    void server_client_handler(std::shared_ptr<Socket> sock, int id);
    void send_file(const std::filesystem::path& path);
    void handle_outbound_nack(const json& j);
    void send_file_nack(const json& nack);
    void try_complete_incoming_file(const std::string& transfer_id, const std::string& room);
    void retain_outbound_session(FileSenderSession session);
    void retransmit_server_file_chunks(const std::string& transfer_id,
                                       const std::shared_ptr<Socket>& dest,
                                       const std::vector<uint32_t>& indices);

    Bytes do_client_handshake(Socket& sock, const std::string& level,
                              bool server_rehandshake = false);
    Bytes do_server_handshake(Socket& sock, const std::string& level);

    void run_benchmarks();
    static BenchmarkResult benchmark_level(const std::string& level);
    static CryptoStats get_crypto_stats(const std::string& level);
    static std::vector<SecurityEstimate> build_security_estimates(const std::string& level);

    void join_room(const std::string& room, const std::string& password = "");
    bool create_room(const std::string& room, const std::string& password = "");
    void broadcast_to_room(const std::string& room,
                           const std::string& msg,
                           std::shared_ptr<Socket> exclude = nullptr);

    // PFS handshake must run in the client handler thread.
    void perform_pfs_rotation(std::shared_ptr<Socket> sock, const std::string& level);
    void request_pfs_rotation(const std::string& room);
    bool take_pending_pfs_rotation(const std::shared_ptr<Socket>& sock,
                                   std::string& out_level);

    std::string security_level() const;
    void set_security_level(std::string level);

    void log(const std::string& text, ImVec4 color, const std::string& room = "general");
    void hs_step(const std::string& label, double time_ms = -1.0);
    void hs_clear();

    static std::string hex_preview(const Bytes& data, size_t n = 8);

    // CHAT AAD anti-replay: binds ciphertext to seq ("CHAT|<seq>").
    static Bytes chat_aad(uint64_t seq);
    static double      ms(std::chrono::high_resolution_clock::time_point a,
                          std::chrono::high_resolution_clock::time_point b);

    void broadcast_raw_to_room(const std::string &room, const std::string &raw_json, std::shared_ptr<Socket> exclude);
};

#endif // QUILL_CHATAPP_H
