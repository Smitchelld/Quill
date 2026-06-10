#include <gtest/gtest.h>
#include "crypto/CryptoManager.h"
#include "crypto/IdentityManager.h"
#include "network/Socket.h"
#include "test_util.h"

#include <nlohmann/json.hpp>
#include <sys/socket.h>
#include <future>

// Test integracyjny: PEŁNY handshake klient<->serwer przez socketpair
// (prawdziwe gniazda, prawdziwa kryptografia, zero mocków)
class HandshakeTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_tmp = std::make_unique<TempDir>("quill_hs");
        IdentityManager::activate(m_tmp->path() / "identity", "");

        int fds[2];
        ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
        m_srv_sock = std::make_unique<Socket>(fds[0]);
        m_cli_sock = std::make_unique<Socket>(fds[1]);
    }
    void TearDown() override { IdentityManager::deactivate(); }

    // Uruchamia obie strony równolegle; zwraca (wynik_serwera, wynik_klienta)
    std::pair<HandshakeResult, HandshakeResult>
    run_handshake(const std::string& level, const std::string& peer_id) {
        CryptoManager cm_srv(level), cm_cli(level);
        auto srv_fut = std::async(std::launch::async,
            [&] { return cm_srv.server_handshake(*m_srv_sock); });
        auto cli = cm_cli.client_handshake(*m_cli_sock, peer_id);
        return {srv_fut.get(), cli};
    }

    std::unique_ptr<TempDir> m_tmp;
    std::unique_ptr<Socket>  m_srv_sock, m_cli_sock;
};

TEST_F(HandshakeTest, BothSidesDeriveSameSessionKey) {
    auto [srv, cli] = run_handshake("BALANCED", "srv:test:7777");

    EXPECT_EQ(srv.session_key, cli.session_key);
    EXPECT_EQ(srv.session_key.size(), 32u);
    EXPECT_EQ(cli.peer_trust, TrustState::UNVERIFIED); // pierwszy kontakt
}

TEST_F(HandshakeTest, AllSecurityLevels) {
    for (const std::string level : {"FAST", "BALANCED", "MAX"}) {
        int fds[2];
        ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
        Socket srv_s(fds[0]), cli_s(fds[1]);

        CryptoManager cm_srv(level), cm_cli(level);
        auto srv_fut = std::async(std::launch::async,
            [&] { return cm_srv.server_handshake(srv_s); });
        auto cli = cm_cli.client_handshake(cli_s, "srv:test:" + level);
        auto srv = srv_fut.get();

        EXPECT_EQ(srv.session_key, cli.session_key) << "level=" << level;
    }
}

TEST_F(HandshakeTest, RehandshakeGivesFreshKeyButKnownTrust) {
    auto [srv1, cli1] = run_handshake("BALANCED", "srv:test:7777");

    int fds[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    Socket srv_s(fds[0]), cli_s(fds[1]);
    CryptoManager cm_srv("BALANCED"), cm_cli("BALANCED");
    auto srv_fut = std::async(std::launch::async,
        [&] { return cm_srv.server_handshake(srv_s); });
    auto cli2 = cm_cli.client_handshake(cli_s, "srv:test:7777");
    srv_fut.get();

    // PFS: nowy Kyber => nowy klucz sesji; tożsamość ta sama => KNOWN
    EXPECT_NE(cli1.session_key, cli2.session_key);
    EXPECT_EQ(cli2.peer_trust, TrustState::KNOWN);
    EXPECT_EQ(cli2.peer_fingerprint, cli1.peer_fingerprint);
}

TEST_F(HandshakeTest, ServerKeyChangeBlocksConnection) {
    run_handshake("BALANCED", "srv:test:7777"); // TOFU zapamiętuje klucz A

    // "Reinstalacja"/atak: nowa tożsamość serwera (świeży katalog, klucz B),
    // ale known_hosts klienta wskazuje nadal na klucz A
    TempDir other_identity("quill_hs_other");
    auto known_hosts = TrustStore::store_path(); // z PIERWSZEGO katalogu
    IdentityManager::activate(other_identity.path() / "identity", "");
    // known_hosts musi pozostać ten sam — kopiujemy stary store do nowego profilu
    std::filesystem::create_directories(other_identity.path());
    std::filesystem::copy_file(known_hosts, TrustStore::store_path());

    int fds[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    Socket srv_s(fds[0]), cli_s(fds[1]);

    CryptoManager cm_srv("BALANCED"), cm_cli("BALANCED");
    auto srv_fut = std::async(std::launch::async, [&] {
        try { cm_srv.server_handshake(srv_s); } catch (...) {}
    });

    EXPECT_THROW(cm_cli.client_handshake(cli_s, "srv:test:7777"),
                 TofuMismatchError);
    cli_s.close_socket(); // zerwij, żeby serwer nie wisiał na recv
    srv_fut.get();
}

TEST_F(HandshakeTest, TamperedKemCiphertextRejectedByServer) {
    // Klient-atakujący: poprawny SRV_HELLO, ale podpis nie pasuje do ct
    CryptoManager cm_srv("BALANCED");
    auto srv_fut = std::async(std::launch::async, [&]() -> std::string {
        try {
            cm_srv.server_handshake(*m_srv_sock);
            return "";
        } catch (const std::exception& e) {
            return e.what();
        }
    });

    // Odbierz SRV_HELLO i odeślij CLI_KEX ze złym podpisem
    auto hello = m_cli_sock->receive_bytes();
    (void)hello;
    nlohmann::json evil;
    evil["type"]       = "CLI_KEX";
    evil["sig_pub"]    = Bytes(1952, 0x00);
    evil["ciphertext"] = Bytes(1088, 0x00);
    evil["sig"]        = Bytes(3309, 0x00);
    std::string s = evil.dump();
    m_cli_sock->send_bytes(Bytes(s.begin(), s.end()));

    std::string err = srv_fut.get();
    EXPECT_NE(err.find("Verification FAILED"), std::string::npos) << err;
}
