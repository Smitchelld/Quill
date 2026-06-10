#include <gtest/gtest.h>
#include "protocol/FileTransfer.h"
#include "test_util.h"

#include <nlohmann/json.hpp>
#include <fstream>

namespace fs = std::filesystem;
using json = nlohmann::json;

static Bytes key32() { return Bytes(32, 0x77); }

// Pełny cykl: send -> pakiety JSON -> receive -> plik na dysku
class FileTransferTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_tmp = std::make_unique<TempDir>("quill_ft");
        m_src = m_tmp->path() / "src.bin";
        m_out = m_tmp->path() / "out";
    }

    // Tworzy plik testowy o zadanym rozmiarze (deterministyczna treść)
    Bytes make_source(size_t size) {
        Bytes data(size);
        for (size_t i = 0; i < size; ++i)
            data[i] = static_cast<uint8_t>(i * 31 + 7);
        std::ofstream f(m_src, std::ios::binary);
        f.write(reinterpret_cast<const char*>(data.data()), data.size());
        return data;
    }

    std::vector<std::string> collect_packets() {
        std::vector<std::string> packets;
        FileSender::send(m_src, key32(), "tester",
            [&](const std::string& pkt) { packets.push_back(pkt); return true; });
        return packets;
    }

    // Dostarcza pakiety do odbiorcy; zwraca (ok, error_msg)
    std::pair<bool, std::string> deliver(FileReceiver& rx,
                                         const std::vector<std::string>& packets) {
        bool ok = false;
        std::string err;
        for (const auto& pkt : packets) {
            json j = json::parse(pkt);
            std::string type = j["type"];
            if (type == "FILE_START") rx.on_start(j);
            if (type == "FILE_CHUNK") rx.on_chunk(j, key32());
            if (type == "FILE_END")
                rx.on_end(j, m_out, [&](const std::string&, const fs::path&,
                                        bool done_ok, const std::string& e) {
                    ok = done_ok;
                    err = e;
                });
        }
        return {ok, err};
    }

    std::unique_ptr<TempDir> m_tmp;
    fs::path m_src, m_out;
};

TEST_F(FileTransferTest, MultiChunkRoundtrip) {
    // 150 KB => 3 chunki (64+64+22)
    Bytes original = make_source(150 * 1024);
    auto packets = collect_packets();
    EXPECT_EQ(packets.size(), 1u + 3u + 1u); // START + 3 chunki + END

    FileReceiver rx;
    auto [ok, err] = deliver(rx, packets);
    EXPECT_TRUE(ok) << err;

    std::ifstream f(m_out / "src.bin", std::ios::binary);
    Bytes received((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    EXPECT_EQ(received, original);
}

TEST_F(FileTransferTest, CorruptedChunkThrowsOnDecrypt) {
    make_source(10 * 1024);
    auto packets = collect_packets();

    json chunk = json::parse(packets[1]);
    Bytes payload = chunk["payload"].get<Bytes>();
    payload[0] ^= 0x01; // MitM przekłamuje szyfrogram
    chunk["payload"] = payload;

    FileReceiver rx;
    rx.on_start(json::parse(packets[0]));
    // Fail-fast: GCM tag odrzuca chunk natychmiast
    EXPECT_THROW(rx.on_chunk(chunk, key32()), std::runtime_error);
}

TEST_F(FileTransferTest, MissingChunkFailsAtEnd) {
    make_source(150 * 1024); // 3 chunki
    auto packets = collect_packets();

    FileReceiver rx;
    rx.on_start(json::parse(packets[0]));
    rx.on_chunk(json::parse(packets[1]), key32()); // chunk 0
    rx.on_chunk(json::parse(packets[3]), key32()); // chunk 2 (1 zgubiony)

    bool ok = true;
    std::string err;
    rx.on_end(json::parse(packets[4]), m_out,
        [&](const std::string&, const fs::path&, bool done_ok, const std::string& e) {
            ok = done_ok;
            err = e;
        });
    EXPECT_FALSE(ok);
    EXPECT_NE(err.find("niekompletny"), std::string::npos);
}

TEST_F(FileTransferTest, WrongFinalHashFails) {
    make_source(10 * 1024);
    auto packets = collect_packets();

    json end = json::parse(packets.back());
    Bytes h = end["file_hash"].get<Bytes>();
    h[0] ^= 0x01;
    end["file_hash"] = h;
    packets.back() = end.dump();

    FileReceiver rx;
    auto [ok, err] = deliver(rx, packets);
    EXPECT_FALSE(ok);
    EXPECT_NE(err.find("INTEGRITY"), std::string::npos);
}

TEST_F(FileTransferTest, DuplicateChunksCountedOnce) {
    make_source(10 * 1024); // 1 chunk
    auto packets = collect_packets();

    FileReceiver rx;
    rx.on_start(json::parse(packets[0]));
    rx.on_chunk(json::parse(packets[1]), key32());
    rx.on_chunk(json::parse(packets[1]), key32()); // duplikat (np. retransmisja)

    auto [ok, err] = deliver(rx, {packets[2]});
    EXPECT_TRUE(ok) << err;
}

TEST(FileTransferHash, Sha3KnownVector) {
    // SHA3-256("") — oficjalny wektor NIST
    EXPECT_EQ(hex(FileSender::sha3_256({})),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
}
