#include <gtest/gtest.h>
#include "protocol/FileTransfer.h"
#include "test_util.h"

#include <nlohmann/json.hpp>
#include <fstream>

namespace fs = std::filesystem;
using json = nlohmann::json;

static Bytes key32() { return Bytes(32, 0x77); }

class FileTransferTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_tmp = std::make_unique<TempDir>("quill_ft");
        m_src = m_tmp->path() / "src.bin";
        m_out = m_tmp->path() / "out";
    }

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

    std::vector<std::string> collect_session_packets(FileSenderSession& session) {
        std::vector<std::string> packets;
        session.send_all([&](const std::string& pkt) {
            packets.push_back(pkt);
            return true;
        });
        return packets;
    }

    std::pair<bool, std::string> deliver(FileReceiver& rx,
                                         const std::vector<std::string>& packets) {
        bool ok = false;
        std::string err;
        for (const auto& pkt : packets) {
            json j = json::parse(pkt);
            std::string type = j["type"];
            if (type == "FILE_START") rx.on_start(j);
            if (type == "FILE_CHUNK") rx.on_chunk(j, key32());
            if (type == "FILE_END") {
                FileEndStatus st = rx.on_end(j, m_out,
                    [&](const std::string&, const fs::path&,
                        bool done_ok, const std::string& e) {
                        ok = done_ok;
                        err = e;
                    });
                if (st == FileEndStatus::NeedsNack) {
                    ok = false;
                    err = "needs_nack";
                }
            }
        }
        return {ok, err};
    }

    std::unique_ptr<TempDir> m_tmp;
    fs::path m_src, m_out;
};

TEST_F(FileTransferTest, MultiChunkRoundtrip) {
    Bytes original = make_source(150 * 1024);
    auto packets = collect_packets();
    EXPECT_EQ(packets.size(), 1u + 3u + 1u);

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
    payload[0] ^= 0x01;
    chunk["payload"] = payload;

    FileReceiver rx;
    rx.on_start(json::parse(packets[0]));
    EXPECT_THROW(rx.on_chunk(chunk, key32()), std::runtime_error);
}

TEST_F(FileTransferTest, MissingChunkRequestsNack) {
    make_source(150 * 1024);
    auto packets = collect_packets();

    FileReceiver rx;
    rx.on_start(json::parse(packets[0]));
    rx.on_chunk(json::parse(packets[1]), key32());
    rx.on_chunk(json::parse(packets[3]), key32());

    bool called = false;
    FileEndStatus st = rx.on_end(json::parse(packets[4]), m_out,
        [&](const std::string&, const fs::path&, bool, const std::string&) {
            called = true;
        });
    EXPECT_EQ(st, FileEndStatus::NeedsNack);
    EXPECT_FALSE(called);

    auto missing = rx.missing_chunks(json::parse(packets[0])["transfer_id"]);
    ASSERT_EQ(missing.size(), 1u);
    EXPECT_EQ(missing[0], 1u);
}

TEST_F(FileTransferTest, SelectiveRepeatRecovery) {
    Bytes original = make_source(150 * 1024);
    FileSenderSession session = FileSenderSession::open(m_src, key32(), "tester");
    auto packets = collect_session_packets(session);

    FileReceiver rx;
    rx.on_start(json::parse(packets[0]));
    rx.on_chunk(json::parse(packets[1]), key32()); // chunk 0
    rx.on_chunk(json::parse(packets[3]), key32()); // chunk 2 — brak 1

    FileEndStatus st = rx.on_end(json::parse(packets[4]), m_out,
        [](const std::string&, const fs::path&, bool, const std::string&) {});
    EXPECT_EQ(st, FileEndStatus::NeedsNack);

    session.retransmit({1}, [&](const std::string& pkt) {
        rx.on_chunk(json::parse(pkt), key32());
        return true;
    });

    bool ok = false;
    EXPECT_TRUE(rx.try_finalize(session.transfer_id(), m_out,
        [&](const std::string&, const fs::path&, bool done_ok, const std::string&) {
            ok = done_ok;
        }));
    EXPECT_TRUE(ok);

    std::ifstream f(m_out / "src.bin", std::ios::binary);
    Bytes received((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    EXPECT_EQ(received, original);
}

TEST_F(FileTransferTest, MaxNackRoundsExceeded) {
    make_source(150 * 1024);
    auto packets = collect_packets();

    FileReceiver rx;
    rx.on_start(json::parse(packets[0]));
    rx.on_chunk(json::parse(packets[1]), key32());

    for (uint32_t round = 0; round < FILE_MAX_NACK_ROUNDS; ++round) {
        FileEndStatus st = rx.on_end(json::parse(packets[4]), m_out,
            [](const std::string&, const fs::path&, bool, const std::string&) {});
        EXPECT_EQ(st, FileEndStatus::NeedsNack) << "round " << round;
    }

    bool failed = false;
    FileEndStatus st = rx.on_end(json::parse(packets[4]), m_out,
        [&](const std::string&, const fs::path&, bool done_ok, const std::string& e) {
            failed = !done_ok;
            EXPECT_NE(e.find("retransmisji"), std::string::npos);
        });
    EXPECT_EQ(st, FileEndStatus::Failed);
    EXPECT_TRUE(failed);
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
    make_source(10 * 1024);
    auto packets = collect_packets();

    FileReceiver rx;
    rx.on_start(json::parse(packets[0]));
    rx.on_chunk(json::parse(packets[1]), key32());
    rx.on_chunk(json::parse(packets[1]), key32());

    auto [ok, err] = deliver(rx, {packets[2]});
    EXPECT_TRUE(ok) << err;
}

TEST_F(FileTransferTest, CrossTransferInjectionRejected) {
    make_source(10 * 1024);
    auto packets_a = collect_packets();

    make_source(20 * 1024);
    auto packets_b = collect_packets();

    FileReceiver rx;
    rx.on_start(json::parse(packets_b[0]));

    json injected = json::parse(packets_a[1]);
    injected["transfer_id"] = json::parse(packets_b[0])["transfer_id"];

    EXPECT_THROW(rx.on_chunk(injected, key32()), std::runtime_error);
}

TEST_F(FileTransferTest, WrongChunkIndexRejected) {
    make_source(150 * 1024);
    auto packets = collect_packets();

    json chunk = json::parse(packets[2]);
    chunk["chunk_index"] = 0;

    FileReceiver rx;
    rx.on_start(json::parse(packets[0]));
    EXPECT_THROW(rx.on_chunk(chunk, key32()), std::runtime_error);
}

TEST_F(FileTransferTest, ChunkHashPresentAndValid) {
    Bytes original = make_source(150 * 1024);
    FileSenderSession session = FileSenderSession::open(m_src, key32(), "tester");
    auto packets = collect_session_packets(session);

    json chunk = json::parse(packets[1]);
    EXPECT_TRUE(chunk.contains("chunk_hash"));
    EXPECT_EQ(chunk["chunk_hash"].get<Bytes>().size(), 32u);

    // hash w pakiecie = SHA3(plaintext chunka 0)
    size_t end = std::min(FILE_CHUNK_SIZE, original.size());
    Bytes plain0(original.begin(), original.begin() + end);
    EXPECT_EQ(chunk["chunk_hash"].get<Bytes>(), FileSender::sha3_256(plain0));
}

TEST_F(FileTransferTest, WrongChunkHashRejected) {
    make_source(10 * 1024);
    auto packets = collect_packets();

    json chunk = json::parse(packets[1]);
    Bytes h = chunk["chunk_hash"].get<Bytes>();
    h[0] ^= 0x01;
    chunk["chunk_hash"] = h;

    FileReceiver rx;
    rx.on_start(json::parse(packets[0]));
    EXPECT_THROW(rx.on_chunk(chunk, key32()), std::runtime_error);
    EXPECT_EQ(rx.progress(json::parse(packets[0])["transfer_id"]).first, 0u);
}

TEST_F(FileTransferTest, MissingChunkHashRejected) {
    make_source(10 * 1024);
    auto packets = collect_packets();

    json chunk = json::parse(packets[1]);
    chunk.erase("chunk_hash");

    FileReceiver rx;
    rx.on_start(json::parse(packets[0]));
    EXPECT_THROW(rx.on_chunk(chunk, key32()), std::runtime_error);
}

TEST_F(FileTransferTest, MakeNackListsMissingIndices) {
    make_source(150 * 1024);
    FileSenderSession session = FileSenderSession::open(m_src, key32(), "tester");
    auto packets = collect_session_packets(session);

    FileReceiver rx;
    rx.on_start(json::parse(packets[0]));
    rx.on_chunk(json::parse(packets[1]), key32());
    rx.on_end(json::parse(packets[4]), m_out,
        [](const std::string&, const fs::path&, bool, const std::string&) {});

    json nack = rx.make_nack(session.transfer_id());
    EXPECT_EQ(nack["type"], "FILE_NACK");
    auto missing = nack["missing"].get<std::vector<uint32_t>>();
    ASSERT_EQ(missing.size(), 2u);
    EXPECT_EQ(missing[0], 1u);
    EXPECT_EQ(missing[1], 2u);
}

TEST(FileTransferHash, Sha3KnownVector) {
    EXPECT_EQ(hex(FileSender::sha3_256({})),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
}
