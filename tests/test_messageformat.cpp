#include <gtest/gtest.h>
#include "protocol/MessageFormat.h"

TEST(MessageFormat, SerializeDeserializeRoundtrip) {
    SecureMessage msg;
    msg.type      = MsgType::CHAT;
    msg.sender    = "alice";
    msg.nonce     = Bytes(12, 0x01);
    msg.payload   = Bytes{0xde, 0xad, 0xbe, 0xef};
    msg.timestamp = 1234567890;

    auto restored = SecureMessage::deserialize(msg.serialize());
    EXPECT_EQ(restored.type,      MsgType::CHAT);
    EXPECT_EQ(restored.sender,    "alice");
    EXPECT_EQ(restored.nonce,     msg.nonce);
    EXPECT_EQ(restored.payload,   msg.payload);
    EXPECT_EQ(restored.timestamp, msg.timestamp);
}

TEST(MessageFormat, BinaryPayloadSurvivesAllByteValues) {
    SecureMessage msg;
    msg.type   = MsgType::FILE_CHUNK;
    msg.sender = "bob";
    msg.nonce  = Bytes(12, 0xFF);
    for (int i = 0; i < 256; ++i)
        msg.payload.push_back(static_cast<uint8_t>(i));
    msg.timestamp = 0;

    auto restored = SecureMessage::deserialize(msg.serialize());
    EXPECT_EQ(restored.payload, msg.payload);
}

TEST(MessageFormat, MalformedDataThrows) {
    Bytes garbage = {'{', 'z', 'e', 'p', 's', 'u', 't', 'e'};
    EXPECT_ANY_THROW(SecureMessage::deserialize(garbage));
}
