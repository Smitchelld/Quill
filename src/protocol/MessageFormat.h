//
// Created by mitchellds on 16.04.2026.
//

#ifndef QUILL_MESSAGEFORMAT_H
#define QUILL_MESSAGEFORMAT_H
#include <string>

struct Packet {
    std::string type;
    std::string algo;
    std::string payload;
    std::string signature;

    std::string toJson() const;
    static Packet fromJson(const std::string& json);
};

class MessageFormat {

};



#endif //QUILL_MESSAGEFORMAT_H
