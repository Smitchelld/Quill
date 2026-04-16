//
// Created by mitchellds on 16.04.2026.
//

#ifndef QUILL_NETWORK_H
#define QUILL_NETWORK_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdexcept>
#include <vector>
#include <cstdint>
#include <cstring>

using Bytes = std::vector<uint8_t>;

inline void send_all(int fd, const uint8_t* data, size_t len) {
    while (len > 0) {
        ssize_t sent = send(fd, data, len, 0);
        if (sent <= 0)
            throw std::runtime_error("send failed");
        data += sent;
        len -= sent;
    }
}

inline void recv_all(int fd, uint8_t* data, size_t len) {
    while (len > 0) {
        ssize_t rec = recv(fd, data, len, 0);
        if (rec <= 0)
            throw std::runtime_error("recv failed");
        data += rec;
        len -= rec;
    }
}

// wysyła: [4B długość][dane]
inline void send_msg(int fd, const Bytes& data) {
    uint32_t len = htonl(data.size());
    send_all(fd, reinterpret_cast<uint8_t*>(&len), 4);
    send_all(fd, data.data(), data.size());
}

inline void send_str(int fd, const std::string& s) {
    Bytes b(s.begin(), s.end());
    send_msg(fd, b);
}

// odbiera: [4B długość][dane]
inline Bytes recv_msg(int fd) {
    uint32_t len = 0;
    recv_all(fd, reinterpret_cast<uint8_t*>(&len), 4);
    len = ntohl(len);

    Bytes data(len);
    recv_all(fd, data.data(), len);
    return data;
}

inline std::string recv_str(int fd) {
    auto b = recv_msg(fd);
    return std::string(b.begin(), b.end());
}

inline int make_server(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(fd, (sockaddr*)&addr, sizeof(addr));
    listen(fd, 1);
    return fd;
}

inline int make_client(const char* host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    if (connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0)
        throw std::runtime_error("Nie mozna polaczyc z serwerem");
    return fd;
}




#endif //QUILL_NETWORK_H
