#ifndef QUILL_NETWORK_H
#define QUILL_NETWORK_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <string>

using Bytes = std::vector<uint8_t>;

inline void send_all(int fd, const uint8_t* data, size_t len) {
    while (len > 0) {
        ssize_t sent = send(fd, data, len, 0);
        if (sent <= 0) throw std::runtime_error("send error");
        data += sent; len -= sent;
    }
}

inline void recv_all(int fd, uint8_t* data, size_t len) {
    while (len > 0) {
        ssize_t rec = recv(fd, data, len, 0);
        if (rec <= 0) throw std::runtime_error("recv error");
        data += rec; len -= rec;
    }
}

inline void send_msg(int fd, const Bytes& data) {
    uint32_t len = htonl(data.size());
    send_all(fd, (uint8_t*)&len, 4);
    send_all(fd, data.data(), data.size());
}

inline Bytes recv_msg(int fd) {
    uint32_t len = 0;
    recv_all(fd, (uint8_t*)&len, 4);
    len = ntohl(len);
    Bytes data(len);
    recv_all(fd, data.data(), len);
    return data;
}

inline int make_server(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{AF_INET, htons((uint16_t)port), {INADDR_ANY}};
    bind(fd, (sockaddr*)&addr, sizeof(addr));
    listen(fd, 1);
    return fd;
}

inline int make_client(const char* host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{AF_INET, htons((uint16_t)port)};
    inet_pton(AF_INET, host, &addr.sin_addr);
    if (connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) throw std::runtime_error("Connect failed");
    return fd;
}

#endif