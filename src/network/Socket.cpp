#include "Socket.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdexcept>

void Socket::close_socket() {
    if (m_fd >= 0) {
        close(m_fd);
        m_fd = -1;
    }
}

void Socket::send_all(int fd, const uint8_t* data, size_t len) {
    while (len > 0) {
        ssize_t sent = send(fd, data, len, 0);
        if (sent <= 0) throw std::runtime_error("Socket send error");
        data += sent; len -= sent;
    }
}

void Socket::recv_all(int fd, uint8_t* data, size_t len) {
    while (len > 0) {
        ssize_t rec = recv(fd, data, len, 0);
        if (rec <= 0) throw std::runtime_error("Socket recv error (connection closed)");
        data += rec; len -= rec;
    }
}

void Socket::send_bytes(const Bytes& data) const {
    uint32_t len = htonl((uint32_t)data.size());
    send_all(m_fd, (uint8_t*)&len, 4);
    send_all(m_fd, data.data(), data.size());
}

Bytes Socket::receive_bytes() const {
    uint32_t len = 0;
    recv_all(m_fd, (uint8_t*)&len, 4);
    len = ntohl(len);
    Bytes data(len);
    if (len > 0) recv_all(m_fd, data.data(), len);
    return data;
}

std::optional<Bytes> Socket::try_receive_bytes(int timeout_ms) const {
    pollfd pfd{m_fd, POLLIN, 0};
    int r = poll(&pfd, 1, timeout_ms);
    if (r == 0) return std::nullopt;
    if (r < 0)  throw std::runtime_error("Socket poll error");
    return receive_bytes();
}
