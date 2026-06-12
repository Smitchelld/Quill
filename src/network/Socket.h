#ifndef QUILL_SOCKET_H
#define QUILL_SOCKET_H

#include <vector>
#include <cstdint>
#include <optional>
#include <unistd.h>

using Bytes = std::vector<uint8_t>;

class Socket {
public:
    explicit Socket(int fd = -1) : m_fd(fd) {}
    virtual ~Socket() { close_socket(); }

    // RAII: Zarządzanie deskryptorem
    void close_socket();
    int get_fd() const { return m_fd; }
    bool is_valid() const { return m_fd >= 0; }

    void send_bytes(const Bytes& data) const;
    Bytes receive_bytes() const;
    // Odczyt z limitem czasu; std::nullopt = timeout (brak danych).
    std::optional<Bytes> try_receive_bytes(int timeout_ms) const;

protected:
    int m_fd;
    static void send_all(int fd, const uint8_t* data, size_t len);
    static void recv_all(int fd, uint8_t* data, size_t len);
};

#endif
