#include "NetworkClient.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdexcept>
#include <cstring>

void NetworkClient::connect_to(const std::string& host, int port) {
    close_socket(); 

    m_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (m_fd < 0) {
        throw std::runtime_error("Nie mozna utworzyc gniazda klienta");
    }

    sockaddr_in addr{};
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
        close_socket();
        throw std::runtime_error("Nieprawidlowy adres hosta: " + host);
    }

    if (connect(m_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close_socket();
        throw std::runtime_error("Blad polaczenia z " + host + ":" + std::to_string(port));
    }
}