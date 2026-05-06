#include "NetworkServer.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <cstring>

NetworkServer::NetworkServer(int port) : Socket() {
    // Utworzenie gniazda TCP
    m_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (m_fd < 0) {
        throw std::runtime_error("Nie mozna utworzyc gniazda serwera");
    }

    // Pozwala na ponowne szybkie użycie portu (omija TIME_WAIT)
    int opt = 1;
    if (setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        throw std::runtime_error("Blad setsockopt(SO_REUSEADDR)");
    }

    sockaddr_in addr{};
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    // Podpięcie pod port
    if (bind(m_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close_socket();
        throw std::runtime_error("Blad bind() na porcie " + std::to_string(port));
    }

    // Nasłuchiwanie
    if (listen(m_fd, SOMAXCONN) < 0) {
        close_socket();
        throw std::runtime_error("Blad listen()");
    }
}

int NetworkServer::accept_client() {
    sockaddr_in cli_addr{};
    socklen_t len = sizeof(cli_addr);
    
    // Akceptacja nowego połączenia
    int cli_fd = accept(m_fd, reinterpret_cast<sockaddr*>(&cli_addr), &len);
    if (cli_fd < 0) {
        throw std::runtime_error("Blad accept() - nie udalo sie polaczyc klienta");
    }
    
    return cli_fd;
}