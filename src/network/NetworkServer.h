//
// Created by mitchellds on 16.04.2026.
//

#ifndef QUILL_NETWORKSERVER_H
#define QUILL_NETWORKSERVER_H
#include "Socket.h"


class NetworkServer : public Socket {
public:
    explicit NetworkServer(int port);
    int accept_client(); // Zwraca FD nowego klienta
};



#endif //QUILL_NETWORKSERVER_H
