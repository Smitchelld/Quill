//
// Created by mitchellds on 16.04.2026.
//

#ifndef QUILL_NETWORKCLIENT_H
#define QUILL_NETWORKCLIENT_H

#include <string>
#include "Socket.h"


class NetworkClient : public Socket {
public:
    void connect_to(const std::string& host, int port);
};



#endif //QUILL_NETWORKCLIENT_H
