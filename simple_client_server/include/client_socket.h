
#pragma once

#include "socket.h"
using namespace ktg;

namespace ktg
{
    class ClientSocket : public Socket
    {
    public:
        ClientSocket() = delete;
        ClientSocket(const string &ip, int port);
        ~ClientSocket() = default;
    };
}