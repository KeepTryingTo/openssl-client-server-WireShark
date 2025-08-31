
#pragma once

#include "socket.h"
using namespace ktg;

namespace ktg
{
    class ServerSocket : public Socket
    {
    public:
        ServerSocket() = delete;
        ServerSocket(const string &ip, int port);
        ~ServerSocket() = default;
    };
}