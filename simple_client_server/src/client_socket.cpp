
#include "client_socket.h"

using namespace ktg;

ClientSocket::ClientSocket(const string &ip, int port)
{
    set_recv_buffer(10 * 1024);
    set_send_buffer(10 * 1024);
    set_linger(true, 0);
    set_keepalive();
    set_reuse_addr();
    sconnect(ip, port);
}