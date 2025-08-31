
#include "socket.h"

using namespace ktg;

Socket::Socket() : m_ip(""), m_port(0), m_sockfd(0)
{
    m_sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_sockfd < 0)
    {
        debug("server create socket is failed errno = %d  %s", errno, strerror(errno));
    }
    else
    {
        debug("create socket id is successfully!");
    }
}

Socket::Socket(int sockfd) : m_ip(""), m_port(0), m_sockfd(sockfd)
{
}

Socket::~Socket()
{
    sclose();
}

bool Socket::sbind(const string &ip, int16_t port)
{
    m_ip = ip;
    m_port = port;
    struct sockaddr_in sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    if (ip.empty())
    {
        sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else
    {
        sockaddr.sin_addr.s_addr = inet_addr(ip.c_str());
    }
    sockaddr.sin_port = htons(port);

    if (bind(m_sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0)
    {
        debug("socket bind is failed errno = %d  %s", errno, strerror(errno));
        return false;
    }
    else
    {
        debug("socket bind is successfully! ip = %s port = %d", ip.c_str(), port);
    }
    return true;
}

bool Socket::slisten(int backlog)
{
    if (listen(m_sockfd, backlog) < 0)
    {
        debug("socket listen is failed errno = %d  %s", errno, strerror(errno));
        return false;
    }
    else
    {
        debug("server is listening ......");
    }
    return true;
}

bool Socket::sconnect(const string &ip, int16_t port)
{
    m_ip = ip;
    m_port = port;
    struct sockaddr_in sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    if (ip.empty())
    {
        sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else
    {
        sockaddr.sin_addr.s_addr = inet_addr(ip.c_str());
    }
    sockaddr.sin_port = htons(port);

    if (connect(m_sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0)
    {
        debug("client connect is failed errno = %d %s\n", errno, strerror(errno));
        return false;
    }

    return true;
}

int Socket::saccept()
{
    int conn = accept(m_sockfd, nullptr, nullptr);
    if (conn < 0)
    {
        debug("socket not accept errno = %d  %s\n", errno, strerror(errno));
        return -1;
    }
    debug("socket connect id = %d", conn);
    return conn;
}

int Socket::sendMsg(const char *buf, int size)
{
    return send(m_sockfd, buf, size, 0);
}

int Socket::recvMsg(char *buf, int size)
{
    return recv(m_sockfd, buf, size, 0);
}

void Socket::sclose()
{
    if (m_sockfd > 0)
    {
        ::close(m_sockfd);
        m_sockfd = 0;
    }
}

bool Socket::set_non_blocking()
{
    int flags = fcntl(m_sockfd, F_GETFL, 0);
    if (flags < 0)
    {
        debug("socket set non blocking error: errno = %d  errmsg = %s", errno, strerror(errno));
        return false;
    }
    flags |= O_NONBLOCK;
    if (fcntl(m_sockfd, F_SETFL, flags) < 0)
    {
        debug("socket non blocking is failed: errno = %d  errmsg = %s", errno, strerror(errno));
        return false;
    }
    return true;
}

bool Socket::set_send_buffer(int size)
{
    int buff_size = size;
    if (setsockopt(m_sockfd, SOL_SOCKET, SO_SNDBUF, &buff_size, sizeof(buff_size)) < 0)
    {
        debug("set send buffer size is failed errno = %d  errmsg = %s", errno, strerror(errno));
        return false;
    }
    return true;
}

bool Socket::set_recv_buffer(int size)
{
    int buff_size = size;
    if (setsockopt(m_sockfd, SOL_SOCKET, SO_RCVBUF, &buff_size, sizeof(buff_size)) < 0)
    {
        debug("set recv buffer size is failed errno = %d  errmsg = %s", errno, strerror(errno));
        return false;
    }
    return true;
}

bool Socket::set_linger(bool active, int seconds)
{
    struct linger l;
    memset(&l, 0, sizeof(l));
    l.l_onoff = active ? 1 : 0;
    l.l_linger = seconds;

    if (setsockopt(m_sockfd, SOL_SOCKET, SO_RCVBUF, &l, sizeof(l)) < 0)
    {
        debug("set linger is failed errno = %d  errmsg = %s", errno, strerror(errno));
        return false;
    }
    return true;
}

bool Socket::set_keepalive()
{
    int flag = 1;
    if (setsockopt(m_sockfd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) < 0)
    {
        debug("set keep alive is failed errno = %d  errmsg = %s", errno, strerror(errno));
        return false;
    }
    return true;
}

bool Socket::set_reuse_addr()
{
    int flag = 1;
    if (setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0)
    {
        debug("set resuse addr errno = %d errmsg = %s", errno, strerror(errno));
        return false;
    }
    return true;
}