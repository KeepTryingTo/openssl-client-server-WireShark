
#pragma once 

#include <iostream>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <string>
#include <stdexcept>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "Logger.h"
using namespace ktg::utility;

using namespace std;

namespace ktg {
    class Socket {
        public:
            Socket();
            Socket(int sockfd);
            ~Socket();

            bool sbind(const string & ip, int16_t port);
            bool slisten(int backlog);
            bool sconnect(const string & ip, int16_t port);
            int saccept();
            int sendMsg(const char * buf, int size);
            int recvMsg(char * buf, int size);
            void sclose();
            //默写从阻塞状态设置为非阻塞状态
            bool set_non_blocking();
            //设置操作系统默认数据缓冲区大小
            bool set_send_buffer(int size);
            bool set_recv_buffer(int size);
            bool set_linger(bool active, int seconds);
            bool set_keepalive();
            bool set_reuse_addr();

        private:
            string m_ip;
            int16_t m_port;
            int m_sockfd;
    };
}