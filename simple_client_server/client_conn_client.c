#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define LOCAL_IP_ADDR (0x7F000001)
#define LOCAL_TCP_PORT (8080)

int main(int argc, char **argv)
{
    struct sockaddr_in local, peer;
    int ret;
    char buf[128];
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    memset(&local, 0, sizeof(local));
    memset(&peer, 0, sizeof(peer));

    local.sin_family = AF_INET;
    local.sin_port = htons(LOCAL_TCP_PORT);
    local.sin_addr.s_addr = htonl(LOCAL_IP_ADDR);

    peer = local;

    int flag = 1;
    ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    if (ret == -1)
    {
        printf("Fail to setsockop SO_REUSEADDR: %s\n", strerror(errno));
        exit(1);
    }

    // 客户端最好不要使用bind
    // ret = bind(sock, (const struct sockaddr*)&local, sizeof(local));
    // if(ret == -1){
    //     printf("fail to bind: %s\n", strerror(errno));
    //     exit(1);
    // }

    ret = connect(sock, (const struct sockaddr *)&peer, sizeof(peer));
    if (ret == -1)
    {
        printf("fail to connect myself: %s\n", strerror(errno));
        exit(1);
    }

    printf("connect to myself successfully\n");

    // 发送数据
    strcpy(buf, "hello, myself!");
    send(sock, buf, strlen(buf), 0);

    memset(buf, 0, sizeof(buf));

    // 接收数据
    recv(sock, buf, sizeof(buf), 0);
    printf("recv data: %s\n", buf);
    sleep(1000);
    close(sock);

    return 0;
}