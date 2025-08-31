// gcc -Wall  -o ssl-svr-demo ssl-svr-demo.c -lssl -lcrypto
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// 打印日志
#define log(...)             \
    do                       \
    {                        \
        printf(__VA_ARGS__); \
        fflush(stdout);      \
    } while (0)
#define check0(x, ...)        \
    if (x)                    \
        do                    \
        {                     \
            log(__VA_ARGS__); \
            exit(1);          \
    } while (0)
#define check1(x, ...)        \
    if (!(x))                 \
        do                    \
        {                     \
            log(__VA_ARGS__); \
            exit(1);          \
    } while (0)

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("usage %s <port>\n", argv[0]);
        exit(1);
    }
    struct sockaddr_in addr;

    // 初始化SSL
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    // 创建SSL上下文
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
    check1(ctx, "SSL_CTX_new failed\n");

    // 要求校验对方证书
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    // 加载CA的证书
    //! SSL_CTX_load_verify_locations(ctx, "cacert.cer", NULL);
    char cert_file[200] = "/home/ubuntu/Documents/KTG/myPro/myProject/openssl-client-server/ssl_client_server/cert.pem";
    char private_key[200] = "/home/ubuntu/Documents/KTG/myPro/myProject/openssl-client-server/ssl_client_server/server.pem";
    // 加载自己的证书
    int r = SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM);
    check1(r > 0, "SSL_CTX_use_certificate_file failed");

    // 加载自己的私钥
    r = SSL_CTX_use_PrivateKey_file(ctx, private_key, SSL_FILETYPE_PEM);
    check1(r > 0, "SSL_CTX_use_PrivateKey_file failed");

    // 判定私钥是否正确
    r = SSL_CTX_check_private_key(ctx);
    check1(r, "SSL_CTX_check_private_key failed");

    log("ssl inited\n");
    // 创建并监听等待连接
    int nListenFd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(argv[1]));
    int len = sizeof(addr);
    addr.sin_addr.s_addr = INADDR_ANY;

    r = bind(nListenFd, (struct sockaddr *)&addr, len);
    check0(r, "bind error errno %d %s", errno, strerror(errno));

    r = listen(nListenFd, 20);
    check0(r, "listen error errno %d %s", errno, strerror(errno));
    log("listen at %d\n", atoi(argv[1]));

    while (true)
    {
        memset(&addr, 0, sizeof(addr));
        int len = sizeof(addr);
        // 从全连接队列中取出已经建立的连接
        int nAcceptFd = accept(nListenFd, (struct sockaddr *)&addr, (socklen_t *)&len);
        log("Accept a connect from [%s:%d]\n",
            inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        // 建立TCP连接之后将连接付给SSL进行四次握手连接
        SSL *ssl = SSL_new(ctx);
        check1(ssl, "SSL_new failed");
        SSL_set_fd(ssl, nAcceptFd);

        // 方式一
        // SSL_set_accept_state(ssl);
        // // SSL握手是由​​服务端主动调用SSL_do_handshake()发起的​​，对于抓包工具来说，
        // // 这看起来就像是TCP连接建立后服务端立即开始发送数据，没有明显的"Client Hello"起始标志
        // r = SSL_do_handshake(ssl);
        // check1(r, "SSL_do_handshake failed");

        // 方式二 改为更标准的SSL接受方式：
        r = SSL_accept(ssl);
        if (r <= 0)
        {
            int err = SSL_get_error(ssl, r);
            log("SSL_accept failed: %d, error: %s\n", err, ERR_error_string(err, NULL));
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(nAcceptFd);
            continue; // 继续处理其他连接而不是退出
        }

        // 进行读取来自浏览器的数据操作
        char szBuffer[1024];
        memset(szBuffer, 0, sizeof(szBuffer));
        SSL_read(ssl, szBuffer, sizeof(szBuffer));
        printf("recv data = %s\n", szBuffer);

        // 向浏览器响应状态
        const char *resp = "HTTP/1.1 200 OK\r\nConnection: Close\r\n\r\n";
        SSL_write(ssl, resp, strlen(resp));
        log("send response %ld bytes to client\n", strlen(resp));

        // 正确关闭SSL连接
        SSL_shutdown(ssl);
        // 释放资源
        SSL_free(ssl);
        close(nAcceptFd);
    }
    SSL_CTX_free(ctx);
    close(nListenFd);
    return 0;
}
