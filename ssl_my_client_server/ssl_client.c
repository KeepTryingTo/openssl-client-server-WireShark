#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_IP "127.0.0.1"
#define PORT 8888
#define BUFFER_SIZE 1024

void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

int main()
{
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    const char *message = "Hello from TLS client!";

    /* 初始化OpenSSL */
    init_openssl();
    SSL_CTX *ctx = create_context();

    /* 创建TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    /* 连接服务器 */
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    printf("Connected to server %s:%d\n", SERVER_IP, PORT);

    /* 创建SSL结构 */
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    /* 执行TLS握手 */
    // SSL握手是由​​客户端主动调用SSL_connect()发起的​​，会首先发送"Client Hello"消息，因此抓包结果会清晰显示完整的TLS握手过程。
    if (SSL_connect(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    printf("SSL/TLS handshake completed\n");
    printf("Using cipher: %s\n", SSL_get_cipher(ssl));

    /* 发送数据 */
    SSL_write(ssl, message, strlen(message));
    printf("Sent: %s\n", message);

    /* 接收响应 */
    int bytes_received;
    bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE);
    if (bytes_received > 0)
    {
        buffer[bytes_received] = '\0';
        printf("Received: %s\n", buffer);

        /* 客户端主动发起关闭 */
        SSL_shutdown(ssl); // 第一次关闭通知
        SSL_shutdown(ssl); // 第二次确认
        close(sockfd);

        SSL_CTX_free(ctx);
        cleanup_openssl();
        return 0; // 直接退出
    }
}