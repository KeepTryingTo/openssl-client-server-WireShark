#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 443
#define CERT_FILE "server.crt"
#define KEY_FILE "server.key"

void init_openssl()
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_ssl_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    // 使用TLS协议
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // 加载证书和私钥
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // 验证私钥
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the certificate\n");
        exit(1);
    }

    return ctx;
}

int create_socket(int port)
{
    int sockfd;
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("Cannot create socket");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Cannot bind socket");
        exit(1);
    }

    if (listen(sockfd, 5) < 0)
    {
        perror("Cannot listen on socket");
        exit(1);
    }

    return sockfd;
}

void handle_client(SSL *ssl)
{
    char request[1024] = {0};
    char response[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<html><body><h1>HTTPS Server Success!</h1></body></html>";

    // 读取客户端请求
    SSL_read(ssl, request, sizeof(request));
    printf("Received request:\n%s\n", request);

    // 发送响应
    SSL_write(ssl, response, strlen(response));
}

int main()
{
    int sockfd, client_sockfd;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    SSL_CTX *ctx;
    SSL *ssl;

    // 初始化OpenSSL
    init_openssl();
    ctx = create_ssl_context();

    // 创建监听套接字
    sockfd = create_socket(PORT);
    printf("HTTPS Server listening on port %d\n", PORT);

    while (1)
    {
        // 接受客户端连接
        client_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
        if (client_sockfd < 0)
        {
            perror("Cannot accept connection");
            continue;
        }

        // 创建SSL连接
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sockfd);

        // SSL握手
        if (SSL_accept(ssl) <= 0)
        {
            ERR_print_errors_fp(stderr);
        }
        else
        {
            // 处理客户端请求
            handle_client(ssl);
        }

        // 关闭SSL和套接字
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_sockfd);
    }

    // 清理
    close(sockfd);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}