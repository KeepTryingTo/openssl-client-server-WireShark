#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    char cert_file[200] = "/home/ubuntu/Documents/KTG/myPro/myProject/openssl-client-server/ssl_client_server/cert.pem";
    char private_key[200] = "/home/ubuntu/Documents/KTG/myPro/myProject/openssl-client-server/ssl_client_server/server.pem";
    /* 设置证书和私钥文件 */
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, private_key, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* 验证私钥是否匹配证书 */
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }
}

int main()
{
    int sockfd, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    /* 初始化OpenSSL */
    init_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    /* 创建TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    /* 绑定地址和端口 */
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    /* 开始监听 */
    if (listen(sockfd, 5) < 0)
    {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    while (1)
    {
        /* 接受客户端连接 */
        client_sock = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0)
        {
            perror("Unable to accept");
            continue;
        }

        printf("Connection accepted from %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        /* 创建SSL结构 */
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        /* 执行TLS握手 */
        if (SSL_accept(ssl) <= 0)
        {
            ERR_print_errors_fp(stderr);
            close(client_sock);
            SSL_free(ssl);
            continue;
        }

        printf("SSL/TLS handshake completed\n");

        /* 处理客户端数据 */
        // int bytes_received;
        // while ((bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE)) > 0)
        // {
        //     buffer[bytes_received] = '\0';
        //     printf("Received: %s\n", buffer);

        //     /* 回显数据 */
        //     SSL_write(ssl, buffer, bytes_received);
        // }
        /* 处理客户端数据 */
        int bytes_received;
        char complete_buffer[BUFFER_SIZE * 10]; // 足够大的缓冲区

        // 只读取数据，不立即回显
        bytes_received = SSL_read(ssl, complete_buffer, sizeof(complete_buffer));
        complete_buffer[bytes_received] = '\0';
        printf("recv data: %s\n", complete_buffer);

        // 读取完成后，一次性回显所有数据
        if (bytes_received > 0)
        {
            printf("Complete message: %s\n", complete_buffer);
            SSL_write(ssl, complete_buffer, bytes_received);
            printf("Echoed %d bytes back to client\n", bytes_received);
            // 等待客户端关闭连接
            printf("Waiting for client to close connection...\n");
            while (SSL_read(ssl, buffer, BUFFER_SIZE) > 0)
            {
                // 空循环，等待客户端关闭
            }

            printf("Client closed connection\n");
        }
        /* 清理 */
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_sock);
        printf("Connection closed\n");
    }

    /* 清理资源 */
    close(sockfd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}