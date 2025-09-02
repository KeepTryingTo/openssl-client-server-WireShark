#include <iostream>
#include <memory>
#include <stdexcept>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string>
#include <string.h>

class OpenSSLContext
{
private:
    SSL_CTX *ctx;

public:
    OpenSSLContext()
    {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();

        // 使用TLS方法创建上下文
        ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx)
        {
            throw std::runtime_error("Unable to create SSL context");
        }

        // 加载证书和私钥
        if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
        {
            throw std::runtime_error("Certificate load error");
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
        {
            throw std::runtime_error("Private key load error");
        }

        if (!SSL_CTX_check_private_key(ctx))
        {
            throw std::runtime_error("Private key does not match certificate");
        }
    }

    ~OpenSSLContext()
    {
        if (ctx)
            SSL_CTX_free(ctx);
        EVP_cleanup();
    }

    SSL_CTX *get() { return ctx; }
};

class SSLSocket
{
private:
    int sockfd;
    SSL *ssl;

public:
    SSLSocket(SSL_CTX *ctx, int port)
    {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0)
        {
            throw std::runtime_error("Socket creation failed");
        }

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        server_addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            throw std::runtime_error("Bind failed");
        }

        listen(sockfd, 5);
    }

    void handleClient(SSL_CTX *ctx)
    {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        int client_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
        if (client_sockfd < 0)
        {
            throw std::runtime_error("Accept failed");
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sockfd);

        if (SSL_accept(ssl) <= 0)
        {
            SSL_free(ssl);
            close(client_sockfd);
            return;
        }

        // 处理请求的逻辑
        char buffer[1024] = {0};
        SSL_read(ssl, buffer, sizeof(buffer));
        std::cout << "Received: " << buffer << std::endl;

        const char *response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>HTTPS Server</h1>";
        SSL_write(ssl, response, strlen(response));

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_sockfd);
    }

    ~SSLSocket()
    {
        close(sockfd);
    }
};

int main()
{
    try
    {
        OpenSSLContext sslContext;
        SSLSocket server(sslContext.get(), 443);

        std::cout << "HTTPS Server running on port 443" << std::endl;

        while (true)
        {
            server.handleClient(sslContext.get());
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}