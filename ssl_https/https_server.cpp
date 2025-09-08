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
#include <sys/errno.h>
#include <chrono>
#include <thread>
#include <iomanip>
#include <sstream>

// 获取当前时间字符串
std::string get_current_time()
{
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// 生成漂亮的HTML页面
std::string generate_html_page(const std::string &title, const std::string &content)
{
    return R"(
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>)" +
           title + R"(</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: #333;
        }
        .container {
            background: white;
            padding: 2rem;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 600px;
            width: 90%;
        }
        h1 {
            color: #667eea;
            margin-bottom: 1rem;
            font-size: 2.5rem;
        }
        .message {
            font-size: 1.2rem;
            margin: 1.5rem 0;
            line-height: 1.6;
            color: #666;
        }
        .time {
            font-size: 1rem;
            color: #888;
            margin-top: 1rem;
        }
        .status {
            display: inline-block;
            padding: 0.5rem 1rem;
            background: #4CAF50;
            color: white;
            border-radius: 20px;
            font-weight: bold;
            margin: 1rem 0;
        }
        .warning {
            background: #ff9800;
            color: white;
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 )" +
           title + R"(</h1>
        <div class="status">HTTPS 服务器运行中</div>
        <div class="message">)" +
           content + R"(</div>
        <div class="warning">
            ⚠️ 注意：这是自签名证书，浏览器可能会显示安全警告。<br>
            请点击"高级" → "继续前往"（不同浏览器提示可能不同）
        </div>
        <div class="time">服务器时间: )" +
           get_current_time() + R"(</div>
    </div>
</body>
</html>
)";
}

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

        // 设置相关选项
        SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION |
                                     SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

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

        // 添加这行会复现第一个代码的问题
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    }

    ~OpenSSLContext()
    {
        if (ctx)
            SSL_CTX_free(ctx);
        EVP_cleanup();
    }

    SSL_CTX *get() { return ctx; }
};

std::string get_last_error()
{
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}

void throw_ssl_error(const std::string &msg)
{
    throw std::runtime_error(msg + ": " + get_last_error());
}

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

        int opt = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
        {
            perror("setsockopt");
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

        std::cout << "SSL协议版本: " << SSL_get_version(ssl) << std::endl;
        std::cout << "SSL加密套件: " << SSL_get_cipher(ssl) << std::endl;
        std::cout << "SSL证书验证状态: " << SSL_get_verify_result(ssl) << std::endl;

        if (SSL_accept(ssl) <= 0)
        {
            SSL_free(ssl);
            close(client_sockfd);
            throw std::runtime_error("SSL accept is failed!");
        }
        // SSL_set_accept_state(ssl);

        try
        {
            // 处理请求的逻辑
            char buffer[1024] = {0};
            int ret = SSL_read(ssl, buffer, sizeof(buffer));
            if (ret <= 0)
            {
                int err = SSL_get_error(ssl, ret);
                if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL)
                {
                    return; // 连接关闭
                }
                throw_ssl_error("SSL read error");
            }
            std::cout << "Received: " << buffer << std::endl;

            std::string content = generate_html_page("HTTPS 服务器", "成功响应页面");

            // const char *response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>HTTPS Server</h1>";
            ret = SSL_write(ssl, content.c_str(), content.size());
            if (ret <= 0)
            {
                throw_ssl_error("SSL write error");
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
        }

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
        int port = 443;
        OpenSSLContext sslContext;
        SSLSocket server(sslContext.get(), port);

        std::cout << "🌐 服务器启动中..." << std::endl;
        std::cout << "📍 本地访问: https://localhost:" << port << std::endl;
        std::cout << "🌍 网络访问: https://<localhost>:" << port << std::endl;
        std::cout << "⏹️  按 Ctrl+C 停止服务器" << std::endl;

        std::cout << "HTTPS Server running on port " << port << std::endl;

        while (true)
        {
            try
            {
                server.handleClient(sslContext.get());
            }
            catch (const std::exception &e)
            {
                std::cerr << e.what() << '\n';
            }
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}