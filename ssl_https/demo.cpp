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
#include <chrono>
#include <iomanip>
#include <sstream>
#include <arpa/inet.h>

// 获取当前时间字符串
std::string
get_current_time()
{
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// 生成简单 HTML 页面
std::string generate_html_page(const std::string &title, const std::string &content)
{
    return std::string(
               "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"UTF-8\">"
               "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
               "<title>") +
           title + "</title></head><body><h1>" + title +
           "</h1><div>" + content + "</div><div>服务器时间: " + get_current_time() +
           "</div></body></html>";
}

std::string get_last_error()
{
    char buf[256];
    unsigned long e = ERR_get_error();
    if (e == 0)
        return std::string("No error");
    ERR_error_string_n(e, buf, sizeof(buf));
    return std::string(buf);
}

void throw_ssl_error(const std::string &msg)
{
    throw std::runtime_error(msg + ": " + get_last_error());
}

class OpenSSLContext
{
private:
    SSL_CTX *ctx;

public:
    OpenSSLContext(const std::string &cert_file = "server.crt", const std::string &key_file = "server.key")
        : ctx(nullptr)
    {
        // 初始化 OpenSSL（对 1.1.0+ 可选）
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();

        ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx)
        {
            throw std::runtime_error("Unable to create SSL context");
        }

        // 基本安全选项
        SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

        // 加载证书和私钥（单次加载）
        if (SSL_CTX_use_certificate_file(ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            throw_ssl_error("Certificate load error");
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            throw_ssl_error("Private key load error");
        }

        if (!SSL_CTX_check_private_key(ctx))
        {
            throw std::runtime_error("Private key does not match certificate");
        }

        // 若不做双向 TLS，禁用客户端证书校验
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

        // 可按需设置超时、CA 列表或 ALPN 等
    }

    ~OpenSSLContext()
    {
        if (ctx)
            SSL_CTX_free(ctx);
        // 不强制调用全局清理（在某些 OpenSSL 版本中不需要）
    }

    SSL_CTX *get() { return ctx; }
};

class SSLSocket
{
private:
    int listen_fd;

public:
    SSLSocket(int port)
    {
        listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0)
        {
            throw std::runtime_error("socket create failed");
        }

        int opt = 1;
        if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            close(listen_fd);
            throw std::runtime_error("setsockopt SO_REUSEADDR failed");
        }

        // 绑定
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            close(listen_fd);
            throw std::runtime_error("bind failed");
        }

        if (listen(listen_fd, SOMAXCONN) < 0)
        {
            close(listen_fd);
            throw std::runtime_error("listen failed");
        }
    }

    ~SSLSocket()
    {
        if (listen_fd >= 0)
            close(listen_fd);
    }

    int accept_fd()
    {
        sockaddr_in client_addr{};
        socklen_t len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &len);
        if (client_fd < 0)
            throw std::runtime_error("accept failed");
        return client_fd;
    }
};

// 处理单个客户端连接：执行 SSL 握手并返回 HTML 页面
void handleClient(int client_fd, SSL_CTX *ctx)
{
    SSL *ssl = SSL_new(ctx);
    if (!ssl)
    {
        close(client_fd);
        std::cerr << "SSL_new failed: " << get_last_error() << std::endl;
        return;
    }

    // 将 socket 绑定到 SSL
    SSL_set_fd(ssl, client_fd);

    // 执行握手
    int ret = SSL_accept(ssl);
    if (ret <= 0)
    {
        int err = SSL_get_error(ssl, ret);
        std::cerr << "SSL_accept failed, err=" << err << " openssl: " << get_last_error() << std::endl;

        // 尝试关闭并释放
        SSL_shutdown(ssl); // 尝试优雅关闭
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    // 握手成功，打印相关信息
    const char *cipher = SSL_get_cipher(ssl);
    long verify_res = SSL_get_verify_result(ssl);
    std::cout << "[INFO] TLS handshake success. Cipher=" << (cipher ? cipher : "(none)")
              << " verify_result=" << verify_res << std::endl;

    // 生成并发送简单 HTTP 响应（带 TLS）
    std::string body = generate_html_page("Hello from C++ OpenSSL Server", "This is a TLS response.");
    std::ostringstream oss;
    oss << "HTTP/1.1 200 OK\r\n";
    oss << "Content-Type: text/html; charset=UTF-8\r\n";
    oss << "Content-Length: " << body.size() << "\r\n";
    oss << "Connection: close\r\n";
    oss << "\r\n";
    std::string header = oss.str();

    // 先发送 header，再发送 body。使用 SSL_write。
    int w = SSL_write(ssl, header.data(), (int)header.size());
    if (w <= 0)
    {
        std::cerr << "SSL_write(header) failed: " << get_last_error() << std::endl;
    }
    else
    {
        w = SSL_write(ssl, body.data(), (int)body.size());
        if (w <= 0)
        {
            std::cerr << "SSL_write(body) failed: " << get_last_error() << std::endl;
        }
    }

    // 关闭连接（优雅关闭）
    // 首先发送 close_notify
    int sd = SSL_shutdown(ssl);
    if (sd == 0)
    {
        // 需要再次调用以完成双向关闭
        SSL_shutdown(ssl);
    }

    SSL_free(ssl);
    close(client_fd);
}

int main(int argc, char *argv[])
{
    const int port = 443; // 按需修改
    const std::string cert_file = "server.crt";
    const std::string key_file = "server.key";

    try
    {
        OpenSSLContext ctx(cert_file, key_file);
        SSLSocket server(port);

        std::cout << "[INFO] Server listening on port " << port << std::endl;

        // 单线程循环接受连接并处理（生产环境请改为多线程/事件驱动）
        while (true)
        {
            int client_fd = -1;
            try
            {
                client_fd = server.accept_fd();
            }
            catch (const std::exception &ex)
            {
                std::cerr << "[ERROR] accept failed: " << ex.what() << std::endl;
                continue;
            }

            // 打印客户端地址（可选）
            sockaddr_in peer_addr;
            socklen_t peer_len = sizeof(peer_addr);
            if (getpeername(client_fd, (struct sockaddr *)&peer_addr, &peer_len) == 0)
            {
                char ipbuf[INET_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET, &peer_addr.sin_addr, ipbuf, sizeof(ipbuf));
                std::cout << "[INFO] Accepted connection from " << ipbuf << ":" << ntohs(peer_addr.sin_port) << std::endl;
            }

            // 处理客户端连接（阻塞）
            handleClient(client_fd, ctx.get());
        }
    }
    catch (const std::exception &ex)
    {
        std::cerr << "[FATAL] " << ex.what() << std::endl;
        return 1;
    }
    // g++ -std=c++11 demo.cpp -o demo_cpp -lssl -lcrypto
    return 0;
}