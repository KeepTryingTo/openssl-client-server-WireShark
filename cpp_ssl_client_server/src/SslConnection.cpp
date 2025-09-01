#include "../include/SslConnection.h"
#include <muduo/base/Logging.h>
#include <openssl/err.h>

namespace ssl
{

    /*
        BIO（Basic Input/Output）是 OpenSSL 提供的 ​​基础 I/O 抽象层​​，
        用于替代传统的文件描述符（File Descriptor）操作，支持 ​​SSL/TLS 加密通信​​ 和 ​​内存缓冲区操作​​
    */
    // 自定义 BIO 方法
    static BIO_METHOD *createCustomBioMethod()
    {
        // 设置对应的回调函数
        BIO_METHOD *method = BIO_meth_new(BIO_TYPE_MEM, "custom");
        // SSL_write时调用
        BIO_meth_set_write(method, SslConnection::bioWrite);
        // SSL_read时调用
        BIO_meth_set_read(method, SslConnection::bioRead);
        BIO_meth_set_ctrl(method, SslConnection::bioCtrl);
        return method;
    }

    SslConnection::SslConnection(const TcpConnectionPtr &conn, SslContext *ctx)
        : ssl_(nullptr),
          ctx_(ctx),
          conn_(conn),
          state_(SSLState::HANDSHAKE),
          readBio_(nullptr),
          writeBio_(nullptr),
          messageCallback_(nullptr)
    {
        // 创建 SSL 对象
        ssl_ = SSL_new(ctx_->getNativeHandle());
        if (!ssl_)
        {
            LOG_ERROR << "Failed to create SSL object: " << ERR_error_string(ERR_get_error(), nullptr);
            return;
        }

        // 创建 BIO 读以及写内存
        readBio_ = BIO_new(BIO_s_mem());
        writeBio_ = BIO_new(BIO_s_mem());

        if (!readBio_ || !writeBio_)
        {
            LOG_ERROR << "Failed to create BIO objects";
            SSL_free(ssl_);
            ssl_ = nullptr;
            return;
        }

        SSL_set_bio(ssl_, readBio_, writeBio_);
        // 设置为服务器模式
        SSL_set_accept_state(ssl_);

        // 设置 SSL 选项
        // 允许在 SSL_write操作期间 ​​安全移动或释放写缓冲区​​（即使数据尚未完全写入底层传输层）
        SSL_set_mode(ssl_, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        // 允许 SSL_write​​部分写入数据​​（即使未完全写入所有字节），避免必须等待完整写入才能返回
        SSL_set_mode(ssl_, SSL_MODE_ENABLE_PARTIAL_WRITE);

        // 设置读写事件回调
        conn_->setMessageCallback(
            std::bind(&SslConnection::onRead, this, std::placeholders::_1,
                      std::placeholders::_2, std::placeholders::_3));
    }

    SslConnection::~SslConnection()
    {
        if (ssl_)
        {
            SSL_free(ssl_); // 这会同时释放 BIO
        }
    }

    void SslConnection::startHandshake()
    {
        SSL_set_accept_state(ssl_);
        handleHandshake();
    }

    void SslConnection::send(const void *data, size_t len)
    {
        if (state_ != SSLState::ESTABLISHED)
        {
            LOG_ERROR << "Cannot send data before SSL handshake is complete";
            return;
        }
        // 将明文数据 data（长度 len）通过 SSL 对象加密，并写入关联的 ​​写 BIO​​（writeBio_）
        int written = SSL_write(ssl_, data, len);
        if (written <= 0)
        {
            int err = SSL_get_error(ssl_, written);
            LOG_ERROR << "SSL_write failed: " << ERR_error_string(err, nullptr);
            return;
        }

        char buf[4096];
        int pending;
        // ​​BIO_pending(writeBio_)​​检查写 BIO 中是否有待读取的 ​​已加密数据​​（即 SSL 加密后的数据）
        while ((pending = BIO_pending(writeBio_)) > 0)
        {
            // BIO_read​​从写 BIO 中读取加密数据到临时缓冲区 buf，最多读取 min(pending, 4096)字节
            int bytes = BIO_read(writeBio_, buf,
                                 std::min(pending, static_cast<int>(sizeof(buf))));
            // conn_->send​​将加密数据通过底层 Socket 发送（如调用 send()或写入非阻塞事件循环）
            if (bytes > 0)
            {
                conn_->send(buf, bytes);
            }
        }
    }

    void SslConnection::onRead(const TcpConnectionPtr &conn, BufferPtr buf,
                               muduo::Timestamp time)
    {
        // 判断当前是SSL握手的哪个阶段
        if (state_ == SSLState::HANDSHAKE)
        {
            // 将数据写入 BIO
            BIO_write(readBio_, buf->peek(), buf->readableBytes());
            // 移动读指针
            buf->retrieve(buf->readableBytes());
            handleHandshake();
            return;
        }
        else if (state_ == SSLState::ESTABLISHED)
        {
            // 解密数据，并保存到decryptedData数组
            char decryptedData[4096];
            int ret = SSL_read(ssl_, decryptedData, sizeof(decryptedData));
            if (ret > 0)
            {
                // 创建新的 Buffer 存储解密后的数据
                muduo::net::Buffer decryptedBuffer;
                decryptedBuffer.append(decryptedData, ret);

                // 调用上层回调处理解密后的数据
                if (messageCallback_)
                {
                    messageCallback_(conn, &decryptedBuffer, time);
                }
            }
        }
    }

    void SslConnection::handleHandshake()
    {
        // SSL握手的最后一次，发送encryped handshark message表示对之前的会话进行
        int ret = SSL_do_handshake(ssl_);

        if (ret == 1)
        {
            state_ = SSLState::ESTABLISHED;
            LOG_INFO << "SSL handshake completed successfully";
            LOG_INFO << "Using cipher: " << SSL_get_cipher(ssl_);
            LOG_INFO << "Protocol version: " << SSL_get_version(ssl_);

            // 握手完成后，确保设置了正确的回调
            if (!messageCallback_)
            {
                LOG_WARN << "No message callback set after SSL handshake";
            }
            return;
        }
        // 如果发生了错误
        int err = SSL_get_error(ssl_, ret);
        switch (err)
        {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            // 正常的握手过程，需要继续
            break;

        default:
        {
            // 获取详细的错误信息
            char errBuf[256];
            unsigned long errCode = ERR_get_error();
            ERR_error_string_n(errCode, errBuf, sizeof(errBuf));
            LOG_ERROR << "SSL handshake failed: " << errBuf;
            conn_->shutdown(); // 关闭TCP连接
            break;
        }
        }
    }

    void SslConnection::onEncrypted(const char *data, size_t len)
    {
        // 发送加密的数据
        writeBuffer_.append(data, len);
        conn_->send(&writeBuffer_);
    }

    void SslConnection::onDecrypted(const char *data, size_t len)
    {
        decryptedBuffer_.append(data, len);
    }

    SSLError SslConnection::getLastError(int ret)
    {
        int err = SSL_get_error(ssl_, ret);
        switch (err)
        {
        case SSL_ERROR_NONE:
            return SSLError::NONE;
        case SSL_ERROR_WANT_READ:
            return SSLError::WANT_READ;
        case SSL_ERROR_WANT_WRITE:
            return SSLError::WANT_WRITE;
        case SSL_ERROR_SYSCALL:
            return SSLError::SYSCALL;
        case SSL_ERROR_SSL:
            return SSLError::SSL;
        default:
            return SSLError::UNKNOWN;
        }
    }

    void SslConnection::handleError(SSLError error)
    {
        switch (error)
        {
        case SSLError::WANT_READ:
        case SSLError::WANT_WRITE:
            // 需要等待更多数据或写入缓冲区可用
            break;
        case SSLError::SSL:
        case SSLError::SYSCALL:
        case SSLError::UNKNOWN:
            LOG_ERROR << "SSL error occurred: " << ERR_error_string(ERR_get_error(), nullptr);
            state_ = SSLState::ERROR;
            conn_->shutdown();
            break;
        default:
            break;
        }
    }

    int SslConnection::bioWrite(BIO *bio, const char *data, int len)
    {
        SslConnection *conn = static_cast<SslConnection *>(BIO_get_data(bio));
        if (!conn)
            return -1;
        // 发送数据
        conn->conn_->send(data, len);
        return len;
    }

    int SslConnection::bioRead(BIO *bio, char *data, int len)
    {
        SslConnection *conn = static_cast<SslConnection *>(BIO_get_data(bio));
        if (!conn)
            return -1;
        // 确认缓冲区是否有数据可读
        size_t readable = conn->readBuffer_.readableBytes();
        if (readable == 0)
        {
            return -1; // 无数据可读
        }

        size_t toRead = std::min(static_cast<size_t>(len), readable);
        // 将缓冲区的数据复制到data中
        memcpy(data, conn->readBuffer_.peek(), toRead);
        // 移动缓冲区的读指针
        conn->readBuffer_.retrieve(toRead);
        return toRead;
    }

    long SslConnection::bioCtrl(BIO *bio, int cmd, long num, void *ptr)
    {
        switch (cmd)
        {
        case BIO_CTRL_FLUSH:
            return 1;
        default:
            return 0;
        }
    }

} // namespace ssl