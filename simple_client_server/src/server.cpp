
#include "socket.h"
#include "singleTon.h"

using namespace ktg;

int main()
{
    SingleTon<Logger>::getInstance()->open("./log.txt");

    Socket serve;
    string ip = "127.0.0.1";
    int port = 8080;

    printf("listening ip = %s port = %ld\n", ip.c_str(), port);

    serve.sbind(ip, port);
    serve.slisten(1024);

    while (true)
    {
        int conn = serve.saccept();
        if (conn < 0)
        {
            cout << "accept is failed" << endl;
            break;
        }

        Socket client(conn);
        char buf[1024] = {0};
        size_t size = client.recvMsg(buf, sizeof(buf));
        cout << "recv data size: " << size << "-" << buf << endl;

        cout << "send data: ";
        client.sendMsg(buf, size); // 返回数据给客户端
    }
    serve.sclose();
    return 0;
}