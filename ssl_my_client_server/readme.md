# 编译服务端
gcc ssl_server.c -o server -lssl -lcrypto

# 编译客户端
gcc ssl_client.c -o client -lssl -lcrypto

# 运行服务端
./server

# 运行客户端（新终端）
./client