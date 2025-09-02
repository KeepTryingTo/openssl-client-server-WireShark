# 生成私钥和证书
```
# 创建私钥
openssl genrsa -out server.key 2048

# 创建证书签名请求(CSR)
openssl req -new -key server.key -out server.csr -subj "/C=CN/ST=Beijing/L=Beijing/O=MyCompany/OU=IT/CN=localhost"

# 自签名证书（有效期10年）
openssl x509 -req -days 3650 -in server.csr -signkey server.key -out server.crt
```

# 编译（需要链接OpenSSL库）
```
gcc -o https_server_c https_server.c -lssl -lcrypto
```

# server.cpp
```
g++ -std=c++11 https_server.cpp -o https_server_cpp -lssl -lcrypto
```

# 项目使用
* 第一步：启动sudo ./https_server_cpp或者sudo ./https_server_c
* 第二步：浏览器（客户端）输入: https://[IP地址]:[端口443]，比如https://10.15.221.21:443
* 第三步：如果能正常运行的话，浏览器（客户端）将显示：HTTPS Server结果
* 最后：如果要抓包的话请看[请看这里](../README.md)
