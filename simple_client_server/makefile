# 编译器设置
CXX := g++
CXXFLAGS := -Wall -Wextra -std=c++11 -g
INCLUDE := -I./include

# 目标文件
TARGETS := bin/client bin/server

# 源文件
CLIENT_SRCS := ./src/client.cpp ./src/client_socket.cpp ./src/Logger.cpp ./src/socket.cpp
SERVER_SRCS := ./src/server.cpp ./src/server_socket.cpp ./src/Logger.cpp ./src/socket.cpp

# 默认目标
all: $(TARGETS)

# 创建bin目录
bin:
	@mkdir -p bin

# 客户端编译
bin/client: $(CLIENT_SRCS) | bin
	$(CXX) $(CXXFLAGS) $(INCLUDE) -o $@ $(CLIENT_SRCS)

# 服务端编译
bin/server: $(SERVER_SRCS) | bin
	$(CXX) $(CXXFLAGS) $(INCLUDE) -o $@ $(SERVER_SRCS)

# 清理
clean:
	rm -rf bin $(TARGETS)

.PHONY: all clean