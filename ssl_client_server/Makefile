SOURCES = async-ssl-svr.cc sync-ssl-svr.cc async-ssl-cli.cc sync-ssl-cli.cc
# 将编译的可执行文件保存到当前目录bin下面
PROGRAMS = $(addprefix bin/,$(SOURCES:.cc=))

# 确保 bin 目录存在
$(shell mkdir -p bin)

default: $(PROGRAMS)

clean:
	rm -rf bin/*.o $(PROGRAMS)

bin/%: %.cc
	g++ -Wall -g $< -o $@ -lssl -lcrypto
