#pragma once

#include <iostream>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <error.h>
#include <algorithm>
using namespace std;

#include "singleTon.h"
using namespace ktg;

namespace ktg {
    namespace utility{
        #define debug(format,...) Logger::getInstance() -> log(Logger::DEBUG, __FILE__, __LINE__, format, ##__VA_ARGS__);
        #define info(format,...) Logger::getInstance() -> log(Logger::INFO, __FILE__, __LINE__, format,  ##__VA_ARGS__);
        #define warn(format,...) Logger::getInstance() -> log(Logger::WARN, __FILE__, __LINE__, format,  ##__VA_ARGS__);
        #define error(format,...) Logger::getInstance() -> log(Logger::ERROR, __FILE__, __LINE__, format, ##__VA_ARGS__);
        #define fatal(format,...) Logger::getInstance() -> log(Logger::FATAL, __FILE__, __LINE__, format, ##__VA_ARGS__);
        class Logger{
            friend class SingleTon<Logger>;
            public:
                enum Level{
                    DEBUG = 0,
                    INFO,
                    WARN,
                    ERROR,
                    FATAL,
                    LEVEL_COUNT
                };
            public:
                static Logger * getInstance();
                void open(const string & filename);
                void close();
                void log(Level level, const char * file, int line, const char * format, ...);
                void setLevel(Level level){
                    m_level = level;
                }
                void set_log_max(int bytes){
                    max_size = bytes;
                }
                void rotate();
            private:
                Logger();
                ~Logger();
            private:
                string m_filename;
                ofstream m_fout;
                Level m_level;
                int64_t max_size;
                int64_t cur_size;
                static const char * s_level[LEVEL_COUNT];
                static Logger * m_instance;
        };
    }
}