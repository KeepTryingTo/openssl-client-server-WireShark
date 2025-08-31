#include <time.h>
#include <stdarg.h>
#include "Logger.h"
using namespace ktg::utility;


const char * Logger::s_level[LEVEL_COUNT] ={
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR",
    "FATAL"
};

Logger * Logger::m_instance = nullptr;

Logger::Logger(): max_size(0), cur_size(0), m_level(DEBUG){

}
Logger::~Logger(){
    close();
}

Logger * Logger::getInstance(){
    if(m_instance == nullptr){
        m_instance = new Logger();
    }
    return m_instance;
}

void Logger::open(const string & filename){
    m_filename = filename;
    m_fout.open(filename, ios::app);
    if(m_fout.fail()){
        throw std::logic_error("open file failed " + filename);
    }
    m_fout.seekp(0, ios::end);
    cur_size = m_fout.tellp();
}
void Logger::close(){
    m_fout.close();
}

void Logger::log(Level level, const char * file, int line, const char * format, ...){
    if(m_level >= level)return;

    if(m_fout.fail()){
        throw std::logic_error("open file failed " + m_filename);
    }

    //获取当前系统时间戳并进行转换
    time_t  ticks = time(NULL);
    struct tm * ptm = localtime(&ticks);
    char timestamp[32];
    memset(timestamp, 0, sizeof(timestamp));
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", ptm);

    const char * ftm = "%s %s %s:%d ";
    int size = snprintf(nullptr, 0, ftm, timestamp, s_level[level], file, line);
    cout<<"file size = "<<size<<endl;
    if(size > 0){
        char * buffer = new char[size + 1];
        snprintf(buffer, size + 1, ftm, timestamp, s_level[level], file, line);
        buffer[size] = '\0';
        // cout<<buffer<<endl;
        m_fout<<buffer<<" ";
        cur_size += size;
        delete buffer;
    }

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int len = vsnprintf(nullptr, 0, format, arg_ptr);
    va_end(arg_ptr);
    if(len > 0){
        char * content = new char[len + 1];
        va_start(arg_ptr, format);
        vsnprintf(content, len + 1, format, arg_ptr);
        va_end(arg_ptr);
        content[len] = 0;
        m_fout << content;
        delete content;
        cur_size += len;
    }
    m_fout<<"\n";
    m_fout.flush();

    if(cur_size >= max_size && max_size > 0){
        rotate();
    }
    
    // cout<<timestamp<<endl;
    // cout<<file<<endl;
    // cout<<line<<endl;
    // cout<<format<<endl;
}

void Logger::rotate(){
    close();
    //获取当前系统时间戳并进行转换
    time_t  ticks = time(NULL);
    struct tm * ptm = localtime(&ticks);
    char timestamp[32];
    memset(timestamp, 0, sizeof(timestamp));
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", ptm);

    string filename = m_filename + timestamp;
    if(rename(m_filename.c_str(), filename.c_str()) != 0){
        throw std::logic_error("rename log file falied: " + string(strerror(errno)));
    }
    open(m_filename);
}