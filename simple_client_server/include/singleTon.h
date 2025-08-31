#pragma once

#include <iostream>
#include <cstring>
#include <algorithm>

namespace ktg{
    template <typename T>
    class SingleTon{
        public:
            static T * getInstance(){
                if(m_instance == nullptr){
                    m_instance = new T();
                }
                return m_instance;
            }
        private:
            SingleTon(){};
            SingleTon(const SingleTon<T>&);
            ~SingleTon();
            SingleTon<T> & operator = (const SingleTon<T>);
        private:
            static T * m_instance;
    };
    template<typename T>
    T * SingleTon<T>::m_instance = nullptr;
}