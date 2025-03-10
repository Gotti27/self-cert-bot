cmake_minimum_required(VERSION 3.30)
project(self_cert_bot)

set(CMAKE_CXX_STANDARD 20)

add_executable(self_cert_bot src/main.cpp
        src/client/Client.cpp
        include/self-cert-bot/Client.h
        src/server/Server.cpp
        include/self-cert-bot/Server.h
        src/utils/utils.cpp
        include/self-cert-bot/utils.h
)

target_include_directories(self_cert_bot PRIVATE include)
find_package(OpenSSL REQUIRED)

target_link_libraries(self_cert_bot OpenSSL::SSL OpenSSL::Crypto)

