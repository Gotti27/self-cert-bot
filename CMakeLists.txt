cmake_minimum_required(VERSION 3.30)
project(self_cert_bot VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)

add_library(self_cert_lib
        src/client/Client.cpp
        src/server/Server.cpp
        src/utils/utils.cpp
        src/utils/protocol.cpp
)

target_include_directories(self_cert_lib PUBLIC include)


find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(Boost REQUIRED)

enable_testing()
add_subdirectory(tests)


target_link_libraries(self_cert_lib
        OpenSSL::SSL
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
)

add_executable(self_cert_bot src/main.cpp)

target_link_libraries(self_cert_bot self_cert_lib)
