cmake_minimum_required(VERSION 3.30)

project(self_cert_bot VERSION 0.1.0)
set(CMAKE_CXX_STANDARD 20)
set(EXECUTABLE_NAME self-cert)

add_library(self_cert_lib SHARED
        src/client/Client.cpp
        src/server/Server.cpp
        src/utils/cert_utils.cpp
        src/utils/utils.cpp
)
set_target_properties(self_cert_lib PROPERTIES PREFIX "")

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

add_executable(${EXECUTABLE_NAME} src/main.cpp)

target_link_libraries(${EXECUTABLE_NAME} self_cert_lib)

