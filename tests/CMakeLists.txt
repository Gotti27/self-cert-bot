find_package(Boost REQUIRED COMPONENTS unit_test_framework)

add_executable(test_self_cert_bot utils/test_utils.cpp)

target_include_directories(test_self_cert_bot PRIVATE ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(test_self_cert_bot
        Boost::unit_test_framework
        self_cert_lib
)

add_test(NAME SelfCertBotTests COMMAND test_self_cert_bot)
