find_package(Boost REQUIRED COMPONENTS unit_test_framework)

set(TEST_SOURCES
        test_main.cpp
        utils/test_cert_utils.cpp
        utils/test_utils.cpp
)

add_executable(test_self_cert_bot ${TEST_SOURCES})

target_link_libraries(test_self_cert_bot PRIVATE Boost::unit_test_framework self_cert_lib)
target_include_directories(test_self_cert_bot PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_definitions(test_self_cert_bot PRIVATE BOOST_TEST_DYN_LINK)

add_test(NAME SelfCertBotAllTests COMMAND test_self_cert_bot)
