//
// Created by Mario Gottardo on 26/06/25.
//

#include <filesystem>
#include <fstream>
#include <arpa/inet.h>
#include <boost/test/unit_test.hpp>
#include <openssl/rand.h>

#include "self-cert-bot/utils.h"

BOOST_AUTO_TEST_SUITE(generate_random_stringTestSuite)

    BOOST_AUTO_TEST_CASE(RandomStringLength) {
        BOOST_CHECK(certbot::generate_random_string(12).size() == 12);
    }

    BOOST_AUTO_TEST_CASE(RandomStrin) {
        BOOST_CHECK(certbot::generate_random_string(24) != certbot::generate_random_string(24));
    }

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(resolve_domainTestSuite)

    BOOST_AUTO_TEST_CASE(DomainResolution) {
        const addrinfo *addrinfo = certbot::resolve_domain("local.mostserene.eu");

        BOOST_CHECK(addrinfo != nullptr);

        char ipStr[INET_ADDRSTRLEN];
        const auto *ipv4 = reinterpret_cast<sockaddr_in *>(addrinfo->ai_addr);

        inet_ntop(AF_INET, &ipv4->sin_addr, ipStr, sizeof(ipStr));

        BOOST_CHECK(strcmp(ipStr, "127.0.0.1") == 0);
    }

    BOOST_AUTO_TEST_CASE(NonExistentDomainResolution) {
        const addrinfo *addrinfo = certbot::resolve_domain("non-existent.mostserene.eu");

        BOOST_CHECK(addrinfo == nullptr);
    }

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(ConfigurationParsingTestSuite)
    BOOST_AUTO_TEST_CASE(InteractiveFlagTest) {
        const char *argv[] = {"prog", "--interactive"};
        auto settings = certbot::parseConfiguration(2, const_cast<char **>(argv));
        BOOST_CHECK(settings.interactive);
    }

    BOOST_AUTO_TEST_CASE(ModeClientTest) {
        const char *argv[] = {"prog", "--mode", "client"};
        auto settings = certbot::parseConfiguration(3, const_cast<char **>(argv));
        BOOST_REQUIRE(settings.mode.has_value());
        BOOST_CHECK(settings.mode.value() == certbot::CLIENT);
    }

    BOOST_AUTO_TEST_CASE(ModeServerTest) {
        const char *argv[] = {"prog", "-m", "server"};
        auto settings = certbot::parseConfiguration(3, const_cast<char **>(argv));
        BOOST_REQUIRE(settings.mode.has_value());
        BOOST_CHECK(settings.mode.value() == certbot::SERVER);
    }

    BOOST_AUTO_TEST_CASE(InvalidModeThrows) {
        const char *argv[] = {"prog", "--mode", "invalid"};
        BOOST_CHECK_THROW(certbot::parseConfiguration(3, const_cast<char**>(argv)), std::invalid_argument);
    }

    BOOST_AUTO_TEST_CASE(ConfigPathExists) {
        // Create a temporary file
        std::string tempFile = "temp_config.json";
        std::ofstream(tempFile).put('x');
        BOOST_REQUIRE(std::filesystem::exists(tempFile));

        const char *argv[] = {"prog", "--config", tempFile.c_str()};
        auto settings = certbot::parseConfiguration(3, const_cast<char **>(argv));
        BOOST_REQUIRE(settings.configPath.has_value());
        BOOST_CHECK(settings.configPath.value() == tempFile);

        std::filesystem::remove(tempFile);
    }

    BOOST_AUTO_TEST_CASE(ConfigPathMissingThrows) {
        const char *argv[] = {"prog", "-c", "nonexistent.conf"};
        BOOST_CHECK_THROW(certbot::parseConfiguration(3, const_cast<char**>(argv)), std::invalid_argument);
    }

    BOOST_AUTO_TEST_CASE(CombinedOptionsTest) {
        std::string tempFile = "combined.conf";
        std::ofstream(tempFile).put('x');

        const char *argv[] = {"prog", "-i", "--mode", "server", "-c", tempFile.c_str()};
        auto settings = certbot::parseConfiguration(6, const_cast<char **>(argv));

        BOOST_CHECK(settings.interactive);
        BOOST_CHECK(settings.mode.value() == certbot::SERVER);
        BOOST_CHECK(settings.configPath.value() == tempFile);

        std::filesystem::remove(tempFile);
    }

    BOOST_AUTO_TEST_CASE(MissingModeArgument) {
        const char *argv[] = {"prog", "--mode"};
        BOOST_CHECK_THROW(certbot::parseConfiguration(2, const_cast<char**>(argv)), std::invalid_argument);
    }

    BOOST_AUTO_TEST_CASE(MissingConfigArgument) {
        const char *argv[] = {"prog", "--config"};
        BOOST_CHECK_THROW(certbot::parseConfiguration(2, const_cast<char**>(argv)), std::invalid_argument);
    }

BOOST_AUTO_TEST_SUITE_END()
