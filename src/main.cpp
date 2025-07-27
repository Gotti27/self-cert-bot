#include <netdb.h>
#include <iostream>
#include <cstdlib>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "self-cert-bot/Client.h"
#include "self-cert-bot/Server.h"
#include "self-cert-bot/utils.h"

void startup_client(const certbot::CertBotSettings &settings) {
    if (settings.interactive) {
        certbot::Client().start();
    } else {
        certbot::Client(settings.configPath.value()).start();
    }
}

void startup_server(const certbot::CertBotSettings &settings) {
    certbot::Server(settings.configPath.value()).start();
}

int main(const int argc, char *argv[]) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    switch (const certbot::CertBotSettings settings = certbot::parseConfiguration(argc, argv); settings.mode.value()) {
        case certbot::CLIENT:
            startup_client(settings);
            break;
        case certbot::SERVER:
            startup_server(settings);
            break;
        default:
            std::cerr << "Invalid mode, exiting";
            exit(EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}
