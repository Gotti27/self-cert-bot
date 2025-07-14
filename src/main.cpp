#include <netdb.h>
#include <iostream>
#include <cstdlib>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "self-cert-bot/Client.h"
#include "self-cert-bot/Server.h"

#define BUF_SIZE 500

int main(const int argc, char *argv[]) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    if (argc < 2) {
        exit(EXIT_FAILURE);
    }

    const std::string configuration_path = argv[2];
    if (const std::string mode = argv[1]; mode == "client") {
        const auto client = certbot::Client(configuration_path);
        client.start();
    } else if (mode == "server") {
        auto server = certbot::Server(configuration_path);
        server.start();
    } else {
        throw std::invalid_argument("Unsupported mode");
    }

    return EXIT_SUCCESS;
}
