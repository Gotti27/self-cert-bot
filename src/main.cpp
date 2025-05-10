#include <netdb.h>
#include <iostream>
#include <cstdlib>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>

#include "self-cert-bot/Client.h"
#include "self-cert-bot/Server.h"

#define BUF_SIZE 500

int main(const int argc, char *argv[]) {

    for (int i = 0; i < argc; i++) {
        std::cout << argv[i] << std::endl;
    }

    if (argc < 3) {
        exit(EXIT_FAILURE);
    }

    const std::string domain = argv[1];

    OpenSSL_add_all_algorithms();

    if (const std::string mode = argv[2]; mode == "client") {
        const auto client = certbot::Client("test.com");
        client.start();
    } else if (mode == "server") {
        const std::string cert_path = argv[3];
        const auto server = certbot::Server(domain, cert_path);
        server.start();
    }

    exit(EXIT_SUCCESS);
}
