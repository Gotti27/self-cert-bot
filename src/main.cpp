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

#define BUF_SIZE 500

int main(const int argc, char *argv[]) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    if (const auto [
            mode, configPath,
            interactive] = certbot::parseConfiguration(argc, argv);
        mode == certbot::CLIENT) {
        if (interactive) {
            certbot::Client().start();
        } else {
            certbot::Client(configPath.value()).start();
        }
    } else if (mode == certbot::SERVER) {
        certbot::Server(configPath.value()).start();
    } else {
    }

    return EXIT_SUCCESS;
}
