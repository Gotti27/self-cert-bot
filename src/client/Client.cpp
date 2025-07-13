//
// Created by Mario Gottardo on 08/03/25.
//

#include "self-cert-bot/Client.h"

#include <iostream>
#include <ostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/types.h>
#include <sys/socket.h>

#include "self-cert-bot/protocol_utils.hpp"
#include "self-cert-bot/utils.h"

namespace certbot {
    void Client::start() const {
        std::cout << "server domain " << domain << ", size " << domain.size() << std::endl;

        const SSL_METHOD* method = TLS_client_method();
        SSL_CTX *ctx = SSL_CTX_new(method);
        if (!ctx) {
            std::cerr << "Failed to create SSL context\n";
        }

        SSL *ssl = SSL_new(ctx);

        const int clientSocket = setup_socket_client();
        if (SSL_set_fd(ssl, clientSocket) == 0) {
            std::cerr << "Failed to bound the file descriptor\n";
            ERR_print_errors_fp(stderr);
        }

        if (const int ret = SSL_connect(ssl); ret != 1) {
            std::cerr << "Failed to connect\n";
            ERR_print_errors_fp(stderr);
        }

        sendSocketMessage(ssl, this->domain);

        if (const auto monad_challenge = receiveSocketMessage(ssl); !monad_challenge.has_value()) {
            std::cerr << "error while receiving the challenge\n";
            exit(EXIT_FAILURE);
        } else {
            const std::string challenge(monad_challenge.value().data());
            std::cout << "challenge received " << challenge << std::endl;
        }

        sendSocketMessage(ssl, this->challengePort);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(clientSocket);

        exit(EXIT_SUCCESS);
    }
} // certbot