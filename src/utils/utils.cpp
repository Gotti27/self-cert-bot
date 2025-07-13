//
// Created by Mario Gottardo on 08/03/25.
//

#include "self-cert-bot/utils.h"

#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

std::string generate_random_string(const int len) {
    static constexpr char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    unsigned char tmp_s[len];
    std::string generated;
    generated.reserve(len);

    if (RAND_bytes(tmp_s, len) == -1) {
        // ERR_get_error()
        std::cerr << "RAND_bytes failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < len; ++i) {
        generated += alphanum[tmp_s[i] % (sizeof(alphanum) - 1)];
    }

    return generated;
}


addrinfo *resolve_domain(const std::string &domain) {
    addrinfo hints = {}, *result;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    if (const int s = getaddrinfo(domain.c_str(), nullptr, &hints, &result); s != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(s);
        //exit(EXIT_FAILURE);
    }

    return result;
}

int setup_socket_client() {
    const int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // inet_addr("127.0.0.1");

    if (const int status = connect(clientSocket, reinterpret_cast<sockaddr *>(&serverAddress), sizeof(serverAddress))) {
        std::cerr << "Failed to connect " << status << std::endl;
        close(clientSocket);
        return 1;
    }

    return clientSocket;
}
