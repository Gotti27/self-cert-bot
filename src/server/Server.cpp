//
// Created by Mario Gottardo on 08/03/25.
//

#include "self-cert-bot/Server.h"
#include "self-cert-bot/utils.h"
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <iostream>
#include <thread>
#include <openssl/pem.h>

namespace certbot {
    void thread_body(const int clientSocket, const sockaddr_in &clientAddress) {
        bool flag = true;

        while (flag) {
            const char *connected_ip = inet_ntoa(clientAddress.sin_addr);

            char buffer[1024] = {};
            recv(clientSocket, buffer, sizeof(buffer), 0);

            std::cout << "Message from " << connected_ip << "--" << clientSocket << ": " << buffer << std::endl;

            if (strcmp(buffer, "exit") == 0) {
                flag = false;
            }
        }
    }

    int configureServer() {
        const int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

        sockaddr_in serverAddress{};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(8080);
        serverAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // inet_addr("127.0.0.1");

        const int bind_result = bind(serverSocket, reinterpret_cast<sockaddr *>(&serverAddress), sizeof(serverAddress));
        std::cout << "bind_result " << bind_result << std::endl;

        listen(serverSocket, 5);
        std::cout << "Server listening" << std::endl;
        return serverSocket;
    }

    [[noreturn]] void serverBody(const int serverSocket) {
        while (true) {
            sockaddr_in clientAddress = {};
            socklen_t clientAddressLength = sizeof clientAddress;
            const int clientSocket = accept(serverSocket,
                                            reinterpret_cast<struct sockaddr *>(&clientAddress),
                                            &clientAddressLength);

            auto thread = std::thread(thread_body, clientSocket, clientAddress);
            thread.detach();
        }
    }

    void Server::load_bot_root_certificate(const std::string &cert_path) {
        root_cert = X509_new();
        FILE* bio_cert = fopen(cert_path.c_str(), "rb");
        PEM_read_X509(bio_cert, &root_cert, nullptr, nullptr);

        fclose(bio_cert);
        if (!root_cert) {
            std::cerr << "Error reading certificate!" << std::endl;
            exit(EXIT_FAILURE);
        }

        if (const X509_NAME* subject = X509_get_issuer_name(root_cert)) {
            char buffer[256];
            const auto entry = X509_NAME_get_entry(subject, 3);

            const auto s = X509_NAME_ENTRY_get_data(entry);

            X509_NAME_oneline(subject, buffer, sizeof(buffer));
            std::cout << "Cert Subject: " << buffer << std::endl << s->data << std::endl;
        } else {
            std::cerr << "Failed to get subject name!" << std::endl;
        }
        // BIO_free(bio_cert);

        this->root_cert;
    }

    Server::~Server() {
        X509_free(this->root_cert);
    }

    void Server::start() const {
        addrinfo *result = resolve_domain(domain);

        for (const addrinfo *p = result; p != nullptr; p = p->ai_next) {
            char ipStr[INET_ADDRSTRLEN];
            const sockaddr_in *ipv4 = reinterpret_cast<struct sockaddr_in *>(p->ai_addr);

            inet_ntop(AF_INET, &ipv4->sin_addr, ipStr, sizeof(ipStr));
            std::cout << ipStr << std::endl;
        }

        freeaddrinfo(result);

        const int serverSocket = configureServer();
        std::cout << generate_random_string(64) << std::endl;

        serverBody(serverSocket);
    }
} // certbot
