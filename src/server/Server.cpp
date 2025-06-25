//
// Created by Mario Gottardo on 08/03/25.
//

#include "self-cert-bot/Server.h"

#include <fstream>

#include "self-cert-bot/utils.h"
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <iostream>
#include <thread>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <nlohmann/json.hpp>

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

    void Server::load_configuration(const std::string &configuration_path) {
        std::ifstream json_file(configuration_path);
        nlohmann::json data = nlohmann::json::parse(json_file);
        conf.ca_cert_path = data["ca_cert_path"].get<std::string>();
        conf.ca_key_path = data["ca_key_path"].get<std::string>();
    }

    void Server::load_bot_root_certificate() {
        root_cert = X509_new();
        FILE *bio_cert = fopen(conf.ca_cert_path.c_str(), "rb");
        PEM_read_X509(bio_cert, &root_cert, nullptr, nullptr);

        fclose(bio_cert);
        if (!root_cert) {
            std::cerr << "Error reading certificate!" << std::endl;
            exit(EXIT_FAILURE);
        }

        if (const X509_NAME *subject = X509_get_issuer_name(root_cert)) {
            char buffer[256];
            const auto entry = X509_NAME_get_entry(subject, 3);

            const auto s = X509_NAME_ENTRY_get_data(entry);

            X509_NAME_oneline(subject, buffer, sizeof(buffer));
            std::cout << "Cert Subject: " << buffer << std::endl << s->data << std::endl;
        } else {
            std::cerr << "Failed to get subject name!" << std::endl;
        }
        // BIO_free(bio_cert);

        // this->root_cert;
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
        configure_SSL_context();
        std::cout << generate_random_string(64) << std::endl;

        serverBody(serverSocket);
        // SSL_CTX_free(ctx);
    }

    void Server::configure_SSL_context() {
        const SSL_METHOD *method = TLS_server_method();
        ctx = SSL_CTX_new(method);
        if (!ctx) {
            std::cerr << "Failed to create SSL context\n";
        }

        SSL_CTX_set_default_passwd_cb(ctx, [](char *buf, int size, int rwflag, void *u) {
            const auto password = static_cast<const char *>(u);
            const int len = static_cast<int>(strlen(password));

            memcpy(buf, password, len);
            return len;
        });

        std::ifstream passkey_file(conf.ca_passkey_path);
        std::stringstream buffer;
        buffer << passkey_file.rdbuf();
        std::string passkey = buffer.str();

        SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *) passkey.c_str());

        if (
            SSL_CTX_use_certificate_file(ctx, conf.ca_cert_path.c_str(), SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(ctx, conf.ca_key_path.c_str(), SSL_FILETYPE_PEM) <= 0
        ) {
            std::cerr << "Failed to load certificate file\n";
        }
    }
} // certbot
