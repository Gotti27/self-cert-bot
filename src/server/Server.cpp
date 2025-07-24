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

#include "self-cert-bot/cert_utils.h"
#include "self-cert-bot/protocol_utils.hpp"

namespace certbot {

    void thread_body(const int clientSocket, const sockaddr_in &clientAddress, SSL_CTX *ctx,
        const X509* ca_cert, EVP_PKEY* ca_pkey, const char* ca_passkey
    ) {
        SSL *ssl = SSL_new(ctx);

        if (SSL_set_fd(ssl, clientSocket) == 0) {
            std::cerr << "Failed to bound the file descriptor\n";
            ERR_print_errors_fp(stderr);
        }

        if (const int ret = SSL_accept(ssl); ret != 1) {
            std::cerr << "Failed to accept a connection: " << ret << std::endl;
            ERR_print_errors_fp(stderr);
        }

        const char *connected_ip = inet_ntoa(clientAddress.sin_addr);

        std::vector<char> domainVector = receiveSocketMessage(ssl).value();
        const std::string domain(domainVector.begin(), domainVector.end());

        std::cout << "requested domain " << domain << std::endl;

        const std::string challenge = generate_random_string(24);
        sendSocketMessage(ssl, challenge);

        std::cout << "challenge sent " << challenge << ", size: " << challenge.size() << std::endl;

        unsigned short port;
        std::memcpy(&port, receiveSocketMessage(ssl).value().data(), sizeof(unsigned short));

        std::cout << "port: " << port << std::endl;

        addrinfo *result = resolve_domain(domain);

        const sockaddr_in *ipv4 = nullptr;
        for (const addrinfo *p = result; p != nullptr; p = p->ai_next) {
            char ipStr[INET_ADDRSTRLEN];
            // const sockaddr_in *ipv4 = reinterpret_cast<struct sockaddr_in *>(p->ai_addr);
            ipv4 = reinterpret_cast<sockaddr_in *>(p->ai_addr);

            inet_ntop(AF_INET, &ipv4->sin_addr, ipStr, sizeof(ipStr));
            std::cout << ipStr << std::endl;
            break;
        }

        if (ipv4 == nullptr) return;

        const int clientChallengeSocket = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in serverAddress{};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(port);
        serverAddress.sin_addr.s_addr = ipv4->sin_addr.s_addr;

        if (const int status = connect(clientChallengeSocket, reinterpret_cast<sockaddr *>(&serverAddress), sizeof(serverAddress))) {
            std::cerr << "Failed to connect " << status << std::endl;
            close(clientChallengeSocket);
            return;
        }

        char buffer[24];
        recv(clientChallengeSocket, buffer, 24, 0);
        close(clientChallengeSocket);
        std::cout << "received challenge " << buffer << std::endl;

        const bool isChallengeCorrect = challenge == std::string(buffer);

        if (isChallengeCorrect) {
            std::cout << "Challenge matches" << std::endl;
            X509* child_cert = nullptr;
            EVP_PKEY* child_pkey = nullptr;
            auto ca_passkey_str = std::string(ca_passkey);

            craft_certificate(ca_cert, ca_pkey, ca_passkey_str, child_cert, child_pkey);

            const std::vector<unsigned char> serializedCert = serializeX509ToDER(child_cert);

            sendSocketMessageRaw(ssl, serializedCert);
        }

        freeaddrinfo(result);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(clientSocket);
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

    [[noreturn]] void serverBody(const int serverSocket, SSL_CTX *ctx,
        const X509* ca_cert, EVP_PKEY* ca_pkey, std::string passkey
    ) {
        while (true) {
            sockaddr_in clientAddress = {};
            socklen_t clientAddressLength = sizeof clientAddress;
            const int clientSocket = accept(serverSocket,
                                            reinterpret_cast<struct sockaddr *>(&clientAddress),
                                            &clientAddressLength);

            auto thread = std::thread(thread_body, clientSocket, clientAddress, ctx,
                ca_cert, ca_pkey, passkey.c_str()
            );
            thread.detach();
        }
    }

    void Server::load_configuration(const std::string &configuration_path) {
        std::ifstream json_file(configuration_path);
        nlohmann::json data = nlohmann::json::parse(json_file);
        conf.ca_cert_path = data["ca_cert_path"].get<std::string>();
        conf.ca_key_path = data["ca_key_path"].get<std::string>();
        conf.ca_passkey_path = data["ca_passkey_path"].get<std::string>();
    }

    void Server::load_bot_root_certificate() {
        FILE *bio_cert = fopen(conf.ca_cert_path.c_str(), "rb");
        FILE *bio_pkey = fopen(conf.ca_key_path.c_str(), "rb");

        if (!bio_cert || !bio_pkey) {
            std::cerr << "Error loading CA files." << std::endl;
            return;
        }

        ca_cert = nullptr;
        ca_pkey = nullptr;

        std::ifstream passkey_file(conf.ca_passkey_path);
        std::stringstream buffer;
        buffer << passkey_file.rdbuf();
        ca_passkey = buffer.str();

        PEM_read_PrivateKey(bio_pkey, &ca_pkey, nullptr, ca_passkey.data());
        PEM_read_X509(bio_cert, &ca_cert, nullptr, nullptr);

        fclose(bio_cert);
        fclose(bio_pkey);
        if (!ca_cert || !ca_pkey) {
            std::cerr << "Error reading certificate!" << std::endl;
            exit(EXIT_FAILURE);
        }

        /*
        if (const X509_NAME *subject = X509_get_issuer_name(ca_cert)) {
            char buffer[256];
            const auto entry = X509_NAME_get_entry(subject, 3);

            const auto s = X509_NAME_ENTRY_get_data(entry);

            X509_NAME_oneline(subject, buffer, sizeof(buffer));
            std::cout << "Cert Subject: " << buffer << std::endl << s->data << std::endl;
        } else {
            std::cerr << "Failed to get subject name!" << std::endl;
        }
        */

        // BIO_free(bio_cert);

        // this->root_cert;
    }

    Server::~Server() {
        SSL_CTX_free(ctx);
        X509_free(this->ca_cert);
        EVP_PKEY_free(ca_pkey);
    }

    void Server::start() {
        /*
        addrinfo *result = resolve_domain(domain);

        for (const addrinfo *p = result; p != nullptr; p = p->ai_next) {
            char ipStr[INET_ADDRSTRLEN];
            const sockaddr_in *ipv4 = reinterpret_cast<struct sockaddr_in *>(p->ai_addr);

            inet_ntop(AF_INET, &ipv4->sin_addr, ipStr, sizeof(ipStr));
            std::cout << ipStr << std::endl;
        }

        freeaddrinfo(result);
        */

        const int serverSocket = configureServer();
        configure_SSL_context();
        std::cout << generate_random_string(64) << std::endl;

        serverBody(serverSocket, ctx, ca_cert, ca_pkey, ca_passkey);
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

        SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *) ca_passkey.c_str());

        if (
            SSL_CTX_use_certificate_file(ctx, conf.ca_cert_path.c_str(), SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(ctx, conf.ca_key_path.c_str(), SSL_FILETYPE_PEM) <= 0
        ) {
            std::cerr << "Failed to load certificate file\n";
        }
    }
} // certbot
