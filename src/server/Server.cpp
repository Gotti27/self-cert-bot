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
    int setup_secure_connection(SSL *ssl, const int clientSocket, const sockaddr_in &clientAddress) {
        if (const int ret = SSL_set_fd(ssl, clientSocket); ret == 0) {
            std::cerr << "Failed to bound the file descriptor: " << ret << std::endl;
            ERR_print_errors_fp(stderr);
            return 1;
        }

        if (const int ret = SSL_accept(ssl); ret != 1) {
            std::cerr << "Failed to accept a connection: " << ret << std::endl;
            ERR_print_errors_fp(stderr);
            return 1;
        }

        const char *connected_ip = inet_ntoa(clientAddress.sin_addr);
        std::cout << "New client connected: " << connected_ip << std::endl;

        return 0;
    }

    int execute_challenge(SSL *ssl) {
        const std::string domain(receiveSocketMessage(ssl).value().data());
        std::cout << "requested domain " << domain << std::endl;

        const std::string challenge = generate_random_string(CHALLENGE_SIZE);
        sendSocketMessage(ssl, challenge);
        std::cout << "challenge sent " << challenge << ", size: " << challenge.size() << std::endl;

        unsigned short port;
        std::memcpy(&port, receiveSocketMessage(ssl).value().data(), sizeof(unsigned short));
        std::cout << "port: " << port << std::endl;

        addrinfo *result = resolve_domain(domain);
        if (result == nullptr) {
            return 2;
        }

        const sockaddr_in *ipv4 = nullptr;

        char ipStr[INET_ADDRSTRLEN];
        ipv4 = reinterpret_cast<sockaddr_in *>(result->ai_addr);

        inet_ntop(AF_INET, &ipv4->sin_addr, ipStr, sizeof(ipStr));
        std::cout << ipStr << std::endl;

        if (ipv4 == nullptr) return 2;

        const int clientChallengeSocket = setup_socket_client(ipv4->sin_addr.s_addr, port);
        freeaddrinfo(result);

        char buffer[32] = {};
        recv(clientChallengeSocket, buffer, CHALLENGE_SIZE, 0);
        close(clientChallengeSocket);
        std::cout << "received challenge " << buffer << std::endl;

        return challenge == std::string(buffer) ? 0 : 1;
    }

    int issue_certificate(SSL *ssl, const X509 *ca_cert, EVP_PKEY *ca_pkey) {
        std::cout << "Challenge matches" << std::endl;

        auto cert_fields_buffer = receiveSocketMessage(ssl).value();
        const CertFields *p_obj = reinterpret_cast<CertFields *>(cert_fields_buffer.data());

        const auto serialized_p_key = receiveSocketMessage(ssl).value();
        EVP_PKEY *child_pkey = deserializePublicKey(
            std::vector<unsigned char>(serialized_p_key.begin(), serialized_p_key.end()));

        X509 *child_cert = craft_certificate(ca_cert, ca_pkey, child_pkey, *p_obj);

        if (child_cert == nullptr) {
            return 1;
        }

        const std::vector<unsigned char> serializedCert = serializeX509ToDER(child_cert);

        sendSocketMessageRaw(ssl, serializedCert);

        X509_free(child_cert);
        EVP_PKEY_free(child_pkey);

        return 0;
    }

    void thread_body(const int clientSocket, const sockaddr_in &clientAddress, SSL_CTX *ctx,
                     const X509 *ca_cert, EVP_PKEY *ca_pkey
    ) {
        SSL *ssl = SSL_new(ctx);

        if (const int ret = setup_secure_connection(ssl, clientSocket, clientAddress); ret == 0) {
            if (execute_challenge(ssl) == 0) {
                issue_certificate(ssl, ca_cert, ca_pkey);
            } else {
                // TODO: blacklist client
                std::cout << "Challenge does not match" << std::endl;
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(clientSocket);
    }

    int configureServer(unsigned short port) {
        const int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

        sockaddr_in serverAddress{};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(port);
        serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);

        const int bind_result = bind(serverSocket, reinterpret_cast<sockaddr *>(&serverAddress), sizeof(serverAddress));
        std::cout << "bind_result " << bind_result << std::endl;

        listen(serverSocket, 5);
        std::cout << "Server listening" << std::endl;
        return serverSocket;
    }

    [[noreturn]] void serverBody(const int serverSocket, SSL_CTX *ctx,
                                 const X509 *ca_cert, EVP_PKEY *ca_pkey) {
        while (true) {
            sockaddr_in clientAddress = {};
            socklen_t clientAddressLength = sizeof clientAddress;
            const int clientSocket = accept(serverSocket,
                                            reinterpret_cast<struct sockaddr *>(&clientAddress),
                                            &clientAddressLength);

            auto thread = std::thread(thread_body, clientSocket, clientAddress, ctx,
                                      ca_cert, ca_pkey
            );
            thread.detach();
        }
    }

    void Server::load_configuration(const std::string &configuration_path) {
        std::ifstream json_file(configuration_path);
        nlohmann::json data = nlohmann::json::parse(json_file);
        conf.port = data["port"].get<unsigned short>();
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
    }

    Server::~Server() {
        SSL_CTX_free(ctx);
        X509_free(this->ca_cert);
        EVP_PKEY_free(ca_pkey);
    }

    void Server::start() {
        const int serverSocket = configureServer(this->conf.port);
        configure_SSL_context();

        serverBody(serverSocket, ctx, ca_cert, ca_pkey);
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
