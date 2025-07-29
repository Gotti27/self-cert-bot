//
// Created by Mario Gottardo on 08/03/25.
//

#include "self-cert-bot/Client.h"

#include <format>
#include <fstream>
#include <iostream>
#include <ostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/types.h>
#include <sys/socket.h>
#include <nlohmann/json.hpp>

#include "self-cert-bot/cert_utils.h"
#include "self-cert-bot/protocol_utils.hpp"
#include "self-cert-bot/utils.h"

namespace certbot {
    void Client::load_configuration(const std::string &configuration_path) {
        std::ifstream json_file(configuration_path);
        nlohmann::json data = nlohmann::json::parse(json_file);
        conf.domain = data["domain"].get<std::string>();
        conf.challengePort = data["port"].get<unsigned short>();
        conf.outPath = data["outPath"].get<std::filesystem::path>();
        conf.C = data["C"].get<std::string>();
        conf.ST = data["ST"].get<std::string>();
        conf.O = data["O"].get<std::string>();
        conf.OU = data["OU"].get<std::string>();
        serverIp = inet_addr(data["serverIp"].get<std::string>().c_str());
        serverPort = data["serverPort"].get<unsigned short>();
    }

    Client::Client(const std::string &conf_path) {
        load_configuration(conf_path);
    }

    Client::Client() {
        std::string domain, country, state, organization, organizationUnit, serverIpString;
        unsigned short challengePort, serverPort;
	    std::filesystem::path outPath;

        std::cout << "Server ip: ";
        std::cin >> serverIpString;
        serverIp = inet_addr(serverIpString.c_str());
        std::cout << "Server port: ";
        std::cin >> serverPort;
        if (!std::cin.good()) {
            throw std::runtime_error("server port is not a number");
        }
        this->serverPort = serverPort;
        std::cout << "Domain: ";
        std::cin >> domain;
        std::cout << "Challenge port: ";
        std::cin >> challengePort;
        if (!std::cin.good()) {
            throw std::runtime_error("challenge port is not a number");
        }
        std::cout << "Out directory: ";
        std::cin >> outPath;
        std::cout << "Country: ";
        std::cin >> country;
        std::cout << "State: ";
        std::cin >> state;
        std::cout << "Organization: ";
        std::cin >> organization;
        std::cout << "Organization Unit: ";
        std::cin >> organizationUnit;

        conf.domain = domain;
        conf.challengePort = challengePort;
        conf.C = country;
        conf.ST = state;
        conf.O = organization;
        conf.outPath = outPath;
        conf.OU = organizationUnit;
    }

    void Client::start() const {
        std::cout << "server domain " << conf.domain << ", size " << conf.domain.size() << std::endl;
        EVP_PKEY *pkey = generate_keypair();

        const SSL_METHOD* method = TLS_client_method();
        SSL_CTX *ctx = SSL_CTX_new(method);
        if (!ctx) {
            std::cerr << "Failed to create SSL context\n";
        }

        SSL *ssl = SSL_new(ctx);

        const int clientSocket = setup_socket_client(serverIp, serverPort);
        if (clientSocket == 1) {
            exit(EXIT_FAILURE);
        }
        if (SSL_set_fd(ssl, clientSocket) == 0) {
            std::cerr << "Failed to bound the file descriptor\n";
            ERR_print_errors_fp(stderr);
        }

        if (const int ret = SSL_connect(ssl); ret != 1) {
            std::cerr << "Failed to connect\n";
            ERR_print_errors_fp(stderr);
        }

        sendSocketMessage(ssl, conf.domain);
        std::string challenge;
        if (const auto monad_challenge = receiveSocketMessage(ssl); !monad_challenge.has_value()) {
            std::cerr << "error while receiving the challenge\n";
            exit(EXIT_FAILURE);
        } else {
            challenge = monad_challenge.value().data();
            std::cout << "challenge received " << challenge << std::endl;
        }

        sendSocketMessage(ssl, conf.challengePort);

        const int challengeSocket = socket(AF_INET, SOCK_STREAM, 0);

        sockaddr_in serverAddress{};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(conf.challengePort);
        serverAddress.sin_addr.s_addr = htonl(INADDR_ANY); // inet_addr("127.0.0.1");

        const int bind_result = bind(challengeSocket, reinterpret_cast<sockaddr *>(&serverAddress), sizeof(serverAddress));
        std::cout << "bind_result " << bind_result << std::endl;

        listen(challengeSocket, 1);
        std::cout << "Server listening" << std::endl;
        sockaddr_in clientAddress = {};
        socklen_t clientAddressLength = sizeof clientAddress;
        const int respondSocket = accept(challengeSocket,
                                        reinterpret_cast<struct sockaddr *>(&clientAddress),
                                        &clientAddressLength);

        send(respondSocket, challenge.c_str(), challenge.size(), 0);
        close(challengeSocket);

        const CertFields cert_fields = {conf.C, conf.ST, conf.O, conf.OU, conf.domain};

        sendSocketMessage(ssl, cert_fields);

        const std::vector<unsigned char> serializedPublicKey = serializePublicKey(pkey);
        sendSocketMessageRaw(ssl, serializedPublicKey);

        std::vector<char> certBufferTemp = receiveSocketMessage(ssl).value();
        const auto certBuffer = std::vector<unsigned char>(certBufferTemp.begin(), certBufferTemp.end());

        const unsigned char* p = certBuffer.data();
        X509* cert = d2i_X509(nullptr, &p, certBuffer.size());
        std::cout << std::endl << X509ToPEMString(cert) << std::endl;

        std::filesystem::create_directories(conf.outPath);
        std::filesystem::path cert_path = conf.outPath / std::format("{}.pem", conf.domain);
        std::filesystem::path key_path = conf.outPath / std::format("{}.key", conf.domain);

        save_certificate(cert, cert_path.c_str());
        save_key(pkey, key_path.c_str());

        EVP_PKEY_free(pkey);
        X509_free(cert);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(clientSocket);

        exit(EXIT_SUCCESS);
    }
} // certbot
