//
// Created by Mario Gottardo on 08/03/25.
//

#ifndef SERVER_H
#define SERVER_H
#include <string>
#include <openssl/types.h>

namespace certbot {

class Server {
private:
    X509 *ca_cert = nullptr;
    EVP_PKEY* ca_pkey = nullptr;
    std::string ca_passkey;
    SSL_CTX *ctx = nullptr;
    struct serverConfiguration {
        std::string ca_cert_path;
        std::string ca_key_path;
        std::string ca_passkey_path;
    } conf = {};

    void load_configuration(const std::string &configuration_path);
    void load_bot_root_certificate();
    void configure_SSL_context();

public:
    explicit Server(const std::string& conf_path) {
        load_configuration(conf_path);
        load_bot_root_certificate();
    }

    ~Server();

    void start();
};

} // certbot

#endif //SERVER_H
