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
    std::string domain;
    X509 *root_cert = nullptr;
    struct serverConfiguration {
        std::string ca_cert_path;
        std::string ca_key_path;
    } conf = {};

    void load_bot_root_certificate();
    void load_configuration(const std::string &configuration_path);

public:
    explicit Server(const std::string& domain, const std::string& conf_path) {
        this->domain = domain;
        load_configuration(conf_path);
        load_bot_root_certificate();
    }

    ~Server();

    void start() const;
};

} // certbot

#endif //SERVER_H
