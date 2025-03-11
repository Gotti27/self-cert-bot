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
    void load_bot_root_certificate(const std::string &cert_path);

public:
    explicit Server(const std::string& domain, const std::string& cert_path) {
        this->domain = domain;
        load_bot_root_certificate(cert_path);
    }

    ~Server();

    void start() const;
};

} // certbot

#endif //SERVER_H
