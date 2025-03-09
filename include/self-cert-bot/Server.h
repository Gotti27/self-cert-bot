//
// Created by Mario Gottardo on 08/03/25.
//

#ifndef SERVER_H
#define SERVER_H
#include <string>

namespace certbot {

class Server {
private:
    std::string domain;

public:
    explicit Server(const std::string &domain) {
        this->domain = domain;
    }

    void start() const;
};

} // certbot

#endif //SERVER_H
