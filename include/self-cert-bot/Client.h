//
// Created by Mario Gottardo on 08/03/25.
//

#ifndef CLIENT_H
#define CLIENT_H
#include <string>

namespace certbot {

class Client {
private:
    std::string domain;

public:
    explicit Client(const std::string &domain) {
        this->domain = domain;
    }

    void start() const;
};

} // certbot

#endif //CLIENT_H
