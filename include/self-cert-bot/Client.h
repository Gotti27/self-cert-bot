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
    unsigned short challengePort;

public:
    explicit Client(const std::string &domain, const unsigned short challengePort) {
        this->domain = domain;
        this->challengePort = challengePort;
    }

    void start() const;
};

} // certbot

#endif //CLIENT_H
