//
// Created by Mario Gottardo on 08/03/25.
//

#ifndef CLIENT_H
#define CLIENT_H
#include <iostream>
#include <string>

namespace certbot {

class Client {
private:
    struct clientConfiguration {
        std::string domain;
        unsigned short challengePort;
        std::string C;
        std::string ST;
        std::string O;
        std::string OU;
    } conf = {};
    void load_configuration(const std::string& configuration_path);

public:
    explicit Client(const std::string& conf_path);

    explicit Client();

    void start() const;
};

} // certbot

#endif //CLIENT_H
