//
// Created by Mario Gottardo on 08/03/25.
//

#ifndef UTILS_H
#define UTILS_H
#include <netdb.h>
#include <optional>
#include <string>

namespace certbot {

enum ExecutionMode { CLIENT, SERVER };

struct CertBotSettings {
    std::optional<ExecutionMode> mode;
    std::optional<std::string> configPath;
    bool interactive {false};
};

CertBotSettings parseConfiguration(int argc, char *argv[]);

std::string generate_random_string(int len);

addrinfo* resolve_domain(const std::string &domain);

int setup_socket_client(in_addr_t server_addr, unsigned short server_port);

} // certbot

#endif //UTILS_H
