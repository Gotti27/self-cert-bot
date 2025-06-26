//
// Created by Mario Gottardo on 08/03/25.
//

#ifndef UTILS_H
#define UTILS_H
#include <netdb.h>
#include <string>

std::string generate_random_string(int len);

addrinfo* resolve_domain(const std::string &domain);

int setup_socket_client();

#endif //UTILS_H
