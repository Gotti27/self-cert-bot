//
// Created by Mario Gottardo on 08/03/25.
//

#include "self-cert-bot/Client.h"

#include <cstring>
#include <iostream>
#include <ostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace certbot {
    void Client::start() const {
        const int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        std::cout << "server domain " << domain << std::endl;

        sockaddr_in serverAddress{};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(8080);
        serverAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // inet_addr("127.0.0.1")

        const int status = connect(clientSocket, reinterpret_cast<sockaddr *>(&serverAddress), sizeof(serverAddress));

        std::cout << "client status: " << status << std::endl;

        bool flag = true;
        const auto hello_message = "Hej!";
        send(clientSocket, hello_message, strlen(hello_message), 0);

        while (flag) {
            std::string message;
            std::cout << "$> ";
            std::cin >> message;
            send(clientSocket, message.c_str(), strlen(message.c_str()), 0);
            if (message == "exit") {
                flag = false;
            }
        }

        close(clientSocket);

        exit(EXIT_SUCCESS);
    }
} // certbot