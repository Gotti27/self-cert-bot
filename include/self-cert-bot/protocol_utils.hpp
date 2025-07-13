//
// Created by Mario Gottardo on 10/07/25.
//

#ifndef PROTOCOL_UTILS_H
#define PROTOCOL_UTILS_H
#include <optional>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/types.h>

namespace certbot {

    inline std::optional<std::vector<char>> receiveSocketMessage(SSL* ssl) {
        constexpr int MAX_PAYLOAD_SIZE = 1024 * 1024;

        int32_t netLength;
        if (SSL_read(ssl, &netLength, sizeof(netLength)) != sizeof(netLength)) {
            return std::nullopt;
        }

        const int32_t length = netLength;
        if (length <= 0 || length > MAX_PAYLOAD_SIZE) {
            return std::nullopt;
        }

        std::vector<char> buffer(length);
        SSL_read(ssl, buffer.data(), length);

        return buffer;
    }

    inline int sendSocketMessageRaw(SSL* ssl, const std::vector<char>& payload) {
        const auto payloadSize = static_cast<int32_t>(payload.size());

        if (const int ret_code = SSL_write(ssl, &payloadSize, sizeof(int32_t)); ret_code <= 0) {
            return SSL_get_error(ssl, ret_code);
        }

        if (const int ret_code = SSL_write(ssl, payload.data(), payloadSize); ret_code <= 0) {
            return SSL_get_error(ssl, ret_code);
        }

        return SSL_ERROR_NONE;
    }

    template<typename T>
    int sendSocketMessage(SSL* ssl, const T& payload) {
        std::vector<char> buffer(sizeof(T));
        std::memcpy(buffer.data(), &payload, sizeof(T));

        return sendSocketMessageRaw(ssl, buffer);
    }

    inline int sendSocketMessage(SSL* ssl, const std::string& payload) {
        const std::vector buffer(payload.begin(), payload.end());

        return sendSocketMessageRaw(ssl, buffer);
    }

} // certbot

#endif //PROTOCOL_UTILS_H
