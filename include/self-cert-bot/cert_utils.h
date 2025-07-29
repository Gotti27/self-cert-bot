//
// Created by Mario Gottardo on 14/03/25.
//

#ifndef CERT_UTILS_H
#define CERT_UTILS_H
#include <string>
#include <vector>
#include <openssl/types.h>

namespace certbot {
#define CHALLENGE_SIZE 24

    typedef struct CertFieldsStruct {
        std::string C;
        std::string ST;
        std::string O;
        std::string OU;
        std::string CN;
    } CertFields;

    EVP_PKEY *generate_keypair();

    X509 *generate_certificate(EVP_PKEY *pkey, const CertFields &cert_fields);

    void sign_child_certificate(const X509 *ca_cert, EVP_PKEY *ca_pkey, X509 *child_cert, EVP_PKEY *child_pkey);

    void save_certificate(const X509 *cert, const char *filename);

    void save_key(const EVP_PKEY *pkey, const char *filename);

    X509 *craft_certificate(const X509 *ca_cert, EVP_PKEY *ca_pkey,
                            EVP_PKEY *child_pkey, const CertFields &cert_fields);

    std::string X509ToPEMString(const X509 *cert);

    std::vector<unsigned char> serializeX509ToDER(const X509 *cert);

    std::vector<unsigned char> serializePrivateKey(const EVP_PKEY *pkey);

    EVP_PKEY *deserializePrivateKey(const std::vector<unsigned char> &buffer);

    std::vector<unsigned char> serializePublicKey(const EVP_PKEY *pkey);

    EVP_PKEY *deserializePublicKey(const std::vector<unsigned char> &buffer);
} // certbot
#endif //CERT_UTILS_H
