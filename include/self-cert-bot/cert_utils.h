//
// Created by Mario Gottardo on 14/03/25.
//

#ifndef CERT_UTILS_H
#define CERT_UTILS_H
#include <string>
#include <openssl/types.h>

EVP_PKEY* generate_keypair();

X509* generate_child_certificate(EVP_PKEY* child_pkey, const X509* ca_cert, EVP_PKEY* ca_pkey);

void save_certificate(const X509* cert, const char* filename);

void save_key(const EVP_PKEY* pkey, const char* filename);

int craft_certificate(const X509* ca_cert, EVP_PKEY* ca_pkey, std::string& passkey, X509*& child_cert, EVP_PKEY*& child_pkey);

std::string X509ToPEMString(const X509* cert);

std::vector<unsigned char> serializeX509ToDER(const X509* cert);

#endif //CERT_UTILS_H
