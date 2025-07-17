//
// Created by Mario Gottardo on 14/03/25.
//

#include "self-cert-bot/cert_utils.h"

#include <fstream>
#include <unistd.h>
#include <arpa/inet.h>
#include <iostream>
#include <openssl/pem.h>
#include <random>
#include <vector>
#include <ranges>
#include <openssl/err.h>

EVP_PKEY* generate_keypair() {
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        throw std::runtime_error("Failed to initialize keygen context");
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        throw std::runtime_error("Failed to set rsa keygen bits");
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        throw std::runtime_error("Failed to generate key from context");
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

X509* generate_child_certificate(EVP_PKEY* child_pkey, const X509* ca_cert, EVP_PKEY* ca_pkey) {
    X509* cert = X509_new();

    std::default_random_engine generator;
    std::uniform_int_distribution<long> distribution(LONG_MIN,LONG_MAX);

    ASN1_INTEGER_set(X509_get_serialNumber(cert), distribution(generator));
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

    X509_set_pubkey(cert, child_pkey);

    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));
    X509_NAME* subj = X509_NAME_new();


    std::string country = "Country";
    unsigned char buffer[country.length()];
    std::ranges::copy(country, buffer);

    // FIXME: update with real input data
    X509_NAME_add_entry_by_txt(subj, "C", MBSTRING_ASC, buffer, -1, -1, 0);
    X509_NAME_add_entry_by_txt(subj, "O", MBSTRING_ASC, (unsigned char *)("Organization"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC, (unsigned char *)("CommonName"), -1, -1, 0);
    X509_set_subject_name(cert, subj);

    X509_sign(cert, ca_pkey, EVP_sha256());

    return cert;
}

void save_certificate(const X509* cert, const char* filename) {
    FILE* file = fopen(filename, "wb");
    PEM_write_X509(file, cert);
    fclose(file);
}

void save_key(const EVP_PKEY* pkey, const char* filename) {
    FILE* file = fopen(filename, "wb");
    PEM_write_PrivateKey(file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(file);
}

int craft_certificate(const X509* ca_cert, EVP_PKEY* ca_pkey, std::string& passkey, X509*& child_cert, EVP_PKEY*& child_pkey) {
    child_pkey = generate_keypair();
    child_cert = generate_child_certificate(child_pkey, ca_cert, ca_pkey);

    const bool failure = child_cert == nullptr || child_pkey == nullptr;

    if (!failure) {
        // TODO: remove this log
        std::cout << "child certificate generated\n";
    }

    return failure;
}

std::string X509ToPEMString(const X509* cert) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";

    if (!PEM_write_bio_X509(bio, cert)) {
        BIO_free(bio);
        return "";
    }

    char* data;
    const long len = BIO_get_mem_data(bio, &data);
    std::string pemString(data, len);

    BIO_free(bio);
    return pemString;
}

std::vector<unsigned char> serializeX509ToDER(const X509* cert) {
    std::vector<unsigned char> der;
    if (!cert) return der;

    const int len = i2d_X509(cert, nullptr);
    if (len <= 0) {
        ERR_print_errors_fp(stderr);
        return der;
    }

    der.resize(len);
    unsigned char* p = der.data();
    i2d_X509(cert, &p);

    return der;
}
