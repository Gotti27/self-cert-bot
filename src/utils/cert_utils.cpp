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
#include <openssl/err.h>

namespace certbot {
    EVP_PKEY *generate_keypair() {
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

    X509 *generate_certificate(EVP_PKEY *pkey, const CertFields &cert_fields) {
        X509 *cert = X509_new();

        std::default_random_engine generator;
        std::uniform_int_distribution distribution(LONG_MIN,LONG_MAX);

        ASN1_INTEGER_set(X509_get_serialNumber(cert), distribution(generator));
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

        X509_set_pubkey(cert, pkey);

        X509_NAME *subj = X509_NAME_new();
        X509_NAME_add_entry_by_txt(subj, "C", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>(cert_fields.C.c_str()), -1, -1, 0);
        X509_NAME_add_entry_by_txt(subj, "ST", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>(cert_fields.ST.data()), -1, -1, 0);
        X509_NAME_add_entry_by_txt(subj, "O", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>(cert_fields.O.data()), -1, -1, 0);
        X509_NAME_add_entry_by_txt(subj, "OU", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>(cert_fields.OU.data()), -1, -1, 0);
        X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>(cert_fields.CN.data()), -1, -1, 0);

        X509_set_subject_name(cert, subj);

        return cert;
    }

    void sign_child_certificate(const X509 *ca_cert, EVP_PKEY *ca_pkey, X509 *child_cert, EVP_PKEY *child_pkey) {
        X509_set_issuer_name(child_cert, X509_get_subject_name(ca_cert));
        X509_sign(child_cert, ca_pkey, EVP_sha256());
    }

    void save_certificate(const X509 *cert, const char *filename) {
        FILE *file = fopen(filename, "wb");
        PEM_write_X509(file, cert);
        fclose(file);
    }

    void save_key(const EVP_PKEY *pkey, const char *filename) {
        FILE *file = fopen(filename, "wb");
        PEM_write_PrivateKey(file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(file);
    }

    X509 *craft_certificate(const X509 *ca_cert, EVP_PKEY *ca_pkey,
                            EVP_PKEY *child_pkey, const CertFields &cert_fields) {
        X509 *child_cert = generate_certificate(child_pkey, cert_fields);
        sign_child_certificate(ca_cert, ca_pkey, child_cert, child_pkey);

        return child_cert;
    }

    std::string X509ToPEMString(const X509 *cert) {
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio) return "";

        if (!PEM_write_bio_X509(bio, cert)) {
            BIO_free(bio);
            return "";
        }

        char *data;
        const long len = BIO_get_mem_data(bio, &data);
        std::string pemString(data, len);

        BIO_free(bio);
        return pemString;
    }

    std::vector<unsigned char> serializeX509ToDER(const X509 *cert) {
        std::vector<unsigned char> der;
        if (!cert) return der;

        const int len = i2d_X509(cert, nullptr);
        if (len <= 0) {
            ERR_print_errors_fp(stderr);
            return der;
        }

        der.resize(len);
        unsigned char *p = der.data();
        i2d_X509(cert, &p);

        return der;
    }

    std::vector<unsigned char> serializePrivateKey(const EVP_PKEY *pkey) {
        const int len = i2d_PrivateKey(pkey, nullptr);
        if (len <= 0) {
            throw std::runtime_error("Failed to get key length");
        }

        std::vector<unsigned char> buffer(len);
        unsigned char *p = buffer.data();
        if (i2d_PrivateKey(pkey, &p) <= 0) {
            throw std::runtime_error("Failed to serialize private key");
        }

        return buffer;
    }


    EVP_PKEY *deserializePrivateKey(const std::vector<unsigned char> &buffer) {
        if (buffer.empty()) {
            throw std::runtime_error("Buffer is empty");
        }

        const unsigned char *p = buffer.data();
        EVP_PKEY *pkey = d2i_PrivateKey(EVP_PKEY_RSA, nullptr, &p, buffer.size());
        if (!pkey) {
            throw std::runtime_error("Failed to deserialize private key");
        }

        return pkey;
    }

    std::vector<unsigned char> serializePublicKey(const EVP_PKEY *pkey) {
        const int len = i2d_PublicKey(pkey, nullptr);
        if (len <= 0) {
            throw std::runtime_error("Failed to get key length");
        }

        std::vector<unsigned char> buffer(len);
        unsigned char *p = buffer.data();
        if (i2d_PublicKey(pkey, &p) <= 0) {
            throw std::runtime_error("Failed to serialize private key");
        }

        return buffer;
    }

    EVP_PKEY * deserializePublicKey(const std::vector<unsigned char> &buffer) {
        if (buffer.empty()) {
            throw std::runtime_error("Buffer is empty");
        }

        const unsigned char *p = buffer.data();
        EVP_PKEY *pkey = d2i_PublicKey(EVP_PKEY_RSA, nullptr, &p, buffer.size());
        if (!pkey) {
            throw std::runtime_error("Failed to deserialize public key");
        }

        return pkey;
    }
} // certbot
