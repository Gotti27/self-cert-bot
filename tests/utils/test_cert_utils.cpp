//
// Created by Mario Gottardo on 26/07/25.
//

// #define BOOST_TEST_MODULE SelfCertBotCertUtilsTests
#include <openssl/rand.h>
#include <boost/test/unit_test.hpp>
#include <openssl/x509.h>

#include "self-cert-bot/cert_utils.h"
#include "self-cert-bot/Client.h"

BOOST_AUTO_TEST_SUITE(generate_keypairTestSuite)

    BOOST_AUTO_TEST_CASE(KeyPairGeneration) {
        EVP_PKEY *pkey = nullptr;

        BOOST_REQUIRE_NO_THROW(pkey = certbot::generate_keypair());
        BOOST_REQUIRE(pkey != nullptr);
        BOOST_CHECK(EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA);

        EVP_PKEY_free(pkey);
    }

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(generate_certificateTestSuite)

    BOOST_AUTO_TEST_CASE(CertificateGeneration) {
        EVP_PKEY *pkey = certbot::generate_keypair();
        const certbot::CertFields cert_fields{
            "CN", "ST", "Organization", "OrganizationUnit", "local.com"
        };

        X509 *cert = nullptr;
        BOOST_CHECK_NO_THROW(cert = certbot::generate_certificate(pkey, cert_fields));
        BOOST_CHECK(cert != nullptr);

        const X509_NAME *name = X509_get_subject_name(cert);
        std::vector<std::string> fields = {
            "CN", "ST", "Organization", "OrganizationUnit", "local.com"
        };

        for (int loc = 0; loc < X509_NAME_entry_count(name); ++loc) {
            const X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, loc);
            const auto value = std::string(reinterpret_cast<char *>(X509_NAME_ENTRY_get_data(entry)->data));

            BOOST_CHECK(fields[loc] == value);
        }

        EVP_PKEY_free(pkey);
        X509_free(cert);
    }

    BOOST_AUTO_TEST_CASE(CertificatePubKey) {
        EVP_PKEY *pkey = certbot::generate_keypair();
        const certbot::CertFields cert_fields{
            "CN", "ST", "Organization", "OrganizationUnit", "local.com"
        };

        X509 *cert = nullptr;
        BOOST_CHECK_NO_THROW(cert = certbot::generate_certificate(pkey, cert_fields));
        BOOST_CHECK(cert != nullptr);
        BOOST_CHECK(EVP_PKEY_eq(pkey, X509_get_pubkey(cert)));

        EVP_PKEY_free(pkey);
        X509_free(cert);
    }

    BOOST_AUTO_TEST_CASE(NoDuplicateSerial) {
        EVP_PKEY *pkey = certbot::generate_keypair();
        const certbot::CertFields cert_fields{
            "CN", "ST", "Organization", "OrganizationUnit", "local.com"
        };

        X509 *cert1 = nullptr;
        X509 *cert2 = nullptr;
        BOOST_CHECK_NO_THROW(cert1 = certbot::generate_certificate(pkey, cert_fields));
        BOOST_CHECK_NO_THROW(cert2 = certbot::generate_certificate(pkey, cert_fields));

        BOOST_CHECK(cert1 != nullptr);
        BOOST_CHECK(cert2 != nullptr);

        BOOST_CHECK(ASN1_INTEGER_cmp(X509_get_serialNumber(cert1), X509_get_serialNumber(cert2)) == 0);

        EVP_PKEY_free(pkey);
        X509_free(cert1);
        X509_free(cert2);
    }

BOOST_AUTO_TEST_SUITE_END()
