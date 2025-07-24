//
// Created by Mario Gottardo on 26/06/25.
//

#define BOOST_TEST_MODULE SelfCertBotTests
#include <boost/test/included/unit_test.hpp>

#include "self-cert-bot/utils.h"

BOOST_AUTO_TEST_CASE(RandomStringLength) {
    BOOST_CHECK(certbot::generate_random_string(12).size() == 12);
}

