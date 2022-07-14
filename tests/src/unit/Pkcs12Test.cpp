#include <libcryptosec/Pkcs12Factory.h>
#include <libcryptosec/Pkcs12Builder.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/certificate/CertificateBuilder.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários das classes Pkcs12, Pkcs12Builder e Pkcs12Factory.
 */
class Pkcs12Test : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    void startUp() {
        RSAKeyPair keyPair(2048);
        privKey = keyPair.getPrivateKey();

        CertificateBuilder certBuilder;
        certBuilder.setPublicKey(*keyPair.getPublicKey());
        cert = certBuilder.sign(*privKey, MessageDigest::SHA256);

        password = "tasukete";
    }

    void testPkcs12Builder() {
        EXPECT_NO_THROW(
            Pkcs12Builder pkcs12Builder;
            pkcs12Builder.setKeyAndCertificate(privKey, cert);

            pkcs12 = pkcs12Builder.doFinal(password);
        );
    }

    void testPkcs12Factory() {
        EXPECT_NO_THROW(
            ByteArray ba = pkcs12->getDerEncoded();
            factoryPkcs12 = Pkcs12Factory::fromDerEncoded(ba);
        );

        ASSERT_EQ(pkcs12->getDerEncoded(), factoryPkcs12->getDerEncoded());
    }

    void testPkcs12() {
        Certificate *pkcs12Cert = pkcs12->getCertificate(password);
        PrivateKey *pkcs12Key = pkcs12->getPrivKey(password);

        ASSERT_EQ(pkcs12Cert->getPemEncoded(), cert->getPemEncoded());
        ASSERT_EQ(pkcs12Key->getPemEncoded(), privKey->getPemEncoded());
    }

    PrivateKey *privKey;
    Certificate *cert;
    Pkcs12 *pkcs12;
    Pkcs12 *factoryPkcs12;
    std::string password;
};

/*
 * Initialization of variables used in the tests
 */

TEST_F(Pkcs12Test, InitTestCase) {
    startUp();
}

/**
 * @brief Tests if Pkcs12Builder properly builds a pkcs12 object
 */
TEST_F(Pkcs12Test, Pkcs12Builder) {
    testPkcs12Builder();
}

/**
 * @brief Tests if Pkcs12Factory properly builds a pkcs12 object
 */
TEST_F(Pkcs12Test, Pkcs12Factory) {
    testPkcs12Factory();
}

/**
 * @brief Tests if both objects from previous tests are identical and
 * if their PrivateKey and Certificate is equal to the one used in creation
 */
TEST_F(Pkcs12Test, Pkcs12) {
    testPkcs12();
}