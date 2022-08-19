#include <libcryptosec/Signer.h>
#include <libcryptosec/RSAKeyPair.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe Signer.
 */
class SignerTest : public ::testing::Test {

protected:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

    void testSign() {
        EXPECT_NO_THROW(
            RSAKeyPair keyPair(2048);
            privKey = keyPair.getPrivateKey();
            pubKey = keyPair.getPublicKey();

            MessageDigest md(MessageDigest::SHA256);
            hash = md.doFinal(data);

            signature = Signer::sign(*privKey, hash, MessageDigest::SHA256);
        );

        ByteArray emptySignature;
        RSAKeyPair wrongPair(1024);
        PublicKey *wrongPubKey = wrongPair.getPublicKey();

        ASSERT_TRUE(signature.size() > 0);
        ASSERT_TRUE(Signer::verify(*pubKey, signature, hash, MessageDigest::SHA256));

        ASSERT_FALSE(Signer::verify(*pubKey, emptySignature, hash, MessageDigest::SHA256));
        ASSERT_FALSE(Signer::verify(*wrongPubKey, signature, hash, MessageDigest::SHA256));
    }

    static std::string data;
    ByteArray hash;
    ByteArray signature;
    PrivateKey *privKey;
    PublicKey *pubKey;
};

/*
 * Initialization of variables used in the tests
 */
std::string SignerTest::data = "Arbitrary sentence.";

/**
 * @brief Tests signing a hash and verifying it afterwards with the correct and wrong key.
 */
TEST_F(SignerTest, SignAndVerify) {
    testSign();
}