#include <libcryptosec/Signer.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/DSAKeyPair.h>
#include <libcryptosec/ECDSAKeyPair.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe Signer.
 */
class SignerTest : public ::testing::Test {

protected:
    virtual void SetUp() {
        MessageDigest::loadMessageDigestAlgorithms();
    }

    virtual void TearDown() {
    }

    void testSigner(KeyPair keyPair, KeyPair wrongKeyPair, MessageDigest::Algorithm algorithm) {
        PrivateKey *privKey;
        PublicKey *pubKey;
        PublicKey *wrongPubKey;
        ByteArray hash;
        ByteArray signature;
        ByteArray emptySignature;

        EXPECT_NO_THROW(
            privKey = keyPair.getPrivateKey();
            pubKey = keyPair.getPublicKey();

            MessageDigest md(algorithm);
            hash = md.doFinal(data);

            signature = Signer::sign(*privKey, hash, algorithm);
        );

        wrongPubKey = wrongKeyPair.getPublicKey();

        ASSERT_TRUE(signature.size() > 0);
        ASSERT_TRUE(Signer::verify(*pubKey, signature, hash, algorithm));

        ASSERT_FALSE(Signer::verify(*pubKey, emptySignature, hash, algorithm));
        ASSERT_FALSE(Signer::verify(*wrongPubKey, signature, hash, algorithm));
    }

    static std::string data;
};

/*
 * Initialization of variables used in the tests
 */
std::string SignerTest::data = "Arbitrary sentence.";

/**
 * @brief Tests signing functions with RSA Key Pair with a few digest algorithms
 */
TEST_F(SignerTest, RSA) {
    RSAKeyPair keyPair(2048);
    RSAKeyPair wrongKeyPair(2048);
    
    testSigner(keyPair, wrongKeyPair, MessageDigest::SHA256);
    testSigner(keyPair, wrongKeyPair, MessageDigest::SHA512);
}

/**
 * @brief Tests signing functions with DSA Key Pair with a few digest algorithms
 */
TEST_F(SignerTest, DSA) {
    DSAKeyPair keyPair(512);
    DSAKeyPair wrongKeyPair(512);
    
    //testSigner(keyPair, wrongKeyPair, MessageDigest::SHA256);
}

/**
 * @brief Tests signing functions with ECDSA Key Pair with a few digest algorithms
 */
TEST_F(SignerTest, ECDSA) {
    ECDSAKeyPair keyPair(AsymmetricKey::SECG_SECP256K1);
    ECDSAKeyPair wrongKeyPair(AsymmetricKey::SECG_SECP256K1);
    
    //testSigner(keyPair, wrongKeyPair, MessageDigest::SHA1);
}