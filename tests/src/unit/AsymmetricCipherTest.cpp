#include <libcryptosec/AsymmetricCipher.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/Base64.h>

#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe AsymmetricCipher.
 */
class AsymmetricCipherTest : public ::testing::Test {

protected:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

    // Keys for Asymmetric Cipher
    static RSAPublicKey pubKey;
    static RSAPrivateKey privKey;

    /* Content to be ciphered and compared
       to when deciphered*/
    static ByteArray baData;
};

/*
 * Initialization of variables used in the tests
 */
std::string strB64 = "SSBsb3ZlIGNoZWVzZWJ1cmdlcg==";
ByteArray AsymmetricCipherTest::baData = Base64::decode(strB64);

RSAKeyPair keyPair = RSAKeyPair(2048);
RSAPrivateKey AsymmetricCipherTest::privKey = RSAPrivateKey(keyPair.getPrivateKey()->getEvpPkey());
RSAPublicKey AsymmetricCipherTest::pubKey = RSAPublicKey(keyPair.getPublicKey()->getEvpPkey());

/**
 * @brief Tests Asymmetric Cipher with padding PKCS1
 */
TEST_F(AsymmetricCipherTest, EncryptPKCS1) {
    ByteArray baEncrypt = AsymmetricCipher::encrypt(AsymmetricCipherTest::pubKey, AsymmetricCipherTest::baData, AsymmetricCipher::PKCS1);
    ByteArray baDecrypt = AsymmetricCipher::decrypt(AsymmetricCipherTest::privKey, baEncrypt, AsymmetricCipher::PKCS1);

    ASSERT_EQ(AsymmetricCipherTest::baData, baDecrypt);
}

/**
 * @brief Tests Asymmetric Cipher with padding PKCS1_OAEP
 */
TEST_F(AsymmetricCipherTest, EncryptPKCS1_OAEP) {
    ByteArray baEncrypt = AsymmetricCipher::encrypt(AsymmetricCipherTest::pubKey, AsymmetricCipherTest::baData, AsymmetricCipher::PKCS1_OAEP);
    ByteArray baDecrypt = AsymmetricCipher::decrypt(AsymmetricCipherTest::privKey, baEncrypt, AsymmetricCipher::PKCS1_OAEP);

    ASSERT_EQ(AsymmetricCipherTest::baData, baDecrypt);
}

/**
 * @brief Tests Asymmetric Cipher with padding SSLV23
 */
TEST_F(AsymmetricCipherTest, EncryptSSLV23) {
    ByteArray baEncrypt = AsymmetricCipher::encrypt(AsymmetricCipherTest::pubKey, AsymmetricCipherTest::baData, AsymmetricCipher::SSLV23);
    ByteArray baDecrypt = AsymmetricCipher::decrypt(AsymmetricCipherTest::privKey, baEncrypt, AsymmetricCipher::SSLV23);

    ASSERT_EQ(AsymmetricCipherTest::baData, baDecrypt);
}

/*
TEST_F(AsymmetricCipherTest, EncryptNO_PADDING) {
    ByteArray baEncrypt = AsymmetricCipher::encrypt(AsymmetricCipherTest::pubKey, AsymmetricCipherTest::baData, AsymmetricCipher::NO_PADDING);
    ByteArray baDecrypt = AsymmetricCipher::decrypt(AsymmetricCipherTest::privKey, baEncrypt, AsymmetricCipher::NO_PADDING);

    ASSERT_EQ("I love cheeseburger", baDecrypt.toString());
} */