#include <libcryptosec/AsymmetricCipher.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/ByteArray.h>

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
    static std::string stringASCII;
    static std::string stringNP;
    static ByteArray baData;
    static ByteArray baDataNP;
};

/*
 * Initialization of variables used in the tests
 */
std::string AsymmetricCipherTest::stringASCII = "I love cheeseburger.";
ByteArray AsymmetricCipherTest::baData = ByteArray(AsymmetricCipherTest::stringASCII);
std::string AsymmetricCipherTest::stringNP = "Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor. Aenean massa. Cum sociis natoque pen";
ByteArray AsymmetricCipherTest::baDataNP = ByteArray(AsymmetricCipherTest::stringNP);

RSAKeyPair keyPair = RSAKeyPair(1024);
RSAPrivateKey AsymmetricCipherTest::privKey = RSAPrivateKey(keyPair.getPrivateKey()->getEvpPkey());
RSAPublicKey AsymmetricCipherTest::pubKey = RSAPublicKey(keyPair.getPublicKey()->getEvpPkey());

/**
 * @brief Tests Asymmetric Cipher with padding PKCS1
 */
TEST_F(AsymmetricCipherTest, EncryptPKCS1) {
    ByteArray baEncrypt = AsymmetricCipher::encrypt(AsymmetricCipherTest::pubKey, AsymmetricCipherTest::baData, AsymmetricCipher::PKCS1);
    ByteArray baDecrypt = AsymmetricCipher::decrypt(AsymmetricCipherTest::privKey, baEncrypt, AsymmetricCipher::PKCS1);

    ASSERT_NE(AsymmetricCipherTest::baData, baEncrypt);
    ASSERT_EQ(AsymmetricCipherTest::baData, baDecrypt);
}

/**
 * @brief Tests Asymmetric Cipher with padding PKCS1_OAEP
 */
TEST_F(AsymmetricCipherTest, EncryptPKCS1_OAEP) {
    ByteArray baEncrypt = AsymmetricCipher::encrypt(AsymmetricCipherTest::pubKey, AsymmetricCipherTest::baData, AsymmetricCipher::PKCS1_OAEP);
    ByteArray baDecrypt = AsymmetricCipher::decrypt(AsymmetricCipherTest::privKey, baEncrypt, AsymmetricCipher::PKCS1_OAEP);

    ASSERT_NE(AsymmetricCipherTest::baData, baEncrypt);
    ASSERT_EQ(AsymmetricCipherTest::baData, baDecrypt);
}

/**
 * @brief Tests Asymmetric Cipher with padding SSLV23
 */
TEST_F(AsymmetricCipherTest, EncryptSSLV23) {
    ByteArray baEncrypt = AsymmetricCipher::encrypt(AsymmetricCipherTest::pubKey, AsymmetricCipherTest::baData, AsymmetricCipher::SSLV23);
    ByteArray baDecrypt = AsymmetricCipher::decrypt(AsymmetricCipherTest::privKey, baEncrypt, AsymmetricCipher::SSLV23);

    ASSERT_NE(AsymmetricCipherTest::baData, baEncrypt);
    ASSERT_EQ(AsymmetricCipherTest::baData, baDecrypt);
}

/**
 * @brief Tests Asymmetric Cipher with no padding
 */
TEST_F(AsymmetricCipherTest, EncryptNO_PADDING) {
    ByteArray baEncrypt = AsymmetricCipher::encrypt(AsymmetricCipherTest::pubKey, AsymmetricCipherTest::baDataNP, AsymmetricCipher::NO_PADDING);
    ByteArray baDecrypt = AsymmetricCipher::decrypt(AsymmetricCipherTest::privKey, baEncrypt, AsymmetricCipher::NO_PADDING);

    ASSERT_NE(AsymmetricCipherTest::baDataNP, baEncrypt);
    ASSERT_EQ(AsymmetricCipherTest::baDataNP, baDecrypt);
}

/**
 * @brief Tests Asymmetric Cipher with padding PKCS1
 */
TEST_F(AsymmetricCipherTest, EncryptStringPKCS1) {
    ByteArray baEncrypt = AsymmetricCipher::encrypt(AsymmetricCipherTest::pubKey, AsymmetricCipherTest::stringASCII, AsymmetricCipher::PKCS1);
    ByteArray baDecrypt = AsymmetricCipher::decrypt(AsymmetricCipherTest::privKey, baEncrypt, AsymmetricCipher::PKCS1);

    ASSERT_NE(AsymmetricCipherTest::baData, baEncrypt);
    ASSERT_EQ(AsymmetricCipherTest::baData, baDecrypt);
}


TEST_F(AsymmetricCipherTest, EncryptStringPKCS1_OAEP) {
    ByteArray baEncrypt = AsymmetricCipher::encrypt(AsymmetricCipherTest::pubKey, AsymmetricCipherTest::stringASCII, AsymmetricCipher::PKCS1_OAEP);
    ByteArray baDecrypt = AsymmetricCipher::decrypt(AsymmetricCipherTest::privKey, baEncrypt, AsymmetricCipher::PKCS1_OAEP);

    ASSERT_NE(AsymmetricCipherTest::baData, baEncrypt);
    ASSERT_EQ(AsymmetricCipherTest::baData, baDecrypt);
}

/**
 * @brief Tests Asymmetric Cipher with padding SSLV23
 */
TEST_F(AsymmetricCipherTest, EncryptStringSSLV23) {
    ByteArray baEncrypt = AsymmetricCipher::encrypt(AsymmetricCipherTest::pubKey, AsymmetricCipherTest::stringASCII, AsymmetricCipher::SSLV23);
    ByteArray baDecrypt = AsymmetricCipher::decrypt(AsymmetricCipherTest::privKey, baEncrypt, AsymmetricCipher::SSLV23);

    ASSERT_NE(AsymmetricCipherTest::baData, baEncrypt);
    ASSERT_EQ(AsymmetricCipherTest::baData, baDecrypt);
}

/**
 * @brief Tests Asymmetric Cipher with no padding
 */
TEST_F(AsymmetricCipherTest, EncryptStringNO_PADDING) {
    ByteArray baEncrypt = AsymmetricCipher::encrypt(AsymmetricCipherTest::pubKey, AsymmetricCipherTest::stringNP, AsymmetricCipher::NO_PADDING);
    ByteArray baDecrypt = AsymmetricCipher::decrypt(AsymmetricCipherTest::privKey, baEncrypt, AsymmetricCipher::NO_PADDING);

    ASSERT_NE(AsymmetricCipherTest::baDataNP, baEncrypt);
    ASSERT_EQ(AsymmetricCipherTest::baDataNP, baDecrypt);
}