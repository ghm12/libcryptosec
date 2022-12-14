#include <libcryptosec/SymmetricKeyGenerator.h>

#include <sstream>
#include <gtest/gtest.h>

/**
 * @brief Testes unitários da classe SymmetricKey
 */
class SymmetricKeyTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    void generateKey(SymmetricKey::Algorithm algorithm) {
        key = SymmetricKeyGenerator::generateKey(algorithm);
    }

    void checkKey(SymmetricKey::Algorithm algorithm) {
        ASSERT_EQ(key->getAlgorithm(), algorithm);
        ASSERT_TRUE(key->getEncoded().size() > 0);
        ASSERT_TRUE(key->getSize() == EVP_MAX_KEY_LENGTH);
    }

    void checkAssignKey(SymmetricKey *simKey, SymmetricKey::Algorithm algorithm) {
        ASSERT_EQ(simKey->getAlgorithm(), algorithm);
        ASSERT_TRUE(simKey->getEncoded().size() > 0);
        ASSERT_TRUE(simKey->getSize() == EVP_MAX_KEY_LENGTH);
    }

    void generateKey(SymmetricKey::Algorithm algorithm, int size) {
        key = SymmetricKeyGenerator::generateKey(algorithm, size);
    }

    void checkKey(SymmetricKey::Algorithm algorithm, int size) {
        ASSERT_EQ(key->getAlgorithm(), algorithm);
        ASSERT_TRUE(key->getEncoded().size() > 0);
        ASSERT_TRUE(key->getSize() == size);
    }

    void recreateKey() {
        ByteArray ba;

        ba = key->getEncoded();
        key = new SymmetricKey(ba, key->getAlgorithm());
    }

    SymmetricKey *key;
    static int size;

    static std::string aes128Name;
    static std::string aes192Name;
    static std::string aes256Name;
    static std::string desName;
    static std::string desEdeName;
    static std::string desEde3Name;
    static std::string rc2Name;
    static std::string rc4Name;
};

/*
 * Initialization of variables used in the tests
 */
int SymmetricKeyTest::size = 128;

std::string SymmetricKeyTest::aes128Name = "aes-128";
std::string SymmetricKeyTest::aes192Name = "aes-192";
std::string SymmetricKeyTest::aes256Name = "aes-256";
std::string SymmetricKeyTest::desName = "des";
std::string SymmetricKeyTest::desEdeName = "des-ede";
std::string SymmetricKeyTest::desEde3Name = "des-ede3";
std::string SymmetricKeyTest::rc2Name = "rc2";
std::string SymmetricKeyTest::rc4Name = "rc4";

/**
 * @brief Tests creation of a SymmetricKey with AES_128 Algorithm
 */
TEST_F(SymmetricKeyTest, AES_128) {
    generateKey(SymmetricKey::AES_128);
    checkKey(SymmetricKey::AES_128);
}

/**
 * @brief Tests creation of a SymmetricKey with AES_128 Algorithm with a specific key size
 */
TEST_F(SymmetricKeyTest, AES_128Size) {
    generateKey(SymmetricKey::AES_128, size);
    checkKey(SymmetricKey::AES_128, size);
}

/**
 * @brief Tests creation of a SymmetricKey with AES_128 Algorithm from a ByteArray containing the Encoded Key
 */
TEST_F(SymmetricKeyTest, AES_128FromByteArray) {
    generateKey(SymmetricKey::AES_128, size);
    recreateKey();
    checkKey(SymmetricKey::AES_128, size);
}

/**
 * @brief Tests creation of a SymmetricKey with AES_192 Algorithm
 */
TEST_F(SymmetricKeyTest, AES_192) {
    generateKey(SymmetricKey::AES_192);
    checkKey(SymmetricKey::AES_192);
}

/**
 * @brief Tests creation of a SymmetricKey with AES_192 Algorithm with a specific key size
 */
TEST_F(SymmetricKeyTest, AES_192Size) {
    generateKey(SymmetricKey::AES_192, size);
    checkKey(SymmetricKey::AES_192, size);
}

/**
 * @brief Tests creation of a SymmetricKey with AES_192 Algorithm from a ByteArray containing the Encoded Key
 */
TEST_F(SymmetricKeyTest, AES_192FromByteArray) {
    generateKey(SymmetricKey::AES_192, size);
    recreateKey();
    checkKey(SymmetricKey::AES_192, size);
}

/**
 * @brief Tests creation of a SymmetricKey with AES_256 Algorithm
 */
TEST_F(SymmetricKeyTest, AES_256) {
    generateKey(SymmetricKey::AES_256);
    checkKey(SymmetricKey::AES_256);
}

/**
 * @brief Tests creation of a SymmetricKey with AES_256 Algorithm with a specific key size
 */
TEST_F(SymmetricKeyTest, AES_256Size) {
    generateKey(SymmetricKey::AES_256, size);
    checkKey(SymmetricKey::AES_256, size);
}

/**
 * @brief Tests creation of a SymmetricKey with AES_256 Algorithm from a ByteArray containing the Encoded Key
 */
TEST_F(SymmetricKeyTest, AES_256FromByteArray) {
    generateKey(SymmetricKey::AES_256, size);
    recreateKey();
    checkKey(SymmetricKey::AES_256, size);
}

/**
 * @brief Tests creation of a SymmetricKey with DES Algorithm
 */
TEST_F(SymmetricKeyTest, DES) {
    generateKey(SymmetricKey::DES);
    checkKey(SymmetricKey::DES);
}

/**
 * @brief Tests creation of a SymmetricKey with DES Algorithm with a specific key size
 */
TEST_F(SymmetricKeyTest, DESSize) {
    generateKey(SymmetricKey::DES, size);
    checkKey(SymmetricKey::DES, size);
}

/**
 * @brief Tests creation of a SymmetricKey with DES Algorithm from a ByteArray containing the Encoded Key
 */
TEST_F(SymmetricKeyTest, DESFromByteArray) {
    generateKey(SymmetricKey::DES, size);
    recreateKey();
    checkKey(SymmetricKey::DES, size);
}

/**
 * @brief Tests creation of a SymmetricKey with DES_EDE Algorithm
 */
TEST_F(SymmetricKeyTest, DES_EDE) {
    generateKey(SymmetricKey::DES_EDE);
    checkKey(SymmetricKey::DES_EDE);
}

/**
 * @brief Tests creation of a SymmetricKey with DES_EDE Algorithm with a specific key size
 */
TEST_F(SymmetricKeyTest, DES_EDESize) {
    generateKey(SymmetricKey::DES_EDE, size);
    checkKey(SymmetricKey::DES_EDE, size);
}

/**
 * @brief Tests creation of a SymmetricKey with DES_EDE Algorithm from a ByteArray containing the Encoded Key
 */
TEST_F(SymmetricKeyTest, DES_EDEFromByteArray) {
    generateKey(SymmetricKey::DES_EDE, size);
    recreateKey();
    checkKey(SymmetricKey::DES_EDE, size);
}

/**
 * @brief Tests creation of a SymmetricKey with DES_EDE3 Algorithm
 */
TEST_F(SymmetricKeyTest, DES_EDE3) {
    generateKey(SymmetricKey::DES_EDE3);
    checkKey(SymmetricKey::DES_EDE3);
}

/**
 * @brief Tests creation of a SymmetricKey with DES_EDE3 Algorithm with a specific key size
 */
TEST_F(SymmetricKeyTest, DES_EDE3Size) {
    generateKey(SymmetricKey::DES_EDE3, size);
    checkKey(SymmetricKey::DES_EDE3, size);
}

/**
 * @brief Tests creation of a SymmetricKey with DES_EDE3 Algorithm from a ByteArray containing the Encoded Key
 */
TEST_F(SymmetricKeyTest, DES_EDE3FromByteArray) {
    generateKey(SymmetricKey::DES_EDE3, size);
    recreateKey();
    checkKey(SymmetricKey::DES_EDE3, size);
}

/**
 * @brief Tests creation of a SymmetricKey with RC2 Algorithm
 */
TEST_F(SymmetricKeyTest, RC2) {
    generateKey(SymmetricKey::RC2);
    checkKey(SymmetricKey::RC2);
}

/**
 * @brief Tests creation of a SymmetricKey with RC2 Algorithm with a specific key size
 */
TEST_F(SymmetricKeyTest, RC2Size) {
    generateKey(SymmetricKey::RC2, size);
    checkKey(SymmetricKey::RC2, size);
}

/**
 * @brief Tests creation of a SymmetricKey with RC2 Algorithm from a ByteArray containing the Encoded Key
 */
TEST_F(SymmetricKeyTest, RC2FromByteArray) {
    generateKey(SymmetricKey::RC2, size);
    recreateKey();
    checkKey(SymmetricKey::RC2, size);
}

/**
 * @brief Tests creation of a SymmetricKey with RC4 Algorithm
 */
TEST_F(SymmetricKeyTest, RC4) {
    generateKey(SymmetricKey::RC4);
    checkKey(SymmetricKey::RC4);
}

/**
 * @brief Tests creation of a SymmetricKey with RC4 Algorithm with a specific key size
 */
TEST_F(SymmetricKeyTest, RC4Size) {
    generateKey(SymmetricKey::RC4, size);
    checkKey(SymmetricKey::RC4, size);
}

/**
 * @brief Tests creation of a SymmetricKey with RC4 Algorithm from a ByteArray containing the Encoded Key
 */
TEST_F(SymmetricKeyTest, RC4FromByteArray) {
    generateKey(SymmetricKey::RC4, size);
    recreateKey();
    checkKey(SymmetricKey::RC4, size);
}

/**
 * @brief Tests assignment of one SymmetricKey object to another
 */
TEST_F(SymmetricKeyTest, OperatorAssign) {
    ByteArray ba;
    generateKey(SymmetricKey::AES_192);

    ba = key->getEncoded();
    SymmetricKey simKey(ba, key->getAlgorithm());
    SymmetricKey simKeyTwo = simKey;

    checkAssignKey(&simKeyTwo, SymmetricKey::AES_192);
}

/**
 * @brief Tests creation of a SymmetricKey from another SymmetricKey object
 */
TEST_F(SymmetricKeyTest, FromSymmetricKey) {
    ByteArray ba;
    generateKey(SymmetricKey::AES_192);

    ba = key->getEncoded();
    SymmetricKey simKey(ba, key->getAlgorithm());
    SymmetricKey simKeyTwo(simKey);

    checkAssignKey(&simKeyTwo, SymmetricKey::AES_192);
}

/**
 * @brief Tests getting the Algorithm Name
 */
TEST_F(SymmetricKeyTest, GetAlgorithmName) {
    ASSERT_EQ(SymmetricKey::getAlgorithmName(SymmetricKey::AES_128), aes128Name);
    ASSERT_EQ(SymmetricKey::getAlgorithmName(SymmetricKey::AES_192), aes192Name);
    ASSERT_EQ(SymmetricKey::getAlgorithmName(SymmetricKey::AES_256), aes256Name);
    ASSERT_EQ(SymmetricKey::getAlgorithmName(SymmetricKey::DES), desName);
    ASSERT_EQ(SymmetricKey::getAlgorithmName(SymmetricKey::DES_EDE), desEdeName);
    ASSERT_EQ(SymmetricKey::getAlgorithmName(SymmetricKey::DES_EDE3), desEde3Name);
    ASSERT_EQ(SymmetricKey::getAlgorithmName(SymmetricKey::RC2), rc2Name);
    ASSERT_EQ(SymmetricKey::getAlgorithmName(SymmetricKey::RC4), rc4Name);
}