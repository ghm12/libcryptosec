#include <libcryptosec/MessageDigest.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe MessageDigest
 */
class MessageDigestTest : public ::testing::Test {

protected:
    virtual void SetUp() {
        md = new MessageDigest();
        ba = new ByteArray();
    }

    virtual void TearDown() {
        free(md);
        free(ba);
    }

    void testDigest(MessageDigest::Algorithm algorithm) {
        md->init(algorithm);
        md->update(data);
        *ba = md->doFinal();
    }

    void testDigestByteArray(MessageDigest::Algorithm algorithm, ByteArray byteArray) {
        md->init(algorithm);
        md->update(byteArray);
        *ba = md->doFinal();
    }

    void testUpdateString(MessageDigest::Algorithm algorithm, std::string content) {
        md->init(algorithm);
        md->update(data);
        md->update(content);
        *ba = md->doFinal();
    }

    void testUpdateByteArray(MessageDigest::Algorithm algorithm, ByteArray byteArray) {
        md->init(algorithm);
        md->update(data);
        md->update(byteArray);
        *ba = md->doFinal();
    }

    void testDoFinalString(MessageDigest::Algorithm algorithm, std::string content) {
        md->init(algorithm);
        md->update(data);
        *ba = md->doFinal(content);
    }

    void testDoFinalByteArray(MessageDigest::Algorithm algorithm, ByteArray byteArray) {
        md->init(algorithm);
        md->update(data);
        *ba = md->doFinal(byteArray);
    }

    MessageDigest *md;
    ByteArray *ba;
    static std::string data;
    static std::string diffData;
    static std::string digestMD4;
    static std::string digestMD5;
    static std::string digestRIPEMD160;
    static std::string digestSHA;
    static std::string digestSHA1;
    static std::string digestSHA224;
    static std::string digestSHA256;
    static std::string digestSHA512;
    static std::string digestUpdate;

};

/*
 * Initialization of variables used in the tests
 */
std::string MessageDigestTest::data = "Forward and back, and then forward and back";
std::string MessageDigestTest::diffData = " and then go forward and back and put one foot forward";
std::string MessageDigestTest::digestMD4 = "C05829701FE5918467D8D0166BAA6766";
std::string MessageDigestTest::digestMD5 = "ADA35AF7AC7C12C38E9DEB7CEC150577";
std::string MessageDigestTest::digestRIPEMD160 = "38D5101C300848D33C54DCEA8ADEC5F1EE9EFD68";
std::string MessageDigestTest::digestSHA1 = "A8C8D02AEC5176C35FD33D06ACD240DD7D770F46";
std::string MessageDigestTest::digestSHA224 = "7DAADCD21C751B5A238D279678FD6CBD4B2A9E0218588873FF5EBC90";
std::string MessageDigestTest::digestSHA256 = "7D3E352CA398B3B9E756B40D39104B055C9F5CAE53E7F173C48FC31AB5461453";
std::string MessageDigestTest::digestSHA512 = "1975D01DA9077C7271833747AF633250000D71D46E4287BD903E77198662CAF35BA6B0837309BD47338F4E94DA76B1CB1E86F2385E66E37669C9845A5665C60E";
std::string MessageDigestTest::digestUpdate = "14F515D0DD290CAE5608698CAD05D4F409D13ECABC7D94731DB8CCD30ABE9E4E";

/**
 * @brief Tests MessageDigest with MD4 Algorithm
 */
TEST_F(MessageDigestTest, MD4) {
    testDigest(MessageDigest::MD4);
    ASSERT_EQ(ba->toHex(), MessageDigestTest::digestMD4);
}

/**
 * @brief Tests MessageDigest with MD5 Algorithm
 */
TEST_F(MessageDigestTest, MD5) {
    testDigest(MessageDigest::MD5);
    ASSERT_EQ(ba->toHex(), MessageDigestTest::digestMD5);
}

/**
 * @brief Tests MessageDigest with RIPEMD160 Algorithm
 */
TEST_F(MessageDigestTest, RIPEMD160) {
    testDigest(MessageDigest::RIPEMD160);
    ASSERT_EQ(ba->toHex(), MessageDigestTest::digestRIPEMD160);
}

/**
 * @brief Tests MessageDigest with SHA1 Algorithm
 */
TEST_F(MessageDigestTest, SHA1) {
    testDigest(MessageDigest::SHA1);
    ASSERT_EQ(ba->toHex(), MessageDigestTest::digestSHA1);
}

/**
 * @brief Tests MessageDigest with SHA224 Algorithm
 */
TEST_F(MessageDigestTest, SHA224) {
    testDigest(MessageDigest::SHA224);
    ASSERT_EQ(ba->toHex(), MessageDigestTest::digestSHA224);
}

/**
 * @brief Tests MessageDigest with SHA256 Algorithm
 */
TEST_F(MessageDigestTest, SHA256) {
    testDigest(MessageDigest::SHA256);
    ASSERT_EQ(ba->toHex(), MessageDigestTest::digestSHA256);
}

/**
 * @brief Tests MessageDigest with SHA512 Algorithm
 */
TEST_F(MessageDigestTest, SHA512) {
    testDigest(MessageDigest::SHA512);
    ASSERT_EQ(ba->toHex(), MessageDigestTest::digestSHA512);
}

/**
 * @brief Tests MessageDigest with ByteArray as content
 */
TEST_F(MessageDigestTest, DigestByteArray) {
    ByteArray byteArray(MessageDigestTest::data);

    testDigestByteArray(MessageDigest::SHA256, byteArray);
    ASSERT_EQ(ba->toHex(), MessageDigestTest::digestSHA256);
}

/**
 * @brief Tests MessageDigest Update with a string
 */
TEST_F(MessageDigestTest, UpdateString) {
    testUpdateString(MessageDigest::SHA256, MessageDigestTest::diffData);
    ASSERT_EQ(ba->toHex(), MessageDigestTest::digestUpdate);
}

/**
 * @brief Tests MessageDigest Update with a ByteArray
 */
TEST_F(MessageDigestTest, UpdateByteArray) {
    ByteArray byteArray(MessageDigestTest::diffData);

    testUpdateByteArray(MessageDigest::SHA256, byteArray);
    ASSERT_EQ(ba->toHex(), MessageDigestTest::digestUpdate);
}

/**
 * @brief Tests MessageDigest doFinal with a string as content
 */
TEST_F(MessageDigestTest, DoFinalString) {
    testDoFinalString(MessageDigest::SHA256, MessageDigestTest::diffData);
    ASSERT_EQ(ba->toHex(), MessageDigestTest::digestUpdate);
}

/**
 * @brief Tests MessageDigest doFinal with a ByteArray as content
 */
TEST_F(MessageDigestTest, DoFinalByteArray) {
    ByteArray byteArray(MessageDigestTest::diffData);

    testDoFinalByteArray(MessageDigest::SHA256, byteArray);
    ASSERT_EQ(ba->toHex(), MessageDigestTest::digestUpdate);
}