#include <libcryptosec/Base64.h>

#include <isstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe Base64.
 */
class Base64Test : public ::testing::Test {

protected:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

    static std::string stringASCII;
    static std::string stringHex;
    static std::string stringB64;
    static std::istringstream isstreamB64;
    static const char compChar;
    static unsigned int size;

};

/*
 * Initialization of variables used in the tests
 */
std::string Base64Test::stringASCII = "Still waiting for Silksong release...";
std::string Base64Test::stringHex = "5374696C6C2077616974696E6720666F722053696C6B736F6E672072656C656173652E2E2E";
std::string Base64Test::stringB64 = "U3RpbGwgd2FpdGluZyBmb3IgU2lsa3NvbmcgcmVsZWFzZS4uLg==";
const char Base64Test::compChar = 'i';
unsigned int Base64Test::size = 37;

/**
 * @brief Tests Base64Decode and the functionalities of returned ByteArray
 */
TEST_F(Base64Test, Base64Decode) {
    ByteArray ba = Base64::decode(Base64Test::stringB64);
    ByteArray baCopy = ba;
    std::istringstream *iss = ba.toStream();

    std::string issValue = iss->str();
    char at = ba.at(10);

    ASSERT_EQ(at, Base64Test::compChar);
    ASSERT_EQ(ba.toString(), Base64Test::stringASCII);
    ASSERT_EQ(ba.toHex(), Base64Test::stringHex);
    ASSERT_EQ(ba.size(), Base64Test::size);

    ASSERT_EQ(baCopy, ba);
    ASSERT_EQ(issValue, Base64Test::stringASCII);
    ASSERT_EQ(ba[10], Base64Test::compChar);

    ASSERT_TRUE(ba == baCopy);
    ASSERT_FALSE(ba != baCopy);
}

/**
 * @brief Tests Decoding and then Encoding
 */
TEST_F(Base64Test, Base64Encode) {
    ByteArray ba = Base64::decode(Base64Test::stringB64);
    std::string encode = Base64::encode(ba);

    ASSERT_EQ(encode, Base64Test::stringB64);
}
