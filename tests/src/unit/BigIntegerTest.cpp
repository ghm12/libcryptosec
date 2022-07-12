#include <libcryptosec/BigInteger.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe BigInteger.
 */
class BigIntegerTest : public ::testing::Test {

protected:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

    static long longValue;
    static long longValueNeg;
    static int size;
    static int sizeNeg;
    static std::string decValue;
    static std::string decValueNeg;
    static std::string hexValue;
    static std::string hexValueNeg;
};

/*
 * Initialization of variables used in the tests
 */
long BigIntegerTest::longValue = 1234567890987654321;
long BigIntegerTest::longValueNeg = -1234567890987654321;
int BigIntegerTest::size = 61;
int BigIntegerTest::sizeNeg = 61;
std::string BigIntegerTest::decValue = "1234567890987654321";
std::string BigIntegerTest::decValueNeg = "-1234567890987654321";
std::string BigIntegerTest::hexValue = "112210F4B16C1CB1";
std::string BigIntegerTest::hexValueNeg = "-112210F4B16C1CB1";

/**
 * @brief Tests if Default Constructor creates a BigInteger with value zero
 */
TEST_F(BigIntegerTest, DefaultConstructor) {
    BigInteger bi;

    ASSERT_EQ(0, bi.getValue());
    ASSERT_EQ(0, bi.size());

    ASSERT_EQ("0", bi.toDec());
    ASSERT_EQ("0", bi.toHex());

    ASSERT_FALSE(bi.isNegative());
}

/**
 * @brief Tests if Constructor with a long parameter creates a BigInteger with proper value
 */
TEST_F(BigIntegerTest, LongConstructor) {
    BigInteger bi(BigIntegerTest::longValue);

    ASSERT_EQ(BigIntegerTest::longValue, bi.getValue());
    ASSERT_EQ(BigIntegerTest::size, bi.size());

    ASSERT_EQ(BigIntegerTest::decValue, bi.toDec());
    ASSERT_EQ(BigIntegerTest::hexValue, bi.toHex());

    ASSERT_FALSE(bi.isNegative());
}

/**
 * @brief Tests if Constructor with a negative long parameter creates a BigInteger with proper value
 */
TEST_F(BigIntegerTest, LongConstructorNeg) {
    BigInteger bi(BigIntegerTest::longValueNeg);

    ASSERT_EQ(BigIntegerTest::longValueNeg, bi.getValue());
    ASSERT_EQ(BigIntegerTest::sizeNeg, bi.size());

    ASSERT_EQ(BigIntegerTest::decValueNeg, bi.toDec());
    ASSERT_EQ(BigIntegerTest::hexValueNeg, bi.toHex());

    ASSERT_TRUE(bi.isNegative());
}

/**
 * @brief Tests if Constructor with a decimal parameter creates a BigInteger with proper value
 */
TEST_F(BigIntegerTest, DecConstructor) {
    BigInteger bi(BigIntegerTest::decValue);

    ASSERT_EQ(BigIntegerTest::longValue, bi.getValue());
    ASSERT_EQ(BigIntegerTest::size, bi.size());

    ASSERT_EQ(BigIntegerTest::decValue, bi.toDec());
    ASSERT_EQ(BigIntegerTest::hexValue, bi.toHex());

    ASSERT_FALSE(bi.isNegative());
}

/**
 * @brief Tests if Constructor with a negative decimal parameter creates a BigInteger with proper value
 */
TEST_F(BigIntegerTest, DecConstructorNeg) {
    BigInteger bi(BigIntegerTest::decValueNeg);

    ASSERT_EQ(BigIntegerTest::longValueNeg, bi.getValue());
    ASSERT_EQ(BigIntegerTest::sizeNeg, bi.size());

    ASSERT_EQ(BigIntegerTest::decValueNeg, bi.toDec());
    ASSERT_EQ(BigIntegerTest::hexValueNeg, bi.toHex());

    ASSERT_TRUE(bi.isNegative());
}

/**
 * @brief Tests if setValue works properly with long, decimal and hexadecimal values
 */
TEST_F(BigIntegerTest, SetValue) {
    BigInteger bi;
    ASSERT_EQ(0, bi.getValue());
    ASSERT_EQ(0, bi.size());

    bi.setValue(BigIntegerTest::longValue);
    ASSERT_EQ(BigIntegerTest::longValue, bi.getValue());
    ASSERT_EQ(BigIntegerTest::decValue, bi.toDec());
    ASSERT_EQ(BigIntegerTest::hexValue, bi.toHex());
    ASSERT_EQ(BigIntegerTest::size, bi.size());
    ASSERT_FALSE(bi.isNegative());

    BigInteger biDec;
    ASSERT_EQ(0, biDec.getValue());
    ASSERT_EQ(0, biDec.size());

    biDec.setDecValue(BigIntegerTest::decValue);
    ASSERT_EQ(BigIntegerTest::longValue, biDec.getValue());
    ASSERT_EQ(BigIntegerTest::decValue, biDec.toDec());
    ASSERT_EQ(BigIntegerTest::hexValue, biDec.toHex());
    ASSERT_EQ(BigIntegerTest::size, biDec.size());
    ASSERT_FALSE(bi.isNegative());

    BigInteger biHex;
    ASSERT_EQ(0, biHex.getValue());
    ASSERT_EQ(0, biHex.size());

    biHex.setHexValue(BigIntegerTest::hexValue);
    ASSERT_EQ(BigIntegerTest::longValue, biHex.getValue());
    ASSERT_EQ(BigIntegerTest::decValue, biHex.toDec());
    ASSERT_EQ(BigIntegerTest::hexValue, biHex.toHex());
    ASSERT_EQ(BigIntegerTest::size, biHex.size());
    ASSERT_FALSE(bi.isNegative());
}

/**
 * @brief Tests if setValue works properly with negative long, decimal and hexadecimal values
 */
TEST_F(BigIntegerTest, SetValueNeg) {
    BigInteger bi;
    ASSERT_EQ(0, bi.getValue());
    ASSERT_EQ(0, bi.size());

    bi.setValue(BigIntegerTest::longValueNeg);
    ASSERT_EQ(BigIntegerTest::longValueNeg, bi.getValue());
    ASSERT_EQ(BigIntegerTest::decValueNeg, bi.toDec());
    ASSERT_EQ(BigIntegerTest::hexValueNeg, bi.toHex());
    ASSERT_EQ(BigIntegerTest::sizeNeg, bi.size());
    ASSERT_TRUE(bi.isNegative());

    BigInteger biDec;
    ASSERT_EQ(0, biDec.getValue());
    ASSERT_EQ(0, biDec.size());

    biDec.setDecValue(BigIntegerTest::decValueNeg);
    ASSERT_EQ(BigIntegerTest::longValueNeg, biDec.getValue());
    ASSERT_EQ(BigIntegerTest::decValueNeg, biDec.toDec());
    ASSERT_EQ(BigIntegerTest::hexValueNeg, biDec.toHex());
    ASSERT_EQ(BigIntegerTest::sizeNeg, biDec.size());
    ASSERT_TRUE(bi.isNegative());

    BigInteger biHex;
    ASSERT_EQ(0, biHex.getValue());
    ASSERT_EQ(0, biHex.size());

    biHex.setHexValue(BigIntegerTest::hexValueNeg);
    ASSERT_EQ(BigIntegerTest::longValueNeg, biHex.getValue());
    ASSERT_EQ(BigIntegerTest::decValueNeg, biHex.toDec());
    ASSERT_EQ(BigIntegerTest::hexValueNeg, biHex.toHex());
    ASSERT_EQ(BigIntegerTest::sizeNeg, biHex.size());
    ASSERT_TRUE(bi.isNegative());
}

/**
 * @brief Tests if setNegative properly sets the value to negative
 */
TEST_F(BigIntegerTest, SetNegative) {
    BigInteger bi;
    ASSERT_EQ(0, bi.getValue());
    ASSERT_EQ(0, bi.size());

    bi.setValue(BigIntegerTest::longValue);
    ASSERT_FALSE(bi.isNegative());

    bi.setNegative();
    ASSERT_EQ(BigIntegerTest::longValueNeg, bi.getValue());
    ASSERT_EQ(BigIntegerTest::decValueNeg, bi.toDec());
    ASSERT_EQ(BigIntegerTest::hexValueNeg, bi.toHex());
    ASSERT_EQ(BigIntegerTest::sizeNeg, bi.size());
    ASSERT_TRUE(bi.isNegative());

    bi.setNegative(false);
    ASSERT_EQ(BigIntegerTest::longValue, bi.getValue());
    ASSERT_EQ(BigIntegerTest::decValue, bi.toDec());
    ASSERT_EQ(BigIntegerTest::hexValue, bi.toHex());
    ASSERT_EQ(BigIntegerTest::size, bi.size());
    ASSERT_FALSE(bi.isNegative());
}

/**
 * @brief Tests if setRandValue creates a value with the specified number of bits
 */
TEST_F(BigIntegerTest, SetRandValue) {
    BigInteger bi;
    ASSERT_EQ(0, bi.getValue());
    ASSERT_EQ(0, bi.size());

    bi.setRandValue(16);
    ASSERT_FALSE(bi.size() > 16);
    ASSERT_EQ(4, bi.toHex().length());

    bi.setRandValue(32);
    ASSERT_FALSE(bi.size() > 32);
    ASSERT_EQ(8, bi.toHex().length());

    bi.setRandValue(64);
    ASSERT_FALSE(bi.size() > 64);
    ASSERT_EQ(16, bi.toHex().length());
}

/**
 * @brief Tests if the ByteArray with mpi codification can be used to create a BigInteger of same value
 */
TEST_F(BigIntegerTest, getBinValue) {
    BigInteger bi;
    ASSERT_EQ(0, bi.getValue());
    ASSERT_EQ(0, bi.size());

    bi.setValue(BigIntegerTest::longValue);
    ByteArray *ba = bi.getBinValue();
    BigInteger biTest(*ba);
    ASSERT_EQ(bi.getValue(), biTest.getValue());

    bi.setValue(BigIntegerTest::longValueNeg);
    ba = bi.getBinValue();
    BigInteger biTestNeg(*ba);
    ASSERT_EQ(bi.getValue(), biTestNeg.getValue());
}

/**
 * @brief Tests if the ASN1_INTEGER returned has the correct value
 */
TEST_F(BigIntegerTest, GetASN1Value) {
    int64_t *value = new int64_t;
    BigInteger bi;
    ASSERT_EQ(0, bi.getValue());
    ASSERT_EQ(0, bi.size());

    bi.setValue(BigIntegerTest::longValue);
    ASN1_INTEGER *asn1Int = bi.getASN1Value();
    ASN1_INTEGER_get_int64(value, asn1Int);

    ASSERT_EQ(BigIntegerTest::longValue, *value);
}

/**
 * @brief Tests if the BIGNUM returned has the correct value
 */
TEST_F(BigIntegerTest, GetBIGNUM) {
    char *chr = new char;
    BigInteger bi;
    ASSERT_EQ(0, bi.getValue());
    ASSERT_EQ(0, bi.size());

    bi.setValue(BigIntegerTest::longValue);
    const BIGNUM *bn = bi.getBIGNUM();
    chr = BN_bn2dec(bn);

    ASSERT_EQ(BigIntegerTest::decValue, chr);
}