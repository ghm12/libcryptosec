#include <libcryptosec/certificate/SubjectKeyIdentifierExtension.h>
#include <libcryptosec/certificate/KeyUsageExtension.h>
#include <libcryptosec/certificate/BasicConstraintsExtension.h>
#include <libcryptosec/certificate/CRLNumberExtension.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe Extension e seus derivados
 */
class ExtensionsTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    void generalTests(Extension ext, Extension::Name name) {
        ObjectIdentifier oid;

        ASSERT_NO_THROW(
            oid = ext.getObjectIdentifier();
        );

        ASSERT_EQ(ext.getTypeName(), name);
        ASSERT_EQ(ext.getName(), oid.getName());

        ASSERT_FALSE(ext.isCritical());
        ext.setCritical(true);
        ASSERT_TRUE(ext.isCritical());
    }

    static std::vector<bool> keyUsageValues;
    static long basicConstraintsPathLen;
    static unsigned long crlSerialNumber;
    static unsigned long crlSerialNew;
    static char* keyIdentifierValue;
};

/*
 * Initialization of variables used in the tests
 */

long ExtensionsTest::basicConstraintsPathLen = 30;
unsigned long ExtensionsTest::crlSerialNumber = 1234567890;
unsigned long ExtensionsTest::crlSerialNew = 9876543210;
char* ExtensionsTest::keyIdentifierValue = (char *) "B132247BE75A265B9CB80BBD3474CBB7A4FA40CC";

/**
 * @brief Tests SubjectKeyIdentifierExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, SubjectKeyIdentifier) {
    SubjectKeyIdentifierExtension ext;
    X509_EXTENSION *extX509;

    ByteArray ba(ExtensionsTest::keyIdentifierValue);
    ByteArray value;

    ext.setKeyIdentifier(ba);
    value = ext.getKeyIdentifier();
    extX509 = ext.getX509Extension();
    SubjectKeyIdentifierExtension fromX509(extX509);

    generalTests(ext, Extension::SUBJECT_KEY_IDENTIFIER);

    ASSERT_EQ(value.toString(), ExtensionsTest::keyIdentifierValue);
    ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());
}

/**
 * @brief Tests KeyUsageExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, KeyUsage) {
    KeyUsageExtension ext;
    X509_EXTENSION *extX509;

    ext.setUsage(KeyUsageExtension::DIGITAL_SIGNATURE, true);
    ext.setUsage(KeyUsageExtension::ENCIPHER_ONLY, true);

    extX509 = ext.getX509Extension();
    KeyUsageExtension fromX509(extX509);

    generalTests(ext, Extension::KEY_USAGE);

    ASSERT_TRUE(ext.getUsage(KeyUsageExtension::DIGITAL_SIGNATURE));
    ASSERT_TRUE(ext.getUsage(KeyUsageExtension::ENCIPHER_ONLY));

    ASSERT_FALSE(ext.getUsage(KeyUsageExtension::KEY_ENCIPHERMENT));
    ASSERT_FALSE(ext.getUsage(KeyUsageExtension::CRL_SIGN));

    ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());
}

/**
 * @brief Tests BasicConstraintsExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, BasicConstraints) {
    BasicConstraintsExtension ext;
    X509_EXTENSION *extX509;

    ext.setCa(true);
    ext.setPathLen(ExtensionsTest::basicConstraintsPathLen);

    extX509 = ext.getX509Extension();
    BasicConstraintsExtension fromX509(extX509);

    generalTests(ext, Extension::BASIC_CONSTRAINTS);

    ASSERT_EQ(ext.getPathLen(), ExtensionsTest::basicConstraintsPathLen);
    ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());
    
    ASSERT_TRUE(ext.isCa());
    ext.setCa(false);
    ASSERT_FALSE(ext.isCa());
}

/**
 * @brief Tests CRLNumberExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, CRLNumber) {
    CRLNumberExtension ext(ExtensionsTest::crlSerialNumber);
    X509_EXTENSION *extX509;

    /* TODO in libcryptosec
    extX509 = ext.getX509Extension();
    CRLNumberExtension fromX509(extX509);

    generalTests(ext, Extension::BASIC_CONSTRAINTS);

    ASSERT_EQ(ext.getSerial(), ExtensionsTest::crlSerialNumber);
    ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());

    ext.setSerial(ExtensionsTest::crlSerialNew);
    ASSERT_EQ(ext.getSerial(), ExtensionsTest::crlSerialNew); */
}


