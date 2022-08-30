#include <libcryptosec/certificate/AuthorityKeyIdentifierExtension.h>
#include <libcryptosec/certificate/SubjectKeyIdentifierExtension.h>
#include <libcryptosec/certificate/KeyUsageExtension.h>
#include <libcryptosec/certificate/ExtendedKeyUsageExtension.h>
#include <libcryptosec/certificate/IssuerAlternativeNameExtension.h>
#include <libcryptosec/certificate/SubjectAlternativeNameExtension.h>
#include <libcryptosec/certificate/BasicConstraintsExtension.h>
#include <libcryptosec/certificate/CRLNumberExtension.h>
#include <libcryptosec/certificate/DeltaCRLIndicatorExtension.h>
#include <libcryptosec/certificate/ObjectIdentifierFactory.h>

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

    static long basicConstraintsPathLen;
    static unsigned long serialNumber;
    static unsigned long serialNew;
    static char* keyIdentifierValue;
    static std::string rfcName;
    static std::string dnsName;
    static std::string extendedKeyUsageOne;
    static std::string extendedKeyUsageTwo;
};

/*
 * Initialization of variables used in the tests
 */
long ExtensionsTest::basicConstraintsPathLen = 30;
unsigned long ExtensionsTest::serialNumber = 1234567890;
unsigned long ExtensionsTest::serialNew = 9876543210;
char* ExtensionsTest::keyIdentifierValue = (char *) "B132247BE75A265B9CB80BBD3474CBB7A4FA40CC";
std::string ExtensionsTest::rfcName = "example@mail.com";
std::string ExtensionsTest::dnsName = "8.8.8.8";
std::string ExtensionsTest::extendedKeyUsageOne = "1.3.6.1.5.5.7.3.1";
std::string ExtensionsTest::extendedKeyUsageTwo = "1.3.6.1.5.5.7.3.4";

/**
 * @brief Tests AuthorityKeyIdentifierExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, AuthorityKeyIdentifier) {
    AuthorityKeyIdentifierExtension ext;
    long serialNumber;
    GeneralNames gns;
    GeneralName gn;
    X509_EXTENSION *extX509;
    std::vector<GeneralName> generalNames;

    ByteArray ba(ExtensionsTest::keyIdentifierValue);
    ByteArray value;

    gn.setRfc822Name(ExtensionsTest::rfcName);
    gns.addGeneralName(gn);

    gn.setDnsName(ExtensionsTest::dnsName);
    gns.addGeneralName(gn);

    ext.setKeyIdentifier(ba);
    ext.setAuthorityCertIssuer(gns);
    ext.setAuthorityCertSerialNumber(ExtensionsTest::serialNumber);

    value = ext.getKeyIdentifier();
    gns = ext.getAuthorityCertIssuer();
    generalNames = gns.getGeneralNames();
    serialNumber = ext.getAuthorityCertSerialNumber();
    extX509 = ext.getX509Extension();
    AuthorityKeyIdentifierExtension fromX509(extX509);

    generalTests(ext, Extension::AUTHORITY_KEY_IDENTIFIER);

    ASSERT_EQ(value.toString(), ExtensionsTest::keyIdentifierValue);
    ASSERT_EQ(generalNames[0].getRfc822Name(), ExtensionsTest::rfcName);
    ASSERT_EQ(generalNames[1].getDnsName(), ExtensionsTest::dnsName);
    ASSERT_EQ(serialNumber, ExtensionsTest::serialNumber);
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
/* Few things to do in libcryptosec */
TEST_F(ExtensionsTest, CRLNumber) {
    CRLNumberExtension ext(ExtensionsTest::serialNumber);
    // X509_EXTENSION *extX509;

    /* TODO in libcryptosec
    extX509 = ext.getX509Extension();
    CRLNumberExtension fromX509(extX509); */

    generalTests(ext, Extension::CRL_NUMBER);

    ASSERT_EQ(ext.getSerial(), ExtensionsTest::serialNumber);
    // ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());

    ext.setSerial(ExtensionsTest::serialNew);
    ASSERT_EQ(ext.getSerial(), ExtensionsTest::serialNew);
}

/**
 * @brief Tests DeltaCRLIndicatorExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, DeltaCRLIndicator) {
    DeltaCRLIndicatorExtension ext(ExtensionsTest::serialNumber);
    X509_EXTENSION *extX509;

    extX509 = ext.getX509Extension();
    DeltaCRLIndicatorExtension fromX509(extX509);

    generalTests(ext, Extension::DELTA_CRL_INDICATOR);

    ASSERT_EQ(ext.getSerial(), ExtensionsTest::serialNumber);
    ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());

    ext.setSerial(ExtensionsTest::serialNew);
    ASSERT_EQ(ext.getSerial(), ExtensionsTest::serialNew);
}

/**
 * @brief Tests ExtendedKeyUsageExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, ExtendedKeyUsage) {
   ExtendedKeyUsageExtension ext;
    X509_EXTENSION *extX509;
    ObjectIdentifier oid;
    std::vector<ObjectIdentifier> usage;

    oid = ObjectIdentifierFactory::getObjectIdentifier(ExtensionsTest::extendedKeyUsageOne);
    ext.addUsage(oid);

    oid = ObjectIdentifierFactory::getObjectIdentifier(ExtensionsTest::extendedKeyUsageTwo);
    ext.addUsage(oid);

    extX509 = ext.getX509Extension();
    ExtendedKeyUsageExtension fromX509(extX509);

    generalTests(ext, Extension::EXTENDED_KEY_USAGE);

    usage = ext.getUsages();
    ASSERT_TRUE(usage.size() == 2);
    ASSERT_EQ(usage[0].getOid(), ExtensionsTest::extendedKeyUsageOne);
    ASSERT_EQ(usage[1].getOid(), ExtensionsTest::extendedKeyUsageTwo);

    //fromX509 has usages reversed from original.
    usage = fromX509.getUsages();
    ASSERT_TRUE(usage.size() == 2);
    ASSERT_EQ(usage[1].getOid(), ExtensionsTest::extendedKeyUsageOne);
    ASSERT_EQ(usage[0].getOid(), ExtensionsTest::extendedKeyUsageTwo);
}

/**
 * @brief Tests IssuerAlternativeNameExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, IssuerAlternativeName) {
    IssuerAlternativeNameExtension ext;
    GeneralNames gns;
    GeneralName gn;
    X509_EXTENSION *extX509;
    std::vector<GeneralName> generalNames;

    gn.setRfc822Name(ExtensionsTest::rfcName);
    gns.addGeneralName(gn);

    gn.setDnsName(ExtensionsTest::dnsName);
    gns.addGeneralName(gn);

    ext.setIssuerAltName(gns);

    gns = ext.getIssuerAltName();
    generalNames = gns.getGeneralNames();
    extX509 = ext.getX509Extension();
    IssuerAlternativeNameExtension fromX509(extX509);

    generalTests(ext, Extension::ISSUER_ALTERNATIVE_NAME);

    ASSERT_EQ(generalNames[0].getRfc822Name(), ExtensionsTest::rfcName);
    ASSERT_EQ(generalNames[1].getDnsName(), ExtensionsTest::dnsName);
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
 * @brief Tests SubjectAlternativeNameExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, SubjectAlternativeName) {
    SubjectAlternativeNameExtension ext;
    GeneralNames gns;
    GeneralName gn;
    X509_EXTENSION *extX509;
    std::vector<GeneralName> generalNames;

    gn.setRfc822Name(ExtensionsTest::rfcName);
    gns.addGeneralName(gn);

    gn.setDnsName(ExtensionsTest::dnsName);
    gns.addGeneralName(gn);

    ext.setSubjectAltName(gns);

    gns = ext.getSubjectAltName();
    generalNames = gns.getGeneralNames();
    extX509 = ext.getX509Extension();
    SubjectAlternativeNameExtension fromX509(extX509);

    generalTests(ext, Extension::SUBJECT_ALTERNATIVE_NAME);

    ASSERT_EQ(generalNames[0].getRfc822Name(), ExtensionsTest::rfcName);
    ASSERT_EQ(generalNames[1].getDnsName(), ExtensionsTest::dnsName);
    ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());
}

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
