#include <libcryptosec/certificate/RevokedCertificate.h>

#include <sstream>
#include <gtest/gtest.h>

/**
 * @brief Testes unitários da classe RevokedCertificate
 */
class RevokedCertificateTest : public ::testing::Test {

protected:
    virtual void SetUp() {
        revoked = new RevokedCertificate();
    }

    virtual void TearDown() {
        free(revoked);
    }

    void fillSerialNumber(RevokedCertificate *rev)
    {
        BigInteger bi;
        bi.setHexValue(serialHex);

        rev->setCertificateSerialNumber(bi);
    }

    void fillRevocationDate(RevokedCertificate *rev)
    {
        DateTime dt;
        dt.setDateTime(epochDate);

        rev->setRevocationDate(dt);
    }

    void fillReasonCode(RevokedCertificate *rev)
    {
        rev->setReasonCode(reason);
    }

    void fillRevokedCertificate(RevokedCertificate *rev)
    {
        fillSerialNumber(rev);
        fillRevocationDate(rev);
        fillReasonCode(rev);
    }

    void checkSerialNumber(RevokedCertificate *rev)
    {
        BigInteger bi;
        bi = rev->getCertificateSerialNumberBigInt();

        ASSERT_EQ(serialHex, bi.toHex());
    }

    void checkRevocationDate(RevokedCertificate *rev)
    {
        DateTime dt;
        dt = rev->getRevocationDate();

        ASSERT_EQ(epochDate, dt.getDateTime());
    }

    void checkReasonCode(RevokedCertificate *rev)
    {
        ASSERT_EQ(reason, rev->getReasonCode());
    }

    void checkRevokedCertificate(RevokedCertificate *rev)
    {
        checkSerialNumber(rev);
        checkRevocationDate(rev);
        checkReasonCode(rev);
    }

    RevokedCertificate *revoked;

    static std::string serialHex;
    static int epochDate;
    static RevokedCertificate::ReasonCode reason;
};

/*
 * Initialization of variables used in the tests
 */
std::string RevokedCertificateTest::serialHex = "DC94A473D5C86891";
int RevokedCertificateTest::epochDate = 1665096307;
RevokedCertificate::ReasonCode RevokedCertificateTest::reason = RevokedCertificate::KEY_COMPROMISE;

/**
 * @brief 
 */
TEST_F(RevokedCertificateTest, SerialNumber) {
    fillSerialNumber(revoked);
    checkSerialNumber(revoked);
}

/**
 * @brief 
 */
TEST_F(RevokedCertificateTest, RevocationDate) {
    fillRevocationDate(revoked);
    checkRevocationDate(revoked);
}

/**
 * @brief 
 */
TEST_F(RevokedCertificateTest, ReasonCode) {
    fillReasonCode(revoked);
    checkReasonCode(revoked);
}

/**
 * @brief 
 */
TEST_F(RevokedCertificateTest, XmlEncoded) {
    fillRevokedCertificate(revoked);
    ASSERT_TRUE(revoked->getXmlEncoded().size() > 0);
}

/**
 * @brief 
 */
TEST_F(RevokedCertificateTest, FromX509) {
    X509_REVOKED *x509;

    fillRevokedCertificate(revoked);

    x509 = revoked->getX509Revoked();
    revoked = new RevokedCertificate(x509);
    
    checkRevokedCertificate(revoked);
}
