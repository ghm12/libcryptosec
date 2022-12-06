#include <libcryptosec/certificate/CertificateRevocationListBuilder.h>
#include <libcryptosec/RSAKeyPair.h>

#include <sstream>
#include <gtest/gtest.h>

/**
 * @brief Testes unitários da classe CertificateRevocationList
 */
class CertificateRevocationListTest : public ::testing::Test {

protected:
    virtual void SetUp() {
        builder = new CertificateRevocationListBuilder();
        signCertificateRevocationListBuilder(builder);
    }

    virtual void TearDown() {
        free(builder);
        free(crl);
    }

    void fillSerialNumber(CertificateRevocationListBuilder *builder)
    {
        BigInteger bi;
        bi.setHexValue(serialHex);

        builder->setSerialNumber(bi);
    }

    void fillVersion(CertificateRevocationListBuilder *builder)
    {
        builder->setVersion(version);
    }

    void fillIssuer(CertificateRevocationListBuilder *builder)
    {
        RDNSequence rdn;

        rdn.addEntry(RDNSequence::COUNTRY, rdnIssuerCountry);
        rdn.addEntry(RDNSequence::STATE_OR_PROVINCE, rdnIssuerState);
        rdn.addEntry(RDNSequence::LOCALITY, rdnIssuerLocality);
        rdn.addEntry(RDNSequence::ORGANIZATION, rdnIssuerOrganization);
        rdn.addEntry(RDNSequence::COMMON_NAME, rdnIssuerCommonName);

        builder->setIssuer(rdn);
    }

    void fillLastUpdate(CertificateRevocationListBuilder *builder)
    {
        DateTime dt(epochLast);
        builder->setLastUpdate(dt);
    }

    void fillNextUpdate(CertificateRevocationListBuilder *builder)
    {
        DateTime dt(epochNext);
        builder->setNextUpdate(dt);
    }

    RevokedCertificate createRevokedCertificate(int type)
    {
        BigInteger bi;
        DateTime dt;
        RevokedCertificate revoked;

        switch(type)
        {
            case 0:
                bi.setHexValue(revSerialOne);
                dt.setDateTime(revEpochOne);

                revoked.setCertificateSerialNumber(bi);
                revoked.setRevocationDate(dt);
                revoked.setReasonCode(revReasonOne);
                break;
            case 1:
                bi.setHexValue(revSerialTwo);
                dt.setDateTime(revEpochTwo);

                revoked.setCertificateSerialNumber(bi);
                revoked.setRevocationDate(dt);
                revoked.setReasonCode(revReasonTwo);
                break;
        }

        return revoked;
    }

    void fillRevokedCertificates(CertificateRevocationListBuilder *builder, int amount)
    {
        std::vector<RevokedCertificate> revoked;
        for (int i = 0; i < amount; i++)
        {
            revoked.push_back(createRevokedCertificate(i));
        }

        builder->addRevokedCertificates(revoked);
    }

    void fillExtension(CertificateRevocationListBuilder *builder)
    {
        DeltaCRLIndicatorExtension ext;
        AuthorityKeyIdentifierExtension keyid;

        ext = DeltaCRLIndicatorExtension(baseCrl);
        keyid.setKeyIdentifier(keyPair->getPublicKey()->getKeyIdentifier());

        builder->addExtension(ext);
        builder->addExtension(keyid);
    }

    void fillCertificateRevocationListBuilder(CertificateRevocationListBuilder *builder)
    {
        fillSerialNumber(builder);
        fillVersion(builder);
        fillIssuer(builder);
        fillLastUpdate(builder);
        fillNextUpdate(builder);
        fillRevokedCertificates(builder, 2);
        fillExtension(builder);
    }

    void signCertificateRevocationListBuilder(CertificateRevocationListBuilder *builder)
    {
        fillCertificateRevocationListBuilder(builder);
        crl = builder->sign(*keyPair->getPrivateKey(), mdAlgorithm);
    }

    void checkSerialNumber(CertificateRevocationList *crl)
    {
        BigInteger bi;
        bi = crl->getSerialNumberBigInt();
        ASSERT_EQ(bi.toHex(), serialHex);
    }

    void checkBaseCRLNumber(CertificateRevocationList *crl)
    {
        BigInteger bi;
        bi = crl->getBaseCRLNumberBigInt();
        ASSERT_EQ(bi.toDec(), baseCrlString);
    }

    void checkVersion(CertificateRevocationList *crl)
    {
        ASSERT_EQ(crl->getVersion(), version);
    }

    void checkIssuer(CertificateRevocationList *crl)
    {
        RDNSequence rdn;
        rdn = crl->getIssuer();

        ASSERT_EQ(rdn.getEntries(RDNSequence::COUNTRY)[0], rdnIssuerCountry);
        ASSERT_EQ(rdn.getEntries(RDNSequence::STATE_OR_PROVINCE)[0], rdnIssuerState);
        ASSERT_EQ(rdn.getEntries(RDNSequence::LOCALITY)[0], rdnIssuerLocality);
        ASSERT_EQ(rdn.getEntries(RDNSequence::ORGANIZATION)[0], rdnIssuerOrganization);
        ASSERT_EQ(rdn.getEntries(RDNSequence::COMMON_NAME)[0], rdnIssuerCommonName);
    }

    void checkLastUpdate(CertificateRevocationList *crl)
    {
        DateTime dt;
        dt = crl->getLastUpdate();

        ASSERT_EQ(dt.getDateTime(), epochLast);
    }

    void checkNextUpdate(CertificateRevocationList *crl)
    {
        DateTime dt;
        dt = crl->getNextUpdate();

        ASSERT_EQ(dt.getDateTime(), epochNext);
    }

    void checkRevokedCertificate(CertificateRevocationList *crl)
    {
        std::vector<RevokedCertificate> revoked;
        revoked = crl->getRevokedCertificate();

        ASSERT_EQ(revoked.size(), 2);

        BigInteger bi;
        DateTime dt;
        RevokedCertificate rev;

        rev = revoked[1];
        bi = rev.getCertificateSerialNumberBigInt();
        dt = rev.getRevocationDate();
        ASSERT_EQ(bi.toHex(), revSerialTwo);
        ASSERT_EQ(dt.getDateTime(), revEpochTwo);
        ASSERT_EQ(rev.getReasonCode(), revReasonTwo);

        rev = revoked[0];
        bi = rev.getCertificateSerialNumberBigInt();
        dt = rev.getRevocationDate();
        ASSERT_EQ(bi.toHex(), revSerialOne);
        ASSERT_EQ(dt.getDateTime(), revEpochOne);
        ASSERT_EQ(rev.getReasonCode(), revReasonOne);
    }

    void checkExtension(CertificateRevocationList *crl)
    {
        std::vector<Extension *> exts;
        DeltaCRLIndicatorExtension ext;

        exts = crl->getExtension(Extension::DELTA_CRL_INDICATOR);
        ASSERT_EQ(exts.size(), 1);
        
        ext = DeltaCRLIndicatorExtension(exts[0]->getX509Extension());
        ASSERT_EQ(ext.getSerial(), baseCrl);
    }

    void checkSignature(CertificateRevocationList *crl)
    {
        ASSERT_TRUE(crl->verify(*keyPair->getPublicKey()));
    }

    CertificateRevocationListBuilder *builder;
    CertificateRevocationList *crl;

    static RSAKeyPair *keyPair;
    static MessageDigest::Algorithm mdAlgorithm;
    static std::string serialHex;
    static int version;

    static std::string rdnIssuerCountry;
    static std::string rdnIssuerState;
    static std::string rdnIssuerLocality;
    static std::string rdnIssuerOrganization;
    static std::string rdnIssuerCommonName;

    static int epochLast;
    static int epochNext;

    static std::string revSerialOne;
    static int revEpochOne;
    static RevokedCertificate::ReasonCode revReasonOne;

    static std::string revSerialTwo;
    static int revEpochTwo;
    static RevokedCertificate::ReasonCode revReasonTwo;

    static long baseCrl;
    static std::string baseCrlString;
};

/*
 * Initialization of variables used in the tests
 */
RSAKeyPair* CertificateRevocationListTest::keyPair = new RSAKeyPair(2048);
MessageDigest::Algorithm CertificateRevocationListTest::mdAlgorithm = MessageDigest::SHA512;
std::string CertificateRevocationListTest::serialHex = "DC94A473D5C86891";
int CertificateRevocationListTest::version = 1;

std::string CertificateRevocationListTest::rdnIssuerCountry = "BR";
std::string CertificateRevocationListTest::rdnIssuerState = "Sao Paulo";
std::string CertificateRevocationListTest::rdnIssuerLocality = "Sao Paulo";
std::string CertificateRevocationListTest::rdnIssuerOrganization = "Cert Signer";
std::string CertificateRevocationListTest::rdnIssuerCommonName = "Ronaldo Cert Signer V3";

int CertificateRevocationListTest::epochLast = 1487889907;
int CertificateRevocationListTest::epochNext = 1665096307;

// Serial seems bugged when retrieving from CRL if 16 bytes, need to look further
std::string CertificateRevocationListTest::revSerialOne = "9A3298AFB5AC71C7";
int CertificateRevocationListTest::revEpochOne = 1487889918;
RevokedCertificate::ReasonCode CertificateRevocationListTest::revReasonOne = RevokedCertificate::KEY_COMPROMISE;

std::string CertificateRevocationListTest::revSerialTwo = "1ED6EB565788E38E";
int CertificateRevocationListTest::revEpochTwo = 1487989907;
RevokedCertificate::ReasonCode CertificateRevocationListTest::revReasonTwo = RevokedCertificate::CA_COMPROMISE;

long CertificateRevocationListTest::baseCrl = 1234567890;
std::string CertificateRevocationListTest::baseCrlString = "1234567890";


/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, SerialNumber) {
    checkSerialNumber(crl);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, BaseCRLNumber) {
    checkBaseCRLNumber(crl);
}


/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, Version) {
    checkVersion(crl);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, Issuer) {
    checkIssuer(crl);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, LastUpdate) {
    checkLastUpdate(crl);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, NextUpdate) {
    checkNextUpdate(crl);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, RevokedCertificate) {
    checkRevokedCertificate(crl);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, Verify) {
    checkSignature(crl);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, FromX509) {
    crl = new CertificateRevocationList(crl->getX509Crl());
    checkRevokedCertificate(crl);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, FromPEM) {
    crl = new CertificateRevocationList(crl->getPemEncoded());
    checkRevokedCertificate(crl);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, FromDER) {
    ByteArray ba;

    ba = crl->getDerEncoded();
    crl = new CertificateRevocationList(ba);
    checkRevokedCertificate(crl);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, FromCRL) {
    CertificateRevocationList rev(crl->getX509Crl());

    crl = new CertificateRevocationList(rev);
    checkRevokedCertificate(crl);
}