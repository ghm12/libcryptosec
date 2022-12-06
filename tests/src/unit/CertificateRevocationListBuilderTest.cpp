#include <libcryptosec/certificate/CertificateRevocationListBuilder.h>
#include <libcryptosec/RSAKeyPair.h>

#include <sstream>
#include <gtest/gtest.h>

/**
 * @brief Testes unitários da classe CertificateRevocationListBuilder
 */
class CertificateRevocationListBuilderTest : public ::testing::Test {

protected:
    virtual void SetUp() {
        builder = new CertificateRevocationListBuilder();
    }

    virtual void TearDown() {
        free(builder);
    }

    void fillSerialNumber(CertificateRevocationListBuilder *builder)
    {
        BigInteger bi;
        bi.setHexValue(serialHex);

        builder->setSerialNumber(bi);
    }

    void checkSerialNumber(CertificateRevocationListBuilder *builder)
    {
        BigInteger bi;
        bi = builder->getSerialNumberBigInt();

        ASSERT_EQ(serialHex, bi.toHex());
    }

    void fillVersion(CertificateRevocationListBuilder *builder)
    {
        builder->setVersion(version);
    }

    void checkVersion(CertificateRevocationListBuilder *builder)
    {
        ASSERT_EQ(version, builder->getVersion());
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

    void checkIssuer(CertificateRevocationListBuilder *builder)
    {
        RDNSequence rdn;
        rdn = builder->getIssuer();

        ASSERT_EQ(rdn.getEntries(RDNSequence::COUNTRY)[0], rdnIssuerCountry);
        ASSERT_EQ(rdn.getEntries(RDNSequence::STATE_OR_PROVINCE)[0], rdnIssuerState);
        ASSERT_EQ(rdn.getEntries(RDNSequence::LOCALITY)[0], rdnIssuerLocality);
        ASSERT_EQ(rdn.getEntries(RDNSequence::ORGANIZATION)[0], rdnIssuerOrganization);
        ASSERT_EQ(rdn.getEntries(RDNSequence::COMMON_NAME)[0], rdnIssuerCommonName);
    }

    void fillLastUpdate(CertificateRevocationListBuilder *builder)
    {
        DateTime dt(epochLast);
        builder->setLastUpdate(dt);
    }

    void checkLastUpdate(CertificateRevocationListBuilder *builder)
    {
        DateTime dt;
        dt = builder->getLastUpdate();

        ASSERT_EQ(dt.getDateTime(), epochLast);
    }

    void fillNextUpdate(CertificateRevocationListBuilder *builder)
    {
        DateTime dt(epochNext);
        builder->setNextUpdate(dt);
    }

    void checkNextUpdate(CertificateRevocationListBuilder *builder)
    {
        DateTime dt;
        dt = builder->getNextUpdate();

        ASSERT_EQ(dt.getDateTime(), epochNext);
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

    void fillRevokedCertificate(CertificateRevocationListBuilder *builder, int amount)
    {
        for (int i = 0; i < amount; i++)
        {
            RevokedCertificate revoked = createRevokedCertificate(i);
            builder->addRevokedCertificate(revoked);
        }
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

    void checkRevokedCertificate(CertificateRevocationListBuilder *builder, int amount)
    {
        std::vector<RevokedCertificate> revoked;
        revoked = builder->getRevokedCertificate();

        ASSERT_EQ(revoked.size(), amount);

        BigInteger bi;
        DateTime dt;
        RevokedCertificate rev;

        switch(amount)
        {
            case 2:
                rev = revoked[1];
                bi = rev.getCertificateSerialNumberBigInt();
                dt = rev.getRevocationDate();

                ASSERT_EQ(bi.toHex(), revSerialTwo);
                ASSERT_EQ(dt.getDateTime(), revEpochTwo);
                ASSERT_EQ(rev.getReasonCode(), revReasonTwo);
            case 1:
                rev = revoked[0];
                bi = rev.getCertificateSerialNumberBigInt();
                dt = rev.getRevocationDate();

                ASSERT_EQ(bi.toHex(), revSerialOne);
                ASSERT_EQ(dt.getDateTime(), revEpochOne);
                ASSERT_EQ(rev.getReasonCode(), revReasonOne);
        }
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

    void fillExtensions(CertificateRevocationListBuilder *builder)
    {
        std::vector<Extension *> exts;
        DeltaCRLIndicatorExtension *ext;
        AuthorityKeyIdentifierExtension *keyid;

        ext = new DeltaCRLIndicatorExtension(baseCrl);
        keyid = new AuthorityKeyIdentifierExtension();
        keyid->setKeyIdentifier(keyPair->getPublicKey()->getKeyIdentifier());

        exts.push_back(ext);
        exts.push_back(keyid);

        builder->addExtensions(exts);
    }

    void replaceExtension(CertificateRevocationListBuilder *builder)
    {
        DeltaCRLIndicatorExtension ext;
        ext = DeltaCRLIndicatorExtension(baseCrlReplace);

        builder->replaceExtension(ext);
    }

    void checkExtension(CertificateRevocationListBuilder *builder, bool replace = false)
    {
        std::vector<Extension *> exts;
        DeltaCRLIndicatorExtension ext;

        exts = builder->getExtension(Extension::DELTA_CRL_INDICATOR);
        ASSERT_EQ(exts.size(), 1);
        
        ext = DeltaCRLIndicatorExtension(exts[0]->getX509Extension());
        
        if (!replace)
        {
            ASSERT_EQ(ext.getSerial(), baseCrl);
            return;
        }

        ASSERT_EQ(ext.getSerial(), baseCrlReplace);
    }

    void checkExtensions(CertificateRevocationListBuilder *builder)
    {
        std::vector<Extension *> exts;
        DeltaCRLIndicatorExtension ext;
        AuthorityKeyIdentifierExtension keyid;

        exts = builder->getExtensions();
        ASSERT_EQ(exts.size(), 2);
        
        ext = DeltaCRLIndicatorExtension(exts[0]->getX509Extension());
        keyid = AuthorityKeyIdentifierExtension(exts[1]->getX509Extension());

        ASSERT_EQ(ext.getSerial(), baseCrl);
        ASSERT_EQ(keyid.getKeyIdentifier().toHex(), keyPair->getPublicKey()->getKeyIdentifier().toHex());
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

    void checkCertificateRevocationListBuilder(CertificateRevocationListBuilder *builder)
    {
        checkSerialNumber(builder);
        checkVersion(builder);
        checkIssuer(builder);
        checkLastUpdate(builder);
        checkNextUpdate(builder);
        checkRevokedCertificate(builder, 2);
        checkExtension(builder);
    }

    void signCertificateRevocationListBuilder(CertificateRevocationListBuilder *builder)
    {
        fillCertificateRevocationListBuilder(builder);
        crl = builder->sign(*keyPair->getPrivateKey(), mdAlgorithm);
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
    static long baseCrlReplace;
};

/*
 * Initialization of variables used in the tests
 */
RSAKeyPair* CertificateRevocationListBuilderTest::keyPair = new RSAKeyPair(2048);
MessageDigest::Algorithm CertificateRevocationListBuilderTest::mdAlgorithm = MessageDigest::SHA512;
std::string CertificateRevocationListBuilderTest::serialHex = "DC94A473D5C86891";
int CertificateRevocationListBuilderTest::version = 1;

std::string CertificateRevocationListBuilderTest::rdnIssuerCountry = "BR";
std::string CertificateRevocationListBuilderTest::rdnIssuerState = "Sao Paulo";
std::string CertificateRevocationListBuilderTest::rdnIssuerLocality = "Sao Paulo";
std::string CertificateRevocationListBuilderTest::rdnIssuerOrganization = "Cert Signer";
std::string CertificateRevocationListBuilderTest::rdnIssuerCommonName = "Ronaldo Cert Signer V3";

int CertificateRevocationListBuilderTest::epochLast = 1487889907;
int CertificateRevocationListBuilderTest::epochNext = 1665096307;

std::string CertificateRevocationListBuilderTest::revSerialOne = "9A3298AFB5AC71C7";
int CertificateRevocationListBuilderTest::revEpochOne = 1483275661;
RevokedCertificate::ReasonCode CertificateRevocationListBuilderTest::revReasonOne = RevokedCertificate::KEY_COMPROMISE;

std::string CertificateRevocationListBuilderTest::revSerialTwo = "1ED6EB565788E38E";
int CertificateRevocationListBuilderTest::revEpochTwo = 1486044122;
RevokedCertificate::ReasonCode CertificateRevocationListBuilderTest::revReasonTwo = RevokedCertificate::CA_COMPROMISE;

long CertificateRevocationListBuilderTest::baseCrl = 1234567890;
long CertificateRevocationListBuilderTest::baseCrlReplace = 9876543210;

/**
 * @brief 
 */
TEST_F(CertificateRevocationListBuilderTest, SerialNumber) {
    fillSerialNumber(builder);
    checkSerialNumber(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListBuilderTest, Version) {
    fillVersion(builder);
    checkVersion(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListBuilderTest, IssuerRDN) {
    fillIssuer(builder);
    checkIssuer(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListBuilderTest, LastUpdate) {
    fillLastUpdate(builder);
    checkLastUpdate(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListBuilderTest, NextUpdate) {
    fillNextUpdate(builder);
    checkNextUpdate(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListBuilderTest, AddOneRevokedCertificate) {
    fillRevokedCertificate(builder, 1);
    checkRevokedCertificate(builder, 1);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListBuilderTest, AddTwoRevokedCertificate) {
    fillRevokedCertificate(builder, 2);
    checkRevokedCertificate(builder, 2);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListBuilderTest, AddRevokedCertificates) {
    fillRevokedCertificates(builder, 2);
    checkRevokedCertificate(builder, 2);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListBuilderTest, AddExtension) {
    fillExtension(builder);
    checkExtension(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListBuilderTest, AddExtensions) {
    fillExtensions(builder);
    checkExtension(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListBuilderTest, ReplaceExtension) {
    fillExtension(builder);
    replaceExtension(builder);
    checkExtension(builder, true);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListBuilderTest, GetExtensions) {
    fillExtensions(builder);
    checkExtensions(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListBuilderTest, Signature) {
    signCertificateRevocationListBuilder(builder);
    checkSignature(crl);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListBuilderTest, FromPEM) {
    signCertificateRevocationListBuilder(builder);

    builder = new CertificateRevocationListBuilder(crl->getPemEncoded());
    checkCertificateRevocationListBuilder(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListBuilderTest, FromDER) {
    ByteArray ba;

    signCertificateRevocationListBuilder(builder);
    ba = crl->getDerEncoded();
    builder = new CertificateRevocationListBuilder(ba);
    checkCertificateRevocationListBuilder(builder);
}