#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/RSAKeyPair.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe 
 */
class CertificateTest : public ::testing::Test {

public:
enum Operation {
    NORMAL,
    ALTER,
    VECTOR,
    OID,
};

protected:
    virtual void SetUp() {
        builder = new CertificateBuilder();
    }

    virtual void TearDown() {
        free(builder);
    }

    void fillSerialNumber(CertificateBuilder *builder)
    {
        BigInteger bi;
        bi.setHexValue(serialHex);
        builder->setSerialNumber(bi);
    }

    void fillPublicKey(CertificateBuilder *builder)
    {
        builder->setPublicKey(*keyPair->getPublicKey());
    }

    void fillVersion(CertificateBuilder *builder)
    {
        builder->setVersion(version);
    }

    void fillNotBefore(CertificateBuilder *builder)
    {
        DateTime dt(epochBefore);
        builder->setNotBefore(dt);
    }

    void fillNotAfter(CertificateBuilder *builder)
    {
        DateTime dt(epochAfter);
        builder->setNotAfter(dt);
    }

    void fillIssuer(CertificateBuilder *builder)
    {
        RDNSequence rdn;

        rdn.addEntry(RDNSequence::COUNTRY, rdnIssuerCountry);
        rdn.addEntry(RDNSequence::STATE_OR_PROVINCE, rdnIssuerState);
        rdn.addEntry(RDNSequence::LOCALITY, rdnIssuerLocality);
        rdn.addEntry(RDNSequence::ORGANIZATION, rdnIssuerOrganization);
        rdn.addEntry(RDNSequence::COMMON_NAME, rdnIssuerCommonName);

        builder->setIssuer(rdn);
    }

    void fillSubject(CertificateBuilder *builder)
    {
        RDNSequence rdn;

        rdn.addEntry(RDNSequence::COUNTRY, rdnSubjectCountry);
        rdn.addEntry(RDNSequence::STATE_OR_PROVINCE, rdnSubjectState);
        rdn.addEntry(RDNSequence::LOCALITY, rdnSubjectLocality);
        rdn.addEntry(RDNSequence::ORGANIZATION, rdnSubjectOrganization);
        rdn.addEntry(RDNSequence::COMMON_NAME, rdnSubjectCommonName);

        builder->setSubject(rdn);
    }

    void alterSubject(CertificateBuilder *builder)
    {
        RDNSequence rdn;

        rdn.addEntry(RDNSequence::COUNTRY, rdnIssuerCountry);
        rdn.addEntry(RDNSequence::STATE_OR_PROVINCE, rdnIssuerState);
        rdn.addEntry(RDNSequence::LOCALITY, rdnIssuerLocality);
        rdn.addEntry(RDNSequence::ORGANIZATION, rdnIssuerOrganization);
        rdn.addEntry(RDNSequence::COMMON_NAME, rdnSubjectCommonName);

        builder->alterSubject(rdn);
    }

    void createBasicConstraints(BasicConstraintsExtension *ext)
    {
        ext->setCa(basicConstrainsCA);
        ext->setPathLen(basicConstraintsPathLen);
    }

    void createBasicConstraintsReplace(BasicConstraintsExtension *ext)
    {
        ext->setCa(basicConstrainsCA);
        ext->setPathLen(basicConstraintsPathLenReplace);
    }

    void createKeyUsage(KeyUsageExtension *ext)
    {
        std::vector<KeyUsageExtension::Usage>::iterator it;
        for (it = keyUsage.begin(); it != keyUsage.end(); it++)
        {
            ext->setUsage(*it, true);
        }
    }

    void fillExtensions(CertificateBuilder *builder, Operation op = NORMAL)
    {
        BasicConstraintsExtension *bcExt;
        KeyUsageExtension *kuExt;
        std::vector<Extension *> exts;

        bcExt = new BasicConstraintsExtension();
        kuExt = new KeyUsageExtension();

        createBasicConstraints(bcExt);
        createKeyUsage(kuExt);

        if (!op)
        {
            builder->addExtension(*bcExt);
            builder->addExtension(*kuExt);
            return;
        }

        exts.push_back(bcExt);
        exts.push_back(kuExt);
        builder->addExtensions(exts);
    }

    void replaceExtension(CertificateBuilder *builder)
    {
        BasicConstraintsExtension *bcExt;

        bcExt = new BasicConstraintsExtension();
        createBasicConstraintsReplace(bcExt);

        builder->replaceExtension(*bcExt);
    }

    void fillCertificateBuilder(CertificateBuilder *builder)
    {
        fillSerialNumber(builder);
        fillPublicKey(builder);
        fillVersion(builder);
        fillNotBefore(builder);
        fillNotAfter(builder);
        fillIssuer(builder);
        fillSubject(builder);
        fillExtensions(builder);
    }

    void signBuilder(CertificateBuilder *builder)
    {
        PrivateKey *privKey;

        privKey = signKeyPair->getPrivateKey();
        certificate = builder->sign(*privKey, mdAlgorithm);
    }

    void checkSerialNumber(CertificateBuilder *builder)
    {
        BigInteger bi;
        bi = builder->getSerialNumberBigInt();
        ASSERT_EQ(bi.toHex(), serialHex);
    }

    void checkPublicKey(CertificateBuilder *builder)
    {
        PublicKey *pubKey = keyPair->getPublicKey();
        PublicKey *keyBuilder = builder->getPublicKey();

        ASSERT_EQ(keyBuilder->getPemEncoded(), pubKey->getPemEncoded());

        free(pubKey);
        free(keyBuilder);
    }

    void checkVersion(CertificateBuilder *builder)
    {
        ASSERT_EQ(builder->getVersion(), version);
    }

    void checkNotBefore(CertificateBuilder *builder)
    {
        DateTime dt;
        dt = builder->getNotBefore();

        ASSERT_EQ(dt.getDateTime(), epochBefore);
    }

    void checkNotAfter(CertificateBuilder *builder)
    {
        DateTime dt;
        dt = builder->getNotAfter();

        ASSERT_EQ(dt.getDateTime(), epochAfter);
    }

    void checkIssuer(CertificateBuilder *builder)
    {
        RDNSequence rdn;
        rdn = builder->getIssuer();

        ASSERT_EQ(rdn.getEntries(RDNSequence::COUNTRY)[0], rdnIssuerCountry);
        ASSERT_EQ(rdn.getEntries(RDNSequence::STATE_OR_PROVINCE)[0], rdnIssuerState);
        ASSERT_EQ(rdn.getEntries(RDNSequence::LOCALITY)[0], rdnIssuerLocality);
        ASSERT_EQ(rdn.getEntries(RDNSequence::ORGANIZATION)[0], rdnIssuerOrganization);
        ASSERT_EQ(rdn.getEntries(RDNSequence::COMMON_NAME)[0], rdnIssuerCommonName);
    }

    void checkSubject(CertificateBuilder *builder, Operation op = NORMAL)
    {
        RDNSequence rdn;
        rdn = builder->getSubject();

        if (!op)
        {
            ASSERT_EQ(rdn.getEntries(RDNSequence::COUNTRY)[0], rdnSubjectCountry);
            ASSERT_EQ(rdn.getEntries(RDNSequence::STATE_OR_PROVINCE)[0], rdnSubjectState);
            ASSERT_EQ(rdn.getEntries(RDNSequence::LOCALITY)[0], rdnSubjectLocality);
            ASSERT_EQ(rdn.getEntries(RDNSequence::ORGANIZATION)[0], rdnSubjectOrganization);  
        } else
        {
            ASSERT_EQ(rdn.getEntries(RDNSequence::COUNTRY)[0], rdnIssuerCountry);
            ASSERT_EQ(rdn.getEntries(RDNSequence::STATE_OR_PROVINCE)[0], rdnIssuerState);
            ASSERT_EQ(rdn.getEntries(RDNSequence::LOCALITY)[0], rdnIssuerLocality);
            ASSERT_EQ(rdn.getEntries(RDNSequence::ORGANIZATION)[0], rdnIssuerOrganization);
        }

        ASSERT_EQ(rdn.getEntries(RDNSequence::COMMON_NAME)[0], rdnSubjectCommonName);
    }

    void checkBasicConstraints(BasicConstraintsExtension *ext)
    {
        ASSERT_TRUE(ext->isCa());
        ASSERT_EQ(ext->getPathLen(), basicConstraintsPathLen);
    }

    void checkBasicConstraintsReplace(BasicConstraintsExtension *ext)
    {
        ASSERT_TRUE(ext->isCa());
        ASSERT_EQ(ext->getPathLen(), basicConstraintsPathLenReplace); 
    }

    void checkKeyUsage(KeyUsageExtension *ext)
    {
        for (int i = 0; i < 9; i++)
        {
            KeyUsageExtension::Usage usage = (KeyUsageExtension::Usage) i;

            if (std::find(keyUsage.begin(), keyUsage.end(), usage) != keyUsage.end())
            {
                ASSERT_TRUE(ext->getUsage(usage));
                continue;
            }

            ASSERT_FALSE(ext->getUsage(usage));
        }
    }

    void checkExtensions(CertificateBuilder *builder, Operation op = NORMAL)
    {
        BasicConstraintsExtension *bcExt;
        KeyUsageExtension *kuExt;
        std::vector<Extension *> exts;

        exts = builder->getExtensions();
        bcExt = new BasicConstraintsExtension(exts[0]->getX509Extension());
        kuExt = new KeyUsageExtension(exts[1]->getX509Extension());

        if (!op)
        {
            checkBasicConstraints(bcExt);
        }
        else
        {
            checkBasicConstraintsReplace(bcExt);
        }

        checkKeyUsage(kuExt);
    }

    void getExtension(CertificateBuilder *builder)
    {
        BasicConstraintsExtension *bcExt;
        KeyUsageExtension *kuExt;
        Extension *ext;

        ext = builder->getExtension(Extension::BASIC_CONSTRAINTS)[0];
        bcExt = new BasicConstraintsExtension(ext->getX509Extension());

        ext = builder->getExtension(Extension::KEY_USAGE)[0];
        kuExt = new KeyUsageExtension(ext->getX509Extension());

        checkBasicConstraints(bcExt);
        checkKeyUsage(kuExt);
    }

    void removeExtension(CertificateBuilder *builder, Operation op = NORMAL)
    {
        BasicConstraintsExtension *bcExt;
        KeyUsageExtension *kuExt;
        ObjectIdentifier oid;
        Extension *ext;

        if (!op)
        {
            ext = builder->removeExtension(Extension::KEY_USAGE)[0];
            kuExt = new KeyUsageExtension(ext->getX509Extension());

            checkKeyUsage(kuExt);
        }
        else
        {
            oid = ObjectIdentifierFactory::getObjectIdentifier(basicConstraintsOID);
            ext = builder->removeExtension(oid)[0];
            bcExt = new BasicConstraintsExtension(ext->getX509Extension());

            checkBasicConstraints(bcExt);
        }

        ASSERT_TRUE(builder->getExtensions().size() == 1);
    }

    void checkSignature(Certificate* cert)
    {
        PublicKey *pubKey;

        pubKey = signKeyPair->getPublicKey();
        ASSERT_TRUE(cert->verify(*pubKey));
    }

    static KeyPair *keyPair;
    static KeyPair *signKeyPair;
    CertificateBuilder *builder;
    Certificate *certificate;

    static int version;

    static std::string rdnSubjectCountry;
    static std::string rdnSubjectState;
    static std::string rdnSubjectLocality;
    static std::string rdnSubjectOrganization;
    static std::string rdnSubjectCommonName;

    static std::string rdnIssuerCountry;
    static std::string rdnIssuerState;
    static std::string rdnIssuerLocality;
    static std::string rdnIssuerOrganization;
    static std::string rdnIssuerCommonName;

    static int epochBefore;
    static int epochAfter;
    static std::string serialHex;

    static bool basicConstrainsCA;
    static long basicConstraintsPathLen;
    static long basicConstraintsPathLenReplace;
    static std::string basicConstraintsOID;

    static std::vector<KeyUsageExtension::Usage> keyUsage;

    static MessageDigest::Algorithm mdAlgorithm;
};

/*
 * Initialization of variables used in the tests
 */
KeyPair* CertificateTest::keyPair = new RSAKeyPair(1024);
KeyPair* CertificateTest::signKeyPair = new RSAKeyPair(1024);

int CertificateTest::version = 2;

std::string CertificateTest::rdnSubjectCountry = "BR";
std::string CertificateTest::rdnSubjectState = "Florianopolis";
std::string CertificateTest::rdnSubjectLocality = "Santa Catarina";
std::string CertificateTest::rdnSubjectOrganization = "UFSC";
std::string CertificateTest::rdnSubjectCommonName = "Ronaldinho da Silva";

std::string CertificateTest::rdnIssuerCountry = "BR";
std::string CertificateTest::rdnIssuerState = "Sao Paulo";
std::string CertificateTest::rdnIssuerLocality = "Sao Paulo";
std::string CertificateTest::rdnIssuerOrganization = "Cert Signer";
std::string CertificateTest::rdnIssuerCommonName = "Ronaldo Cert Signer V3";

int CertificateTest::epochBefore = 1487889907;
int CertificateTest::epochAfter = 1665096307;
std::string CertificateTest::serialHex = "DC94A473D5C86891";

bool CertificateTest::basicConstrainsCA = true;
long CertificateTest::basicConstraintsPathLen = 2;
long CertificateTest::basicConstraintsPathLenReplace = 3;
std::string CertificateTest::basicConstraintsOID = "2.5.29.19";

std::vector<KeyUsageExtension::Usage> CertificateTest::keyUsage{KeyUsageExtension::DIGITAL_SIGNATURE,
                                                                       KeyUsageExtension::DATA_ENCIPHERMENT};

MessageDigest::Algorithm CertificateTest::mdAlgorithm = MessageDigest::SHA512;

/**
 * @brief 
 */
TEST_F(CertificateTest, SerialNumber) {
    fillSerialNumber(builder);
    checkSerialNumber(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateTest, PublicKey) {
    fillPublicKey(builder);
    checkPublicKey(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateTest, Version) {
    fillVersion(builder);
    checkVersion(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateTest, NotBefore) {
    fillNotBefore(builder);
    checkNotBefore(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateTest, NotAfter) {
    fillNotAfter(builder);
    checkNotAfter(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateTest, IssuerRDN) {
    fillIssuer(builder);
    checkIssuer(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateTest, SubjectRDN) {
    fillSubject(builder);
    checkSubject(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateTest, AlterSubject) {
    fillSubject(builder);
    alterSubject(builder);
    checkSubject(builder, CertificateTest::ALTER);
}

/**
 * @brief 
 */
TEST_F(CertificateTest, Extension) {
    fillExtensions(builder);
    checkExtensions(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateTest, ExtensionVector) {
    fillExtensions(builder, CertificateTest::VECTOR);
    checkExtensions(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateTest, GetExtension) {
    fillExtensions(builder);
    getExtension(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateTest, RemoveExtension) {
    fillExtensions(builder);
    removeExtension(builder);
}

/**
 * @brief 
 */
TEST_F(CertificateTest, RemoveExtensionOID) {
    fillExtensions(builder);
    removeExtension(builder, CertificateTest::OID);
}

/**
 * @brief 
 */
TEST_F(CertificateTest, ReplaceExtension) {
    fillExtensions(builder);
    replaceExtension(builder);
    checkExtensions(builder, CertificateTest::ALTER);
}

/**
 * @brief 
 */
TEST_F(CertificateTest, Sign) {

}