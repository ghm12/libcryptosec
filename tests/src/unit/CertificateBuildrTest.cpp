#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/certificate/CertificateRequest.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/ECDSAKeyPair.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe 
 */
class CertificateBuildrTest : public ::testing::Test {

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

    void fillIssuer(CertificateBuilder *builder, X509 *x509)
    {
        builder->setIssuer(x509);
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

    void fillSubject(CertificateBuilder *builder, X509_REQ *req)
    {
        builder->setSubject(req);
    }

    void alterSubject(CertificateBuilder *builder)
    {
        RDNSequence rdn;

        rdn.addEntry(RDNSequence::COUNTRY, rdnIssuerCountry);
        rdn.addEntry(RDNSequence::STATE_OR_PROVINCE, rdnIssuerState);
        rdn.addEntry(RDNSequence::LOCALITY, rdnIssuerLocality);
        rdn.addEntry(RDNSequence::ORGANIZATION, rdnIssuerOrganization);
        rdn.addEntry(RDNSequence::COMMON_NAME, rdnIssuerCommonName);

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

    void testECDSAParameters(CertificateBuilder *builder)
    {
        ECDSAKeyPair ecdsa(AsymmetricKey::SECG_SECP256K1);

        ASSERT_FALSE(builder->isIncludeEcdsaParameters());

        builder->setIncludeEcdsaParameters(true);
        ASSERT_TRUE(builder->isIncludeEcdsaParameters());

        builder->setPublicKey(*ecdsa.getPublicKey());
        builder->includeEcdsaParameters();
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

    void checkPublicKeyInfo(CertificateBuilder *builder)
    {
        ByteArray fromBuilder, fromKey;
        PublicKey *pubKey = keyPair->getPublicKey();

        fromKey = pubKey->getKeyIdentifier();
        fromBuilder = builder->getPublicKeyInfo();

        ASSERT_EQ(fromKey.toHex(), fromBuilder.toHex());
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
            ASSERT_EQ(rdn.getEntries(RDNSequence::COMMON_NAME)[0], rdnSubjectCommonName);
            return;
        }

        ASSERT_EQ(rdn.getEntries(RDNSequence::COUNTRY)[0], rdnIssuerCountry);
        ASSERT_EQ(rdn.getEntries(RDNSequence::STATE_OR_PROVINCE)[0], rdnIssuerState);
        ASSERT_EQ(rdn.getEntries(RDNSequence::LOCALITY)[0], rdnIssuerLocality);
        ASSERT_EQ(rdn.getEntries(RDNSequence::ORGANIZATION)[0], rdnIssuerOrganization);
        ASSERT_EQ(rdn.getEntries(RDNSequence::COMMON_NAME)[0], rdnIssuerCommonName);

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

    void checkCertificateBuilder(CertificateBuilder *builder)
    {
        checkSerialNumber(builder);
        checkPublicKey(builder);
        checkPublicKeyInfo(builder);
        checkVersion(builder);
        checkNotBefore(builder);
        checkNotAfter(builder);
        checkIssuer(builder);
        checkSubject(builder);
        checkExtensions(builder);
    }

    void generateCertificate()
    {
        fillCertificateBuilder(builder);
        signBuilder(builder);
    }

    void checkSerialNumber(Certificate *cert)
    {
        BigInteger bi;
        bi = cert->getSerialNumberBigInt();
        ASSERT_EQ(bi.toHex(), serialHex);
    }

    void checkPublicKey(Certificate *cert)
    {
        PublicKey *pubKey = keyPair->getPublicKey();
        PublicKey *keyCert = cert->getPublicKey();

        ASSERT_EQ(keyCert->getPemEncoded(), pubKey->getPemEncoded());

        free(pubKey);
        free(keyCert);
    }

    void checkPublicKeyInfo(Certificate *cert)
    {
        ByteArray crt, subject;
        PublicKey *pubKey = keyPair->getPublicKey();

        subject = pubKey->getKeyIdentifier();
        crt = cert->getPublicKeyInfo();

        ASSERT_EQ(crt.toHex(), subject.toHex());
    }

    void checkVersion(Certificate *cert)
    {
        ASSERT_EQ(cert->getVersion(), version); 
    }

    void checkNotBefore(Certificate *cert)
    {
        DateTime dt;
        dt = cert->getNotBefore();

        ASSERT_EQ(dt.getDateTime(), epochBefore);
    }

    void checkNotAfter(Certificate *cert)
    {
        DateTime dt;
        dt = cert->getNotAfter();

        ASSERT_EQ(dt.getDateTime(), epochAfter);
    }

    void checkIssuer(Certificate *cert)
    {
        RDNSequence rdn;
        rdn = cert->getIssuer();

        ASSERT_EQ(rdn.getEntries(RDNSequence::COUNTRY)[0], rdnIssuerCountry);
        ASSERT_EQ(rdn.getEntries(RDNSequence::STATE_OR_PROVINCE)[0], rdnIssuerState);
        ASSERT_EQ(rdn.getEntries(RDNSequence::LOCALITY)[0], rdnIssuerLocality);
        ASSERT_EQ(rdn.getEntries(RDNSequence::ORGANIZATION)[0], rdnIssuerOrganization);
        ASSERT_EQ(rdn.getEntries(RDNSequence::COMMON_NAME)[0], rdnIssuerCommonName);
    }

    void checkSubject(Certificate *cert)
    {
        RDNSequence rdn;
        rdn = cert->getSubject();

        ASSERT_EQ(rdn.getEntries(RDNSequence::COUNTRY)[0], rdnSubjectCountry);
        ASSERT_EQ(rdn.getEntries(RDNSequence::STATE_OR_PROVINCE)[0], rdnSubjectState);
        ASSERT_EQ(rdn.getEntries(RDNSequence::LOCALITY)[0], rdnSubjectLocality);
        ASSERT_EQ(rdn.getEntries(RDNSequence::ORGANIZATION)[0], rdnSubjectOrganization);  
        ASSERT_EQ(rdn.getEntries(RDNSequence::COMMON_NAME)[0], rdnSubjectCommonName);
    }

    void checkExtensions(Certificate *cert)
    {
        BasicConstraintsExtension *bcExt;
        KeyUsageExtension *kuExt;
        std::vector<Extension *> exts;

        exts = cert->getExtensions();
        bcExt = new BasicConstraintsExtension(exts[0]->getX509Extension());
        kuExt = new KeyUsageExtension(exts[1]->getX509Extension());
        
        checkBasicConstraints(bcExt);
        checkKeyUsage(kuExt);
    }

    void getExtension(Certificate *cert)
    {
        BasicConstraintsExtension *bcExt;
        KeyUsageExtension *kuExt;
        Extension *ext;

        ext = cert->getExtension(Extension::BASIC_CONSTRAINTS)[0];
        bcExt = new BasicConstraintsExtension(ext->getX509Extension());

        ext = cert->getExtension(Extension::KEY_USAGE)[0];
        kuExt = new KeyUsageExtension(ext->getX509Extension());

        checkBasicConstraints(bcExt);
        checkKeyUsage(kuExt);
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
KeyPair* CertificateBuildrTest::keyPair = new RSAKeyPair(1024);
KeyPair* CertificateBuildrTest::signKeyPair = new RSAKeyPair(1024);

int CertificateBuildrTest::version = 2;

std::string CertificateBuildrTest::rdnSubjectCountry = "BR";
std::string CertificateBuildrTest::rdnSubjectState = "Florianopolis";
std::string CertificateBuildrTest::rdnSubjectLocality = "Santa Catarina";
std::string CertificateBuildrTest::rdnSubjectOrganization = "UFSC";
std::string CertificateBuildrTest::rdnSubjectCommonName = "Ronaldinho da Silva";

std::string CertificateBuildrTest::rdnIssuerCountry = "BR";
std::string CertificateBuildrTest::rdnIssuerState = "Sao Paulo";
std::string CertificateBuildrTest::rdnIssuerLocality = "Sao Paulo";
std::string CertificateBuildrTest::rdnIssuerOrganization = "Cert Signer";
std::string CertificateBuildrTest::rdnIssuerCommonName = "Ronaldo Cert Signer V3";

int CertificateBuildrTest::epochBefore = 1487889907;
int CertificateBuildrTest::epochAfter = 1665096307;
std::string CertificateBuildrTest::serialHex = "DC94A473D5C86891";

bool CertificateBuildrTest::basicConstrainsCA = true;
long CertificateBuildrTest::basicConstraintsPathLen = 2;
long CertificateBuildrTest::basicConstraintsPathLenReplace = 3;
std::string CertificateBuildrTest::basicConstraintsOID = "2.5.29.19";

std::vector<KeyUsageExtension::Usage> CertificateBuildrTest::keyUsage{KeyUsageExtension::DIGITAL_SIGNATURE,
                                                                       KeyUsageExtension::DATA_ENCIPHERMENT};

MessageDigest::Algorithm CertificateBuildrTest::mdAlgorithm = MessageDigest::SHA512;

/**
 * @brief Tests set and get for CertificateBuilder SerialNumber
 */
TEST_F(CertificateBuildrTest, SerialNumber) {
    fillSerialNumber(builder);
    checkSerialNumber(builder);
}

/**
 * @brief Tests set and get for CertificateBuilder PublicKey
 */
TEST_F(CertificateBuildrTest, PublicKey) {
    fillPublicKey(builder);
    checkPublicKey(builder);
}

/**
 * @brief Tests PublicKeyInfo's content compared to the Key Identifier
 */
TEST_F(CertificateBuildrTest, PublicKeyInfo) {
    fillPublicKey(builder);
    checkPublicKeyInfo(builder);
}

/**
 * @brief Tests set and get for CertificateBuilder Version
 */
TEST_F(CertificateBuildrTest, Version) {
    fillVersion(builder);
    checkVersion(builder);
}

/**
 * @brief Tests set and get for CertificateBuilder NotBefore
 */
TEST_F(CertificateBuildrTest, NotBefore) {
    fillNotBefore(builder);
    checkNotBefore(builder);
}

/**
 * @brief Tests set and get for CertificateBuilder NotAfter
 */
TEST_F(CertificateBuildrTest, NotAfter) {
    fillNotAfter(builder);
    checkNotAfter(builder);
}

/**
 * @brief Tests set and get for CertificateBuilder Issuer from a RDNSequence
 */
TEST_F(CertificateBuildrTest, IssuerRDN) {
    fillIssuer(builder);
    checkIssuer(builder);
}

/**
 * @brief Tests set and get for CertificateBuilder Issuer from a X509 structure
 */
TEST_F(CertificateBuildrTest, IssuerX509) {
    X509 *x509;

    fillCertificateBuilder(builder);
    alterSubject(builder);
    signBuilder(builder);

    x509 = certificate->getX509();
    builder = new CertificateBuilder();

    fillIssuer(builder, x509);
    checkIssuer(builder);
}

/**
 * @brief Tests set and get for CertificateBuilder Subject from a RDNSequence
 */
TEST_F(CertificateBuildrTest, SubjectRDN) {
    fillSubject(builder);
    checkSubject(builder);
}

/**
 * @brief Tests set and get for CertificateBuilder Subject from a X509_REQ structure
 */
TEST_F(CertificateBuildrTest, SubjectREQ) {
    CertificateRequest certReq;
    X509_REQ *req;

    fillCertificateBuilder(builder);
    signBuilder(builder);

    certReq = certificate->getNewCertificateRequest(*CertificateBuildrTest::keyPair->getPrivateKey(), 
                                                 CertificateBuildrTest::mdAlgorithm);
    req = certReq.getX509Req();
    builder = new CertificateBuilder();

    fillSubject(builder, req);
    checkSubject(builder);
}

/**
 * @brief Tests modifying a subject from a CertificateBuilder
 */
TEST_F(CertificateBuildrTest, AlterSubject) {
    fillSubject(builder);
    alterSubject(builder);
    checkSubject(builder, CertificateBuildrTest::ALTER);
}

/**
 * @brief Tests set and get for CertificateBuilder Extension
 */
TEST_F(CertificateBuildrTest, Extension) {
    fillExtensions(builder);
    checkExtensions(builder);
}

/**
 * @brief Tests set and get for CertificateBuilder Extension from a vector
 */
TEST_F(CertificateBuildrTest, ExtensionVector) {
    fillExtensions(builder, CertificateBuildrTest::VECTOR);
    checkExtensions(builder);
}

/**
 * @brief Tests getting a single extension from CertificateBuilder
 */
TEST_F(CertificateBuildrTest, GetExtension) {
    fillExtensions(builder);
    getExtension(builder);
}

/**
 * @brief Tests removing a extension from CertificateBuilder
 */
TEST_F(CertificateBuildrTest, RemoveExtension) {
    fillExtensions(builder);
    removeExtension(builder);
}

/**
 * @brief Tests removing a extension from CertificateBuilder using its OID
 */
TEST_F(CertificateBuildrTest, RemoveExtensionOID) {
    fillExtensions(builder);
    removeExtension(builder, CertificateBuildrTest::OID);
}

/**
 * @brief Tests replacing a extension from CertificateBuilder
 */
TEST_F(CertificateBuildrTest, ReplaceExtension) {
    fillExtensions(builder);
    replaceExtension(builder);
    checkExtensions(builder, CertificateBuildrTest::ALTER);
}

/**
 * @brief Tests including ECDSA Parameters for a CertificateBuilder
 */
TEST_F(CertificateBuildrTest, IncludeECDSAParameters) {
    testECDSAParameters(builder);
}

/**
 * @brief Tests signing and verifying a CertificateBuilder
 */
TEST_F(CertificateBuildrTest, Sign) {
    fillCertificateBuilder(builder);
    signBuilder(builder);
    checkSignature(certificate);
}

/**
 * @brief Tests creating a CertificateBuilder from its PEM Encoding
 */
TEST_F(CertificateBuildrTest, FromPem) {
    CertificateBuilder *newBuilder;

    fillCertificateBuilder(builder);
    signBuilder(builder);

    newBuilder = new CertificateBuilder(certificate->getPemEncoded());

    checkCertificateBuilder(newBuilder);
}

/**
 * @brief Tests creating a CertificateBuilder from its DER Encoding
 */
TEST_F(CertificateBuildrTest, FromDer) {
    CertificateBuilder *newBuilder;
    ByteArray ba;

    fillCertificateBuilder(builder);
    signBuilder(builder);

    ba = certificate->getDerEncoded();
    newBuilder = new CertificateBuilder(ba);

    checkCertificateBuilder(newBuilder);
}

/**
 * @brief Tests creating a CertificateBuilder from another CertificateBuilder Object
 */
TEST_F(CertificateBuildrTest, FromBuilder) {
    CertificateBuilder *newBuilder;
    CertificateBuilder midBuilder;

    fillCertificateBuilder(builder);
    signBuilder(builder);

    midBuilder = CertificateBuilder(certificate->getPemEncoded());
    newBuilder = new CertificateBuilder(midBuilder);

    checkCertificateBuilder(newBuilder);
}

/**
 * @brief Tests assigning a CertificateBuilder object value to another object
 */
TEST_F(CertificateBuildrTest, OperatorAssign) {
    CertificateBuilder newBuilder;
    CertificateBuilder midBuilder;

    fillCertificateBuilder(builder);
    signBuilder(builder);

    midBuilder = CertificateBuilder(certificate->getPemEncoded());
    newBuilder = midBuilder;

    checkCertificateBuilder(&newBuilder);
}
