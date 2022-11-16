#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/certificate/CertificateRequest.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/ECDSAKeyPair.h>

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
        generateCertificate();
    }

    virtual void TearDown() {
        free(certificate);
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

    void createBasicConstraints(BasicConstraintsExtension *ext)
    {
        ext->setCa(basicConstrainsCA);
        ext->setPathLen(basicConstraintsPathLen);
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

    Certificate* signBuilder(CertificateBuilder *builder)
    {
        PrivateKey *privKey;

        privKey = signKeyPair->getPrivateKey();
        return builder->sign(*privKey, mdAlgorithm);
    }

    void generateCertificate()
    {
        CertificateBuilder *builder = new CertificateBuilder();

        fillCertificateBuilder(builder);
        certificate = signBuilder(builder);

        free(builder);
    }

    void checkSerialNumber(Certificate *cert)
    {
        BigInteger bi;
        bi = cert->getSerialNumberBigInt();
        ASSERT_EQ(bi.toHex(), serialHex);
    }

    void checkMessageDigest(Certificate *cert)
    {
        ASSERT_EQ(cert->getMessageDigestAlgorithm(), mdAlgorithm);
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

    void checkBasicConstraints(BasicConstraintsExtension *ext)
    {
        ASSERT_TRUE(ext->isCa());
        ASSERT_EQ(ext->getPathLen(), basicConstraintsPathLen);
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

    void checkCertificate(Certificate *cert)
    {
        checkSerialNumber(cert);
        checkMessageDigest(cert);
        checkPublicKey(cert);
        checkPublicKeyInfo(cert);
        checkVersion(cert);
        checkNotBefore(cert);
        checkNotAfter(cert);
        checkIssuer(cert);
        checkSubject(cert);
        checkExtensions(cert);
        checkSignature(cert);
    }

    void checkVersion(CertificateRequest *req)
    {
        ASSERT_EQ(req->getVersion(), 0);
    }

    void checkPublicKey(CertificateRequest *req)
    {
        PublicKey *pubKey = keyPair->getPublicKey();
        PublicKey *keyReq = req->getPublicKey();
        ASSERT_EQ(keyReq->getPemEncoded(), pubKey->getPemEncoded());

        free(pubKey);
        free(keyReq);
    }

    void checkRDNSequence(CertificateRequest *req)
    {
        RDNSequence rdn = req->getSubject();

        ASSERT_EQ(rdn.getEntries(RDNSequence::COUNTRY)[0], rdnSubjectCountry);
        ASSERT_EQ(rdn.getEntries(RDNSequence::STATE_OR_PROVINCE)[0], rdnSubjectState);
        ASSERT_EQ(rdn.getEntries(RDNSequence::LOCALITY)[0], rdnSubjectLocality);
        ASSERT_EQ(rdn.getEntries(RDNSequence::ORGANIZATION)[0], rdnSubjectOrganization);
        ASSERT_EQ(rdn.getEntries(RDNSequence::COMMON_NAME)[0], rdnSubjectCommonName);
    }

    void checkExtensions(CertificateRequest *req)
    {
        std::vector<Extension *> exts;
        BasicConstraintsExtension *bcExt;
        KeyUsageExtension *kuExt;

        exts = req->getExtensions();
        bcExt = new BasicConstraintsExtension(exts[0]->getX509Extension());
        kuExt = new KeyUsageExtension(exts[1]->getX509Extension());

        checkBasicConstraints(bcExt);
        checkKeyUsage(kuExt);
    }

    void checkSignature(CertificateRequest *req)
    {
        ASSERT_TRUE(req->verify());
        ASSERT_EQ(req->getMessageDigestAlgorithm(), mdAlgorithm);
    }

    void checkNewRequest(Certificate* cert)
    {
        CertificateRequest req;
        PrivateKey *privKey;

        privKey = keyPair->getPrivateKey();
        req = certificate->getNewCertificateRequest(*privKey, mdAlgorithm);

        checkVersion(&req);
        checkPublicKey(&req);
        checkRDNSequence(&req);
        checkSignature(&req);
    }

    static KeyPair *keyPair;
    static KeyPair *signKeyPair;
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
 * @brief Tests getting the SerialNumber from a Certificate
 */
TEST_F(CertificateTest, SerialNumber) {
    checkSerialNumber(certificate);
}

/**
 * @brief Tests getting the MessaDigest algorithm from a Certificate
 */
TEST_F(CertificateTest, MessageDigest) {
    checkMessageDigest(certificate);
}

/**
 * @brief Tests getting the PublicKey from a Certificate
 */
TEST_F(CertificateTest, PublicKey) {
    checkPublicKey(certificate);
}

/**
 * @brief Tests getting the PublicKeyInfo from a Certificate and comparing to the original KeyIdentifier
 */
TEST_F(CertificateTest, PublicKeyInfo) {
    checkPublicKeyInfo(certificate);
}

/**
 * @brief Tests getting the Version from a Certificate
 */
TEST_F(CertificateTest, Version) {
    checkVersion(certificate);
}

/**
 * @brief Tests getting the NotBefore DateTime from a Certificate
 */
TEST_F(CertificateTest, NotBefore) {
    checkNotBefore(certificate);
}

/**
 * @brief Tests getting the NotAfter DateTime from a Certificate
 */
TEST_F(CertificateTest, NotAfter) {
    checkNotAfter(certificate);
}

/**
 * @brief Tests getting the Issuer from a Certificate
 */
TEST_F(CertificateTest, Issuer) {
    checkIssuer(certificate);
}

/**
 * @brief Tests getting the Subject from a Certificate
 */
TEST_F(CertificateTest, Subject) {
    checkSubject(certificate);
}

/**
 * @brief Tests getting the Extensions from a Certificate
 */
TEST_F(CertificateTest, Extensions) {
    checkExtensions(certificate);
}

/**
 * @brief Tests getting a single Extension from a Certificate
 */
TEST_F(CertificateTest, Extension) {
    getExtension(certificate);
}

/**
 * @brief Tests verifying the signature from a Certificate
 */
TEST_F(CertificateTest, Signature) {
    checkSignature(certificate);
}

/**
 * @brief Tests creating a new CertificateRequest from the current Certificate
 */
TEST_F(CertificateTest, NewRequest) {
    checkNewRequest(certificate);
}

/**
 * @brief Tests creating a new Certificate Object from its X509 structure
 */
TEST_F(CertificateTest, FromX509) {
    Certificate *newCert;
    X509 *x509;

    x509 = certificate->getX509();
    newCert = new Certificate(x509);

    checkCertificate(newCert);
    free(newCert);
}

/**
 * @brief Tests creating a new Certificate Object from its PEM Encoding
 */
TEST_F(CertificateTest, FromPem) {
    Certificate *newCert;
    newCert = new Certificate(certificate->getPemEncoded());

    checkCertificate(newCert);
    free(newCert);
}

/**
 * @brief Tests creating a new Certificate Object from its DER Encoding
 */
TEST_F(CertificateTest, FromDer) {
    Certificate *newCert;
    ByteArray ba;

    ba = certificate->getDerEncoded();
    newCert = new Certificate(ba);

    checkCertificate(newCert);
    free(newCert);
}

/**
 * @brief Tests creating a new Certificate Object from another Certificate Object
 */
TEST_F(CertificateTest, FromCertificate) {
    Certificate *newCert;

    Certificate midCert(certificate->getPemEncoded());
    newCert = new Certificate(midCert);

    checkCertificate(newCert);
    free(newCert);
}

/**
 * @brief Tests assigning the value from a Certificate Object to another Certificate Object
 */
TEST_F(CertificateTest, OperatorAssign) {
    Certificate midCert(certificate->getPemEncoded());
    Certificate newCert = midCert;

    checkCertificate(&newCert);
}

/**
 * @brief Tests if both Certificate Objects are equal
 */
TEST_F(CertificateTest, OperatorEqual) {
    Certificate midCert(certificate->getPemEncoded());
    Certificate newCert = midCert;

    ASSERT_TRUE(midCert == newCert);
}

/**
 * @brief Tests if both Certificate Objects are not equal
 */
TEST_F(CertificateTest, OperatorNotEqual) {
    Certificate midCert(certificate->getPemEncoded());
    Certificate newCert = midCert;

    ASSERT_FALSE(midCert != newCert);
}