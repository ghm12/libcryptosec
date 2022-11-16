#include <libcryptosec/certificate/CertificateRequest.h>
#include <libcryptosec/RSAKeyPair.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe 
 */
class CertificateRequestTest : public ::testing::Test {

public:
enum Operation 
{
    NORMAL,
    REPLACE,
    REMOVE,
    NAME,
    OID,
    LIST,
    WRONGSIGN,
};

protected:
    virtual void SetUp() {
        req = new CertificateRequest();
    }

    virtual void TearDown() {
        free(req);
    }

    void fillVersion(CertificateRequest *req)
    {
        req->setVersion(version);
    }

    void fillPublicKey(CertificateRequest *req)
    {
        req->setPublicKey(*keyPair->getPublicKey());
    }

    void fillRDNSequence(CertificateRequest *req)
    {
        RDNSequence rdn;

        rdn.addEntry(RDNSequence::COUNTRY, rdnCountry);
        rdn.addEntry(RDNSequence::STATE_OR_PROVINCE, rdnState);
        rdn.addEntry(RDNSequence::LOCALITY, rdnLocality);
        rdn.addEntry(RDNSequence::ORGANIZATION, rdnOrganization);
        rdn.addEntry(RDNSequence::COMMON_NAME, rdnCommonName);

        ASSERT_NO_THROW(
            req->setSubject(rdn);
        );
    }

    void fillExtensions(CertificateRequest *req, Operation insertType = NORMAL)
    {
        BasicConstraintsExtension bcExt;
        KeyUsageExtension kuExt;
        std::vector<KeyUsageExtension::Usage>::iterator it;
        std::vector<Extension *> exts;

        bcExt.setCa(basicConstrainsCA);
        bcExt.setPathLen(basicConstraintsPathLen);

        for (it = keyUsage.begin(); it != keyUsage.end(); it++)
        {
            kuExt.setUsage(*it, true);
        }

        if (insertType == NORMAL)
        {
            req->addExtension(bcExt);
            req->addExtension(kuExt);
            return; 
        }

        exts.push_back(&kuExt);
        req->addExtension(bcExt);
        req->addExtensions(exts);
    }

    void fillRequest(CertificateRequest *req)
    {
        fillVersion(req);
        fillPublicKey(req);
        fillRDNSequence(req);
        fillExtensions(req);
        req->sign(*keyPair->getPrivateKey(), mdAlgorithm);
    }

    void testSign(CertificateRequest *req, Operation op = NORMAL)
    {
        fillRequest(req);

        if (op)
        {
            RSAKeyPair kp(1024);
            req->sign(*kp.getPrivateKey(), mdAlgorithm);
            return;
        }

        req->sign(*keyPair->getPrivateKey(), mdAlgorithm);
    }

    ByteArray getFingerPrint(CertificateRequest *req)
    {
        fillVersion(req);
        fillPublicKey(req);
        fillRDNSequence(req);

        return req->getFingerPrint(mdAlgorithm);
    }

    void getExtension(CertificateRequest *req)
    {
        std::vector<Extension *> exts;
        KeyUsageExtension kuExt;

        exts = req->getExtension(Extension::KEY_USAGE);
        kuExt = KeyUsageExtension(exts[0]->getX509Extension());

        checkKeyUsage(kuExt);
    }

    void replaceExtension(CertificateRequest *req)
    {
        BasicConstraintsExtension bc;

        bc.setCa(!basicConstrainsCA);
        bc.setPathLen(basicConstraintsPathLenReplace);

        req->replaceExtension(bc);
    }

    void removeExtension(CertificateRequest *req, Operation removalType = NAME)
    {
        std::vector<Extension *> exts;
        BasicConstraintsExtension bcExt;
        KeyUsageExtension kuExt;
        ObjectIdentifier oid;

        if (removalType == NAME)
        {
            ASSERT_NO_THROW(
                exts = req->removeExtension(Extension::KEY_USAGE);
                kuExt = KeyUsageExtension(exts[0]->getX509Extension());
            );

            ASSERT_EQ(kuExt.getTypeName(), Extension::KEY_USAGE);
            checkKeyUsage(kuExt);
            return;
        }

        oid = ObjectIdentifierFactory::getObjectIdentifier(basicConstraintsOID);

        ASSERT_NO_THROW(
            exts = req->removeExtension(oid);
            bcExt = BasicConstraintsExtension(exts[0]->getX509Extension());
        );

        ASSERT_EQ(bcExt.getTypeName(), Extension::BASIC_CONSTRAINTS);

        ASSERT_EQ(req->getExtensions().size(), 0);
    }

    void checkVersion(CertificateRequest *req)
    {
        ASSERT_EQ(req->getVersion(), version);
    }

    void checkPublicKey(CertificateRequest *req)
    {
        PublicKey *pubKey = keyPair->getPublicKey();
        PublicKey *keyReq = req->getPublicKey();
        ASSERT_EQ(keyReq->getPemEncoded(), pubKey->getPemEncoded());
    }

    void checkPublicKeyInfo(CertificateRequest *req)
    {
        ByteArray fromReq, fromKey;
        PublicKey *pubKey = keyPair->getPublicKey();

        fromKey = pubKey->getKeyIdentifier();
        fromReq = req->getPublicKeyInfo();

        ASSERT_EQ(fromKey.toHex(), fromReq.toHex());
    }

    void checkRDNSequence(CertificateRequest *req)
    {
        RDNSequence rdn = req->getSubject();

        ASSERT_EQ(rdn.getEntries(RDNSequence::COUNTRY)[0], rdnCountry);
        ASSERT_EQ(rdn.getEntries(RDNSequence::STATE_OR_PROVINCE)[0], rdnState);
        ASSERT_EQ(rdn.getEntries(RDNSequence::LOCALITY)[0], rdnLocality);
        ASSERT_EQ(rdn.getEntries(RDNSequence::ORGANIZATION)[0], rdnOrganization);
        ASSERT_EQ(rdn.getEntries(RDNSequence::COMMON_NAME)[0], rdnCommonName);
    }

    void checkExtensions(CertificateRequest *req, Operation op = NORMAL)
    {
        std::vector<Extension *> exts;
        BasicConstraintsExtension bcExt;
        KeyUsageExtension kuExt;

        exts = req->getExtensions();
        bcExt = BasicConstraintsExtension(exts[0]->getX509Extension());

        if (op == NORMAL)
        {
            ASSERT_EQ(bcExt.isCa(), basicConstrainsCA);
            ASSERT_EQ(bcExt.getPathLen(), basicConstraintsPathLen);
        } else {
            ASSERT_EQ(bcExt.isCa(), !basicConstrainsCA);
            ASSERT_EQ(bcExt.getPathLen(), basicConstraintsPathLenReplace);
        }

        if (op == REMOVE)
        {
            ASSERT_EQ(exts.size(), 1);
            return;
        }

        kuExt = KeyUsageExtension(exts[1]->getX509Extension());

        for (int i = 0; i < 9; i++)
        {
            checkKeyUsage(kuExt);
        }
    }

    void checkKeyUsage(KeyUsageExtension kuExt)
    {
        for (int i = 0; i < 9; i++)
        {
            KeyUsageExtension::Usage usage = (KeyUsageExtension::Usage) i;

            if (std::find(keyUsage.begin(), keyUsage.end(), usage) != keyUsage.end())
            {
                ASSERT_TRUE(kuExt.getUsage(usage));
                continue;
            }

            ASSERT_FALSE(kuExt.getUsage(usage));
        }
    }

    void checkSignature(CertificateRequest *req)
    {
        ASSERT_TRUE(req->verify());
        ASSERT_EQ(req->getMessageDigestAlgorithm(), mdAlgorithm);
    }

    void checkRequest(CertificateRequest *req)
    {
        checkVersion(req);
        checkPublicKey(req);
        checkRDNSequence(req);
        checkExtensions(req);
        checkSignature(req);
    }

    static KeyPair *keyPair;
    CertificateRequest *req;

    static int version;

    static std::string rdnCountry;
    static std::string rdnState;
    static std::string rdnLocality;
    static std::string rdnOrganization;
    static std::string rdnCommonName;

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
KeyPair* CertificateRequestTest::keyPair = new RSAKeyPair(1024);

int CertificateRequestTest::version = 2;

std::string CertificateRequestTest::rdnCountry = "BR";
std::string CertificateRequestTest::rdnState = "Florianopolis";
std::string CertificateRequestTest::rdnLocality = "Santa Catarina";
std::string CertificateRequestTest::rdnOrganization = "UFSC";
std::string CertificateRequestTest::rdnCommonName = "Ronaldinho da Silva";

bool CertificateRequestTest::basicConstrainsCA = true;
long CertificateRequestTest::basicConstraintsPathLen = 2;
long CertificateRequestTest::basicConstraintsPathLenReplace = 3;
std::string CertificateRequestTest::basicConstraintsOID = "2.5.29.19";

std::vector<KeyUsageExtension::Usage> CertificateRequestTest::keyUsage{KeyUsageExtension::DIGITAL_SIGNATURE,
                                                                       KeyUsageExtension::DATA_ENCIPHERMENT};

MessageDigest::Algorithm CertificateRequestTest::mdAlgorithm = MessageDigest::SHA512;

/**
 * @brief Tests set and get for CertificateRequest Version
 */
TEST_F(CertificateRequestTest, Version) {
    fillVersion(req);
    checkVersion(req);
}

/**
 * @brief Tests set and get for CertificateRequest Subject
 */
TEST_F(CertificateRequestTest, Subject) {
    fillRDNSequence(req);
    checkRDNSequence(req);
}

/**
 * @brief Tests set and get for CertificateRequest PublicKey
 */
TEST_F(CertificateRequestTest, PublicKey) {
    fillPublicKey(req);
    checkPublicKey(req);
}

/**
 * @brief Tests PublicKeyInfo
 */
// TEST_F(CertificateRequestTest, PublicKeyInfo) {
//     fillPublicKey(req);
//     checkPublicKeyInfo(req);
// }

/**
 * @brief Tests all extension features within a CertificateRequest such as set, get,
 *        replace and remove
 */
TEST_F(CertificateRequestTest, Extensions) {
    fillExtensions(req);
    checkExtensions(req);
    getExtension(req);

    replaceExtension(req);
    checkExtensions(req, CertificateRequestTest::REPLACE);

    removeExtension(req);
    checkExtensions(req, CertificateRequestTest::REMOVE);

    removeExtension(req, CertificateRequestTest::OID);

    fillExtensions(req, CertificateRequestTest::LIST);
    checkExtensions(req);
}

/**
 * @brief Tests a CertificateRequest FingerPrint value
 */
TEST_F(CertificateRequestTest, FingerPrint) {
    ByteArray ba, baNew;

    ba = getFingerPrint(req);

    req = new CertificateRequest();
    baNew = getFingerPrint(req);

    ASSERT_EQ(ba.toString(), baNew.toString());

    req = new CertificateRequest();
    fillExtensions(req);
    baNew = getFingerPrint(req);

    ASSERT_NE(ba.toString(), baNew.toString());
}

/**
 * @brief Tests a CertificateRequest signature and verification
 */
TEST_F(CertificateRequestTest, Sign) {
    ASSERT_FALSE(req->isSigned());

    testSign(req);
    ASSERT_TRUE(req->isSigned());
    ASSERT_TRUE(req->verify());

    req = new CertificateRequest();

    testSign(req, CertificateRequestTest::WRONGSIGN);
    ASSERT_TRUE(req->isSigned());
    ASSERT_FALSE(req->verify());
}

/**
 * @brief Tests creating a CertificateRequest from a X509_REQ structure
 */
TEST_F(CertificateRequestTest, FromX509) {
    CertificateRequest newReq;
    X509_REQ *x509;

    fillRequest(req);
    checkRequest(req);

    x509 = req->getX509Req();
    newReq = CertificateRequest(x509);

    checkRequest(&newReq);
}

/**
 * @brief Tests creating a CertificareRequest from its PEM Encoding
 */
TEST_F(CertificateRequestTest, FromPem) {
    CertificateRequest newReq;
    std::string pem;

    fillRequest(req);
    checkRequest(req);

    pem = req->getPemEncoded();
    newReq = CertificateRequest(pem);

    checkRequest(&newReq);
}

/**
 * @brief Tests creating a CertificareRequest from its DER Encoding
 */
TEST_F(CertificateRequestTest, FromDer) {
    CertificateRequest newReq;
    ByteArray der;

    fillRequest(req);
    checkRequest(req);

    der = req->getDerEncoded();
    newReq = CertificateRequest(der);

    checkRequest(&newReq);
}

/**
 * @brief Tests creating a CertificareRequest from another CertificateRequest
 */
TEST_F(CertificateRequestTest, FromRequest) {
    CertificateRequest newReq;
    std::string pemEncoded;

    fillRequest(req);
    checkRequest(req);

    pemEncoded = req->getPemEncoded();
    newReq = CertificateRequest(pemEncoded);

    checkRequest(&newReq);
}

/**
 * @brief Tests assigning a CertificateRequest object value to another object
 */
TEST_F(CertificateRequestTest, AssignOperator) {
    std::string pemEncoded;
    CertificateRequest newReq, foo;

    fillRequest(req);
    checkRequest(req);

    pemEncoded = req->getPemEncoded();
    foo = CertificateRequest(pemEncoded);
    newReq = foo;

    checkRequest(&newReq);
}
