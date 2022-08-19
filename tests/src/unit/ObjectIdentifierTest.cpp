#include <libcryptosec/certificate/ObjectIdentifierFactory.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários das classes ObjectIdentifier e ObjectIdentifierFactory
 */
class ObjectIdentifierTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    static int oidNid;
    static int nid;
    static std::string nidOid;
    static std::string nidName;
    static std::string nidXml;
    static std::string oid;
    static std::string oidName;
    static std::string oidXml;
    static std::string createOid;
    static std::string createName;
    static std::string createXml;
};

/*
 * Initialization of variables used in the tests
 */
int ObjectIdentifierTest::nid = 14;
std::string ObjectIdentifierTest::nidOid = "2.5.4.6";
std::string ObjectIdentifierTest::nidName = "C";
std::string ObjectIdentifierTest::nidXml = "<oid>2.5.4.6</oid>\n";

int ObjectIdentifierTest::oidNid = 13;
std::string ObjectIdentifierTest::oid = "2.5.4.3";
std::string ObjectIdentifierTest::oidName = "CN";
std::string ObjectIdentifierTest::oidXml = "<oid>2.5.4.3</oid>\n";

std::string ObjectIdentifierTest::createOid = "2.16.76.1.3.3";
std::string ObjectIdentifierTest::createName = "CNPJ";
std::string ObjectIdentifierTest::createXml = "<oid>2.16.76.1.3.3</oid>\n";

/**
 * @brief Tests getter and values of an ObjectIdentifier from its nid value
 */
TEST_F(ObjectIdentifierTest, GetByNid) {
    ObjectIdentifier oid = ObjectIdentifierFactory::getObjectIdentifier(ObjectIdentifierTest::nid);

    ASSERT_EQ(oid.getOid(), ObjectIdentifierTest::nidOid);
    ASSERT_EQ(oid.getNid(), ObjectIdentifierTest::nid);
    ASSERT_EQ(oid.getName(), ObjectIdentifierTest::nidName);
    ASSERT_EQ(oid.getXmlEncoded(), ObjectIdentifierTest::nidXml);
}

/**
 * @brief Tests getter and values of an ObjectIdentifier from its oid value
 */
TEST_F(ObjectIdentifierTest, GetByOid) {
    ObjectIdentifier oid = ObjectIdentifierFactory::getObjectIdentifier(ObjectIdentifierTest::oid);

    ASSERT_EQ(oid.getOid(), ObjectIdentifierTest::oid);
    ASSERT_EQ(oid.getNid(), ObjectIdentifierTest::oidNid);
    ASSERT_EQ(oid.getName(), ObjectIdentifierTest::oidName);
    ASSERT_EQ(oid.getXmlEncoded(), ObjectIdentifierTest::oidXml);
}

/**
 * @brief Tests creation and values of an ObjectIdentifier from it's oid and name value
 */
TEST_F(ObjectIdentifierTest, createOid) {
    ObjectIdentifier oid = ObjectIdentifierFactory::createObjectIdentifier(ObjectIdentifierTest::createOid, ObjectIdentifierTest::createName);

    ASSERT_EQ(oid.getOid(), ObjectIdentifierTest::createOid);
    ASSERT_EQ(oid.getName(), ObjectIdentifierTest::createName);
    ASSERT_EQ(oid.getXmlEncoded(), ObjectIdentifierTest::createXml);
}

/**
 * @brief Tests creating an ObjectIdentifier from an ASN1_OBJECT
 */
TEST_F(ObjectIdentifierTest, createFromASN1) {
    ObjectIdentifier oid = ObjectIdentifierFactory::getObjectIdentifier(ObjectIdentifierTest::oid);
    ASN1_OBJECT *obj = oid.getObjectIdentifier();

    ObjectIdentifier oidObj = ObjectIdentifier(obj);

    ASSERT_EQ(oidObj.getOid(), ObjectIdentifierTest::oid);
    ASSERT_EQ(oidObj.getNid(), ObjectIdentifierTest::oidNid);
    ASSERT_EQ(oidObj.getName(), ObjectIdentifierTest::oidName);
    ASSERT_EQ(oidObj.getXmlEncoded(), ObjectIdentifierTest::oidXml);
}

/**
 * @brief Tests creating an ObjectIdentifier from assignment of another ObjectIdentifier
 */
TEST_F(ObjectIdentifierTest, createFromOID) {
    ObjectIdentifier oid = ObjectIdentifierFactory::getObjectIdentifier(ObjectIdentifierTest::oid);
    ObjectIdentifier oidAssign = oid;

    ASSERT_EQ(oidAssign.getOid(), ObjectIdentifierTest::oid);
    ASSERT_EQ(oidAssign.getNid(), ObjectIdentifierTest::oidNid);
    ASSERT_EQ(oidAssign.getName(), ObjectIdentifierTest::oidName);
    ASSERT_EQ(oidAssign.getXmlEncoded(), ObjectIdentifierTest::oidXml);
}