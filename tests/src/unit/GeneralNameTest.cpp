#include <libcryptosec/certificate/GeneralName.h>
#include <libcryptosec/certificate/GeneralNames.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe GeneralName e GeneralNames
 */
class GeneralNameTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    static std::string otherNameOID;
    static std::string otherNameData;
    static std::string rfcName;
    static std::string dnsName;
    static std::string directoryCN;
    static std::string uriName;
    static std::string ipAddress;
    static std::string ridName;
};

/*
 * Initialization of variables used in the tests
 */
std::string GeneralNameTest::otherNameOID = "2.16.76.1.3.3";
std::string GeneralNameTest::otherNameData = "01234567891011";
std::string GeneralNameTest::rfcName = "example@mail.com";
std::string GeneralNameTest::dnsName = "8.8.8.8";
std::string GeneralNameTest::directoryCN = "Example Name";
std::string GeneralNameTest::uriName = "www.example.com";
std::string GeneralNameTest::ipAddress = "127.0.0.1";
std::string GeneralNameTest::ridName = "2.5.4.3";

/**
 * @brief Tests GeneralName Other Name funcionalities
 */
TEST_F(GeneralNameTest, OtherName) {
    GeneralName gn;
    GeneralName fromGn;
    GENERAL_NAME* gnX509;
    pair< std::string, std::string > otherName;

    gn.setOtherName(GeneralNameTest::otherNameOID, GeneralNameTest::otherNameData);
    gnX509 = gn.getGeneralName();
    fromGn = GeneralName(gnX509);

    otherName = gn.getOtherName();
    ASSERT_EQ(otherName.first, GeneralNameTest::otherNameOID);
    ASSERT_EQ(otherName.second, GeneralNameTest::otherNameData);
    ASSERT_EQ(gn.getType(), GeneralName::OTHER_NAME);

    otherName = fromGn.getOtherName();
    ASSERT_EQ(otherName.first, GeneralNameTest::otherNameOID);
    ASSERT_EQ(otherName.second, GeneralNameTest::otherNameData);
    ASSERT_EQ(fromGn.getType(), GeneralName::OTHER_NAME);
}

/**
 * @brief Tests Generalname RFC 822 Name functionalities
 */
TEST_F(GeneralNameTest, Rfc822Name) {
    GeneralName gn;
    GeneralName fromGn;
    GENERAL_NAME* gnX509;

    gn.setRfc822Name(GeneralNameTest::rfcName);
    gnX509 = gn.getGeneralName();
    fromGn = GeneralName(gnX509);

    ASSERT_EQ(gn.getRfc822Name(), GeneralNameTest::rfcName);
    ASSERT_EQ(gn.getType(), GeneralName::RFC_822_NAME);

    ASSERT_EQ(fromGn.getRfc822Name(), GeneralNameTest::rfcName);
    ASSERT_EQ(fromGn.getType(), GeneralName::RFC_822_NAME);
}

/**
 * @brief Tests GeneralName DNS Name functionalities
 */
TEST_F(GeneralNameTest, DnsName) {
    GeneralName gn;
    GeneralName fromGn;
    GENERAL_NAME* gnX509;

    gn.setDnsName(GeneralNameTest::dnsName);
    gnX509 = gn.getGeneralName();
    fromGn = GeneralName(gnX509);

    ASSERT_EQ(gn.getDnsName(), GeneralNameTest::dnsName);
    ASSERT_EQ(gn.getType(), GeneralName::DNS_NAME);

    ASSERT_EQ(fromGn.getDnsName(), GeneralNameTest::dnsName);
    ASSERT_EQ(fromGn.getType(), GeneralName::DNS_NAME);
}

/**
 * @brief Tests GeneralName Directory Name functionalities
 */
TEST_F(GeneralNameTest, DirectoryName) {
    RDNSequence rdn;
    GeneralName gn;
    GeneralName fromGn;
    GENERAL_NAME* gnX509;
    std::vector<std::string> entries;

    rdn.addEntry(RDNSequence::COMMON_NAME, GeneralNameTest::directoryCN);
    gn.setDirectoryName(rdn);
    gnX509 = gn.getGeneralName();
    fromGn = GeneralName(gnX509);

    entries = gn.getDirectoryName().getEntries(RDNSequence::COMMON_NAME);
    ASSERT_EQ(entries[0], GeneralNameTest::directoryCN);
    ASSERT_EQ(gn.getType(), GeneralName::DIRECTORY_NAME);

    entries = fromGn.getDirectoryName().getEntries(RDNSequence::COMMON_NAME);
    ASSERT_EQ(entries[0], GeneralNameTest::directoryCN);
    ASSERT_EQ(fromGn.getType(), GeneralName::DIRECTORY_NAME);
}

/**
 * @brief Tests General Name Uniform Resource Identifier functionalities
 */
TEST_F(GeneralNameTest, UniformResourceIdentifier) {
    GeneralName gn;
    GeneralName fromGn;
    GENERAL_NAME* gnX509;

    gn.setUniformResourceIdentifier(GeneralNameTest::uriName);
    gnX509 = gn.getGeneralName();
    fromGn = GeneralName(gnX509);

    ASSERT_EQ(gn.getUniformResourceIdentifier(), GeneralNameTest::uriName);
    ASSERT_EQ(gn.getType(), GeneralName::UNIFORM_RESOURCE_IDENTIFIER);

    ASSERT_EQ(fromGn.getUniformResourceIdentifier(), GeneralNameTest::uriName);
    ASSERT_EQ(fromGn.getType(), GeneralName::UNIFORM_RESOURCE_IDENTIFIER);
}

/**
 * @brief Tests General Name IP Address functionalities
 */
TEST_F(GeneralNameTest, IPAddress) {
    GeneralName gn;
    GeneralName fromGn;
    GENERAL_NAME* gnX509;

    gn.setIpAddress(GeneralNameTest::ipAddress);
    gnX509 = gn.getGeneralName();
    fromGn = GeneralName(gnX509);

    ASSERT_EQ(gn.getIpAddress(), GeneralNameTest::ipAddress);
    ASSERT_EQ(gn.getType(), GeneralName::IP_ADDRESS);

    ASSERT_EQ(fromGn.getIpAddress(), GeneralNameTest::ipAddress);
    ASSERT_EQ(fromGn.getType(), GeneralName::IP_ADDRESS);
}

/**
 * @brief Tests General Name Registered ID functionalities
 */
TEST_F(GeneralNameTest, RegisteredID) {
    ObjectIdentifier oid;
    GeneralName gn;
    GeneralName fromGn;
    GENERAL_NAME* gnX509;

    oid = ObjectIdentifierFactory::getObjectIdentifier(GeneralNameTest::ridName);
    gn.setRegisteredId(oid);
    gnX509 = gn.getGeneralName();
    fromGn = GeneralName(gnX509);

    ASSERT_EQ(gn.getRegisteredId().getOid(), GeneralNameTest::ridName);
    ASSERT_EQ(gn.getType(), GeneralName::REGISTERED_ID);

    ASSERT_EQ(fromGn.getRegisteredId().getOid(), GeneralNameTest::ridName);
    ASSERT_EQ(fromGn.getType(), GeneralName::REGISTERED_ID);
}

/**
 * @brief Tests GeneralNames funcionality from a few GeneralName entries
 */
TEST_F(GeneralNameTest, GeneralNames) {
    ObjectIdentifier oid;
    GeneralName gn;
    GeneralNames gns;
    GeneralNames fromGns;
    GENERAL_NAMES* gnsX509;
    std::vector<GeneralName> generalNames;
    pair< std::string, std::string > otherName;

    oid = ObjectIdentifierFactory::getObjectIdentifier(GeneralNameTest::ridName);
    gn.setRegisteredId(oid);
    gns.addGeneralName(gn);

    gn.setIpAddress(GeneralNameTest::ipAddress);
    gns.addGeneralName(gn);

    gn.setOtherName(GeneralNameTest::otherNameOID, GeneralNameTest::otherNameData);
    gns.addGeneralName(gn);

    gnsX509 = gns.getInternalGeneralNames();
    fromGns = GeneralNames(gnsX509);

    generalNames = gns.getGeneralNames();
    otherName = generalNames[2].getOtherName();
    ASSERT_EQ(generalNames[0].getRegisteredId().getOid(), GeneralNameTest::ridName);
    ASSERT_EQ(generalNames[0].getType(), GeneralName::REGISTERED_ID);
    ASSERT_EQ(generalNames[1].getIpAddress(), GeneralNameTest::ipAddress);
    ASSERT_EQ(generalNames[1].getType(), GeneralName::IP_ADDRESS);
    ASSERT_EQ(otherName.first, GeneralNameTest::otherNameOID);
    ASSERT_EQ(otherName.second, GeneralNameTest::otherNameData);
    ASSERT_EQ(generalNames[2].getType(), GeneralName::OTHER_NAME);

    generalNames = fromGns.getGeneralNames();
    otherName = generalNames[2].getOtherName();
    ASSERT_EQ(generalNames[0].getRegisteredId().getOid(), GeneralNameTest::ridName);
    ASSERT_EQ(generalNames[0].getType(), GeneralName::REGISTERED_ID);
    ASSERT_EQ(generalNames[1].getIpAddress(), GeneralNameTest::ipAddress);
    ASSERT_EQ(generalNames[1].getType(), GeneralName::IP_ADDRESS);
    ASSERT_EQ(otherName.first, GeneralNameTest::otherNameOID);
    ASSERT_EQ(otherName.second, GeneralNameTest::otherNameData);
    ASSERT_EQ(generalNames[2].getType(), GeneralName::OTHER_NAME);
}
