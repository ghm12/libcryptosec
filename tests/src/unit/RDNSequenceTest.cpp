#include <libcryptosec/certificate/RDNSequence.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe RDNSequence.
 */
class RDNSequenceTest : public ::testing::Test {


protected:
    virtual void SetUp() {
        rdn = new RDNSequence();
    }

    virtual void TearDown() {
        free(rdn);
    }

    void fillCountry (RDNSequence *rdn) {
        rdn->addEntry(RDNSequence::COUNTRY, RDNSequenceTest::countryOne);
        rdn->addEntry(RDNSequence::COUNTRY, RDNSequenceTest::countryTwo);
    }

    void fillCommonName(RDNSequence *rdn) {
        rdn->addEntry(RDNSequence::COMMON_NAME, RDNSequenceTest::commonNameOne);
        rdn->addEntry(RDNSequence::COMMON_NAME, RDNSequenceTest::commonNameTwo);
    }

    RDNSequence *rdn;
    static std::string countryName;
    static std::string countryOne;
    static std::string countryTwo;
    static std::string commonNameName;
    static std::string commonNameOne;
    static std::string commonNameTwo;
    static std::string xmlEncoded;
};

/*
 * Initialization of variables used in the tests
 */
std::string RDNSequenceTest::countryName = "C";
std::string RDNSequenceTest::countryOne = "BR";
std::string RDNSequenceTest::countryTwo = "RB";

std::string RDNSequenceTest::commonNameName = "CN";
std::string RDNSequenceTest::commonNameOne = "Common Name";
std::string RDNSequenceTest::commonNameTwo = "emaN nommoC";

std::string RDNSequenceTest::xmlEncoded = "<RDNSequence>\n\t<countryName>BR</countryName>\n\t<commonName>emaN nommoC</commonName>\n</RDNSequence>\n";

TEST_F(RDNSequenceTest, FromX509Name) {
    X509_NAME *name;
    RDNSequence fromX509;

    rdn->addEntry(RDNSequence::COUNTRY, RDNSequenceTest::countryOne);
    rdn->addEntry(RDNSequence::COMMON_NAME, RDNSequenceTest::commonNameOne);

    name = rdn->getX509Name();
    fromX509 = RDNSequence(name);

    ASSERT_EQ(rdn->getXmlEncoded(), fromX509.getXmlEncoded());
}

/**
 * @brief Tests adding and getting specific entries from a RDNSequence
 */
TEST_F(RDNSequenceTest, GetEntriesSpecific) {
    std::vector<std::string> vector;

    fillCountry(rdn);
    fillCommonName(rdn);

    vector = rdn->getEntries(RDNSequence::COUNTRY);

    ASSERT_EQ(vector[0], RDNSequenceTest::countryOne);
    ASSERT_EQ(vector[1], RDNSequenceTest::countryTwo);

    vector = rdn->getEntries(RDNSequence::COMMON_NAME);

    ASSERT_EQ(vector[0], RDNSequenceTest::commonNameOne);
    ASSERT_EQ(vector[1], RDNSequenceTest::commonNameTwo);
}

/**
 * @brief Tests adding and then getting all known entries from a RDNSequence
 */
TEST_F(RDNSequenceTest, GetEntriesGeneral) {
    std::vector< std::pair<ObjectIdentifier, std::string> > vector;

    fillCountry(rdn);
    fillCommonName(rdn);

    vector = rdn->getEntries();

    ASSERT_EQ(vector[0].first.getName(), RDNSequenceTest::countryName);
    ASSERT_EQ(vector[0].second, RDNSequenceTest::countryOne);
    ASSERT_EQ(vector[1].second, RDNSequenceTest::countryTwo);

    ASSERT_EQ(vector[2].first.getName(), RDNSequenceTest::commonNameName);
    ASSERT_EQ(vector[2].second, RDNSequenceTest::commonNameOne);
    ASSERT_EQ(vector[3].second, RDNSequenceTest::commonNameTwo);
}

/**
 * @brief Tests getting data in XML format from a RDNSequence
 */
TEST_F(RDNSequenceTest, GetXmlEncoded) {
    rdn->addEntry(RDNSequence::COUNTRY, RDNSequenceTest::countryOne);
    rdn->addEntry(RDNSequence::COMMON_NAME, RDNSequenceTest::commonNameTwo);

    ASSERT_EQ(rdn->getXmlEncoded(), RDNSequenceTest::xmlEncoded);
}