#include <libcryptosec/certificate/AuthorityKeyIdentifierExtension.h>
#include <libcryptosec/certificate/AuthorityInformationAccessExtension.h>
#include <libcryptosec/certificate/CertificatePoliciesExtension.h>
#include <libcryptosec/certificate/SubjectKeyIdentifierExtension.h>
#include <libcryptosec/certificate/KeyUsageExtension.h>
#include <libcryptosec/certificate/CRLDistributionPointsExtension.h>
#include <libcryptosec/certificate/ExtendedKeyUsageExtension.h>
#include <libcryptosec/certificate/IssuerAlternativeNameExtension.h>
#include <libcryptosec/certificate/SubjectAlternativeNameExtension.h>
#include <libcryptosec/certificate/SubjectInformationAccessExtension.h>
#include <libcryptosec/certificate/BasicConstraintsExtension.h>
#include <libcryptosec/certificate/CRLNumberExtension.h>
#include <libcryptosec/certificate/DeltaCRLIndicatorExtension.h>
#include <libcryptosec/certificate/ObjectIdentifierFactory.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe Extension e seus derivados
 */
class ExtensionsTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    void generalTests(Extension ext, Extension::Name name) {
        ObjectIdentifier oid;

        ASSERT_NO_THROW(
            oid = ext.getObjectIdentifier();
        );

        ASSERT_EQ(ext.getTypeName(), name);
        ASSERT_EQ(ext.getName(), oid.getName());

        ASSERT_FALSE(ext.isCritical());
        ext.setCritical(true);
        ASSERT_TRUE(ext.isCritical());
    }

    static long basicConstraintsPathLen;
    static unsigned long serialNumber;
    static unsigned long serialNew;
    static char* keyIdentifierValue;
    static std::vector<long> noticeNumbers;
    static std::string rfcName;
    static std::string dnsName;
    static std::string orgName;
    static std::string explicitText;
    static std::string extendedKeyUsageOneOid;
    static std::string extendedKeyUsageOneName;
    static std::string extendedKeyUsageTwoOid;
    static std::string extendedKeyUsageTwoName;
    static std::string authorityAccessInfoOid;
    static std::string subjectAccessInfoOid;
    static std::string policyInformationOid;
    static std::string subjectAccessInfoName;
    static std::string authorityAccessInfoName;
    static std::string policyInformationName;
    static std::string cpsUri;
};

/*
 * Initialization of variables used in the tests
 */
long ExtensionsTest::basicConstraintsPathLen = 5;
unsigned long ExtensionsTest::serialNumber = 1234567890;
unsigned long ExtensionsTest::serialNew = 9876543210;
char* ExtensionsTest::keyIdentifierValue = (char *) "B132247BE75A265B9CB80BBD3474CBB7A4FA40CC";
std::vector<long> ExtensionsTest::noticeNumbers{1234567890, 9876543210};
std::string ExtensionsTest::rfcName = "example@mail.com";
std::string ExtensionsTest::dnsName = "8.8.8.8";
std::string ExtensionsTest::orgName = "Org Name";
std::string ExtensionsTest::explicitText = "Explicit Text.";
std::string ExtensionsTest::extendedKeyUsageOneOid = "1.3.6.1.5.5.7.3.1";
std::string ExtensionsTest::extendedKeyUsageOneName = "serverAuth";
std::string ExtensionsTest::extendedKeyUsageTwoOid = "1.3.6.1.5.5.7.3.4";
std::string ExtensionsTest::extendedKeyUsageTwoName = "emailProtection";
std::string ExtensionsTest::authorityAccessInfoOid = "1.3.6.1.5.5.7.1.1";
std::string ExtensionsTest::authorityAccessInfoName = "authorityInfoAccess";
std::string ExtensionsTest::subjectAccessInfoOid = "1.3.6.1.5.5.7.1.11";
std::string ExtensionsTest::subjectAccessInfoName = "subjectInfoAccess";
std::string ExtensionsTest::policyInformationOid = "1.3.6.1.5.5.7.14";
//std::string ExtensionsTest::policyInformationName = "cp";
std::string ExtensionsTest::cpsUri = "www.example.com";

/**
 * @brief Tests AccessDescription class for usage in InformationAccessExtension
 */
TEST_F(ExtensionsTest, AccessDescription) {
    AccessDescription ad;
    AccessDescription fromX509;
    ACCESS_DESCRIPTION *desc;
    GeneralName gn;
    ObjectIdentifier oid;

    gn.setDnsName(ExtensionsTest::dnsName);
    oid = ObjectIdentifierFactory::getObjectIdentifier(ExtensionsTest::subjectAccessInfoOid);

    ad.setAccessLocation(gn);
    ad.setAccessMethod(oid);

    desc = ad.getAccessDescription();
    fromX509 = AccessDescription(desc);

    ASSERT_EQ(ad.getAccessLocation().getDnsName(), ExtensionsTest::dnsName);
    ASSERT_EQ(ad.getAccessMethod().getOid(), ExtensionsTest::subjectAccessInfoOid);
    ASSERT_EQ(ad.getAccessMethod().getName(), ExtensionsTest::subjectAccessInfoName);
    ASSERT_EQ(ad.getXmlEncoded(), fromX509.getXmlEncoded());
}

/**
 * @brief Tests SubjectInformationAccessExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, AuthorityInformationAccess) {
    AuthorityInformationAccessExtension ext;
    AuthorityInformationAccessExtension fromX509;
    X509_EXTENSION *extX509;
    AccessDescription ad;
    GeneralName gn;
    ObjectIdentifier oid;
    std::vector< AccessDescription > accessDescriptions;

    gn.setDnsName(ExtensionsTest::dnsName);
    oid = ObjectIdentifierFactory::getObjectIdentifier(ExtensionsTest::authorityAccessInfoOid);
    ad.setAccessLocation(gn);
    ad.setAccessMethod(oid);
    ext.addAccessDescription(ad);

    gn.setRfc822Name(ExtensionsTest::rfcName);
    ad.setAccessLocation(gn);
    ext.addAccessDescription(ad);

    extX509 = ext.getX509Extension();
    fromX509 = AuthorityInformationAccessExtension(extX509);

    generalTests(ext, Extension::AUTHORITY_INFORMATION_ACCESS);

    accessDescriptions = ext.getAccessDescriptions();
    ASSERT_EQ(accessDescriptions[0].getAccessLocation().getDnsName(), ExtensionsTest::dnsName);
    ASSERT_EQ(accessDescriptions[0].getAccessMethod().getOid(), ExtensionsTest::authorityAccessInfoOid);
    ASSERT_EQ(accessDescriptions[0].getAccessMethod().getName(), ExtensionsTest::authorityAccessInfoName);
    ASSERT_EQ(accessDescriptions[1].getAccessLocation().getDnsName(), ExtensionsTest::rfcName);
    ASSERT_EQ(accessDescriptions[1].getAccessMethod().getOid(), ExtensionsTest::authorityAccessInfoOid);
    ASSERT_EQ(accessDescriptions[1].getAccessMethod().getName(), ExtensionsTest::authorityAccessInfoName);
    ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());
}

/**
 * @brief Tests AuthorityKeyIdentifierExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, AuthorityKeyIdentifier) {
    AuthorityKeyIdentifierExtension ext;
    long serialNumber;
    GeneralNames gns;
    GeneralName gn;
    X509_EXTENSION *extX509;
    std::vector<GeneralName> generalNames;

    ByteArray ba(ExtensionsTest::keyIdentifierValue);
    ByteArray value;

    gn.setRfc822Name(ExtensionsTest::rfcName);
    gns.addGeneralName(gn);

    gn.setDnsName(ExtensionsTest::dnsName);
    gns.addGeneralName(gn);

    ext.setKeyIdentifier(ba);
    ext.setAuthorityCertIssuer(gns);
    ext.setAuthorityCertSerialNumber(ExtensionsTest::serialNumber);

    value = ext.getKeyIdentifier();
    gns = ext.getAuthorityCertIssuer();
    generalNames = gns.getGeneralNames();
    serialNumber = ext.getAuthorityCertSerialNumber();
    extX509 = ext.getX509Extension();
    AuthorityKeyIdentifierExtension fromX509(extX509);

    generalTests(ext, Extension::AUTHORITY_KEY_IDENTIFIER);

    ASSERT_EQ(value.toString(), ExtensionsTest::keyIdentifierValue);
    ASSERT_EQ(generalNames[0].getRfc822Name(), ExtensionsTest::rfcName);
    ASSERT_EQ(generalNames[1].getDnsName(), ExtensionsTest::dnsName);
    ASSERT_EQ(serialNumber, ExtensionsTest::serialNumber);
    ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());
}

/**
 * @brief Tests BasicConstraintsExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, BasicConstraints) {
    BasicConstraintsExtension ext;
    X509_EXTENSION *extX509;

    ext.setCa(true);
    ext.setPathLen(ExtensionsTest::basicConstraintsPathLen);

    extX509 = ext.getX509Extension();
    BasicConstraintsExtension fromX509(extX509);

    generalTests(ext, Extension::BASIC_CONSTRAINTS);

    ASSERT_EQ(ext.getPathLen(), ExtensionsTest::basicConstraintsPathLen);
    ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());
    
    ASSERT_TRUE(ext.isCa());
    ext.setCa(false);
    ASSERT_FALSE(ext.isCa());
}

/**
 * @brief Tests UserNotice for usage in PolicyQualifierInfo
 */
TEST_F(ExtensionsTest, UserNotice) {
    UserNotice un;
    UserNotice fromX509;
    USERNOTICE *notice;
    std::pair<std::string, std::vector<long> > noticeRef;

    un.setNoticeReference(ExtensionsTest::orgName, ExtensionsTest::noticeNumbers);
    un.setExplicitText(ExtensionsTest::explicitText);

    noticeRef = un.getNoticeReference();
    notice = un.getUserNotice();
    fromX509 = UserNotice(notice);

    ASSERT_EQ(noticeRef.first, ExtensionsTest::orgName);
    ASSERT_EQ(noticeRef.second[0], ExtensionsTest::noticeNumbers[0]);
    ASSERT_EQ(noticeRef.second[1], ExtensionsTest::noticeNumbers[1]);
    ASSERT_EQ(un.getExplicitText(), ExtensionsTest::explicitText);
    ASSERT_EQ(un.getXmlEncoded(), fromX509.getXmlEncoded());
}

/**
 * @brief Tests PolicyQualifierInfo for usage in PolicyInformation
 */
TEST_F(ExtensionsTest, PolicyQualifierInfo) {
    PolicyQualifierInfo info;
    PolicyQualifierInfo fromX509;
    UserNotice un;
    POLICYQUALINFO *policyinfo;

    un.setNoticeReference(ExtensionsTest::orgName, ExtensionsTest::noticeNumbers);
    un.setExplicitText(ExtensionsTest::explicitText);

    info.setCpsUri(ExtensionsTest::cpsUri);
    ASSERT_EQ(info.getCpsUri(), ExtensionsTest::cpsUri);
    ASSERT_EQ(info.getType(), PolicyQualifierInfo::CPS_URI);

    policyinfo = info.getPolicyQualInfo();
    fromX509 = PolicyQualifierInfo(policyinfo);
    ASSERT_EQ(info.getXmlEncoded(), fromX509.getXmlEncoded());

    info.setUserNotice(un);
    ASSERT_EQ(info.getUserNotice().getExplicitText(), ExtensionsTest::explicitText);
    ASSERT_EQ(info.getType(), PolicyQualifierInfo::USER_NOTICE);

    policyinfo = info.getPolicyQualInfo();
    fromX509 = PolicyQualifierInfo(policyinfo);
    ASSERT_EQ(info.getXmlEncoded(), fromX509.getXmlEncoded());
}

/**
 * @brief Tests PolicyInformation for usage in CertificatePoliciesExtension
 */
TEST_F(ExtensionsTest, PolicyInformation) {
    PolicyInformation info;
    PolicyInformation fromX509;
    ObjectIdentifier oid;
    UserNotice un;
    PolicyQualifierInfo qualInfo;
    POLICYINFO *policyinfo;
    std::vector< PolicyQualifierInfo > qualInfos;

    oid = ObjectIdentifierFactory::getObjectIdentifier(ExtensionsTest::policyInformationOid);
    un.setNoticeReference(ExtensionsTest::orgName, ExtensionsTest::noticeNumbers);
    un.setExplicitText(ExtensionsTest::explicitText);

    qualInfo.setCpsUri(ExtensionsTest::cpsUri);
    info.setPolicyIdentifier(oid);
    info.addPolicyQualifierInfo(qualInfo);

    qualInfo.setUserNotice(un);
    info.addPolicyQualifierInfo(qualInfo);

    policyinfo = info.getPolicyInfo();
    fromX509 = PolicyInformation(policyinfo);

    qualInfos = info.getPoliciesQualifierInfo();
    ASSERT_EQ(info.getPolicyIdentifier().getOid(), ExtensionsTest::policyInformationOid);
    ASSERT_EQ(qualInfos[0].getCpsUri(), ExtensionsTest::cpsUri);
    ASSERT_EQ(qualInfos[1].getUserNotice().getExplicitText(), ExtensionsTest::explicitText);
    ASSERT_EQ(info.getXmlEncoded(), fromX509.getXmlEncoded());
}

/**
 * @brief Tests CertificatePoliciesExtension
 */
TEST_F(ExtensionsTest, CertificatePolicies) {
    CertificatePoliciesExtension ext;
    CertificatePoliciesExtension fromX509;
    PolicyInformation info;
    ObjectIdentifier oid;
    UserNotice un;
    PolicyQualifierInfo qualInfo;
    X509_EXTENSION *extX509;
    std::vector< PolicyInformation > policies;

    oid = ObjectIdentifierFactory::getObjectIdentifier(ExtensionsTest::policyInformationOid);
    un.setNoticeReference(ExtensionsTest::orgName, ExtensionsTest::noticeNumbers);
    un.setExplicitText(ExtensionsTest::explicitText);

    qualInfo.setCpsUri(ExtensionsTest::cpsUri);
    info.setPolicyIdentifier(oid);
    info.addPolicyQualifierInfo(qualInfo);
    ext.addPolicyInformation(info);

    qualInfo.setUserNotice(un);
    info.addPolicyQualifierInfo(qualInfo);
    ext.addPolicyInformation(info);

    extX509 = ext.getX509Extension();
    fromX509 = CertificatePoliciesExtension(extX509);

    generalTests(ext, Extension::CERTIFICATE_POLICIES);

    policies = ext.getPoliciesInformation();
    qualInfo = policies[0].getPoliciesQualifierInfo()[0];
    ASSERT_TRUE(policies.size() == 2);
    ASSERT_EQ(policies[1].getPolicyIdentifier().getOid(), ExtensionsTest::policyInformationOid);
    ASSERT_EQ(qualInfo.getCpsUri(), ExtensionsTest::cpsUri);
    ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());
}

/**
 * @brief Tests CRLNumberExtension general and specific functionalities
 */
/* Few things to do in libcryptosec */
TEST_F(ExtensionsTest, CRLNumber) {
    CRLNumberExtension ext(ExtensionsTest::serialNumber);
    // X509_EXTENSION *extX509;

    /* TODO in libcryptosec
    extX509 = ext.getX509Extension();
    CRLNumberExtension fromX509(extX509); */

    generalTests(ext, Extension::CRL_NUMBER);

    ASSERT_EQ(ext.getSerial(), ExtensionsTest::serialNumber);
    // ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());

    ext.setSerial(ExtensionsTest::serialNew);
    ASSERT_EQ(ext.getSerial(), ExtensionsTest::serialNew);
}

/**
 * @brief Tests CRLNumberExtension general and specific functionalities
 */
/* Few things to do in libcryptosec */
TEST_F(ExtensionsTest, DistributionPointName) {
    DistributionPointName distPointName;
    DistributionPointName fromX509;
    DIST_POINT_NAME *dpName;
    RDNSequence rdn;
    GeneralName gn;
    GeneralNames gNames;

    rdn.addEntry(RDNSequence::ORGANIZATION, ExtensionsTest::orgName);
    rdn.addEntry(RDNSequence::EMAIL, ExtensionsTest::rfcName);

    gn.setRfc822Name(ExtensionsTest::rfcName);
    gNames.addGeneralName(gn);
    gn.setUniformResourceIdentifier(ExtensionsTest::cpsUri);
    gNames.addGeneralName(gn);

    distPointName.setNameRelativeToCrlIssuer(rdn);
    dpName = distPointName.getDistPointName();
    fromX509 = DistributionPointName(dpName);

    rdn = fromX509.getNameRelativeToCrlIssuer();
    ASSERT_EQ(distPointName.getType(), DistributionPointName::RELATIVE_NAME);
    ASSERT_EQ(fromX509.getType(), DistributionPointName::RELATIVE_NAME);
    ASSERT_EQ(rdn.getEntries(RDNSequence::ORGANIZATION)[0], ExtensionsTest::orgName);
    ASSERT_EQ(rdn.getEntries(RDNSequence::EMAIL)[0], ExtensionsTest::rfcName);

    distPointName.setFullName(gNames);
    dpName = distPointName.getDistPointName();
    fromX509 = DistributionPointName(dpName);

    gNames = fromX509.getFullName();
    ASSERT_EQ(distPointName.getType(), DistributionPointName::FULL_NAME);
    ASSERT_EQ(fromX509.getType(), DistributionPointName::FULL_NAME);
    ASSERT_EQ(gNames.getGeneralNames()[0].getRfc822Name(), ExtensionsTest::rfcName);
    ASSERT_EQ(gNames.getGeneralNames()[1].getUniformResourceIdentifier(), ExtensionsTest::cpsUri);
    ASSERT_EQ(distPointName.getXmlEncoded(), fromX509.getXmlEncoded());
}

/**
 * @brief Tests CRLNumberExtension general and specific functionalities
 */
/* Few things to do in libcryptosec */
TEST_F(ExtensionsTest, DistributionPoint) {
    DistributionPoint distPoint;
    DistributionPoint fromX509;
    DistributionPointName distPointName;
    DIST_POINT *dPoint;
    GeneralName gn;
    GeneralNames gNames;

    gn.setRfc822Name(ExtensionsTest::rfcName);
    gNames.addGeneralName(gn);
    gn.setUniformResourceIdentifier(ExtensionsTest::cpsUri);
    gNames.addGeneralName(gn);

    distPointName.setFullName(gNames);
    distPoint.setDistributionPointName(distPointName);
    distPoint.setCrlIssuer(gNames);
    distPoint.setReasonFlag(DistributionPoint::KEY_COMPROMISE, true);
    distPoint.setReasonFlag(DistributionPoint::CESSATION_OF_OPERATION, true);

    dPoint = distPoint.getDistPoint();
    fromX509 = DistributionPoint(dPoint);

    gNames = fromX509.getCrlIssuer();
    ASSERT_EQ(gNames.getGeneralNames()[0].getRfc822Name(), ExtensionsTest::rfcName);
    ASSERT_EQ(gNames.getGeneralNames()[1].getUniformResourceIdentifier(), ExtensionsTest::cpsUri);

    gNames = fromX509.getDistributionPointName().getFullName();
    ASSERT_EQ(gNames.getGeneralNames()[0].getRfc822Name(), ExtensionsTest::rfcName);
    ASSERT_EQ(gNames.getGeneralNames()[1].getUniformResourceIdentifier(), ExtensionsTest::cpsUri);
    
    ASSERT_EQ(distPoint.getXmlEncoded(), fromX509.getXmlEncoded());

    ASSERT_TRUE(distPoint.getReasonFlag(DistributionPoint::KEY_COMPROMISE));
    ASSERT_TRUE(distPoint.getReasonFlag(DistributionPoint::CESSATION_OF_OPERATION));
    ASSERT_FALSE(distPoint.getReasonFlag(DistributionPoint::UNUSED));
    ASSERT_FALSE(distPoint.getReasonFlag(DistributionPoint::CA_COMPROMISE));
}

/**
 * @brief Tests CRLNumberExtension general and specific functionalities
 */
/* Few things to do in libcryptosec */
TEST_F(ExtensionsTest, CRLDistributionPoints) {
    CRLDistributionPointsExtension ext;
    CRLDistributionPointsExtension fromX509;
    X509_EXTENSION *extX509;
    DistributionPoint distPoint;
    DistributionPointName distPointName;
    GeneralName gn;
    GeneralNames gNames;
    std::vector< DistributionPoint > distPoints;

    gn.setRfc822Name(ExtensionsTest::rfcName);
    gNames.addGeneralName(gn);
    gn.setUniformResourceIdentifier(ExtensionsTest::cpsUri);
    gNames.addGeneralName(gn);

    distPointName.setFullName(gNames);
    distPoint.setDistributionPointName(distPointName);
    distPoint.setCrlIssuer(gNames);
    distPoint.setReasonFlag(DistributionPoint::KEY_COMPROMISE, true);

    ext.addDistributionPoint(distPoint);
    distPoint.setReasonFlag(DistributionPoint::CESSATION_OF_OPERATION, true);
    ext.addDistributionPoint(distPoint);

    extX509 = ext.getX509Extension();
    fromX509 = CRLDistributionPointsExtension(extX509);

    generalTests(ext, Extension::CRL_DISTRIBUTION_POINTS);

    distPoints = ext.getDistributionPoints();
    ASSERT_TRUE(distPoints[0].getReasonFlag(DistributionPoint::KEY_COMPROMISE));
    ASSERT_FALSE(distPoints[0].getReasonFlag(DistributionPoint::CESSATION_OF_OPERATION));

    ASSERT_TRUE(distPoints[1].getReasonFlag(DistributionPoint::KEY_COMPROMISE));
    ASSERT_TRUE(distPoints[1].getReasonFlag(DistributionPoint::CESSATION_OF_OPERATION));

    ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());
}

/**
 * @brief Tests DeltaCRLIndicatorExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, DeltaCRLIndicator) {
    DeltaCRLIndicatorExtension ext(ExtensionsTest::serialNumber);
    X509_EXTENSION *extX509;

    extX509 = ext.getX509Extension();
    DeltaCRLIndicatorExtension fromX509(extX509);

    generalTests(ext, Extension::DELTA_CRL_INDICATOR);

    ASSERT_EQ(ext.getSerial(), ExtensionsTest::serialNumber);
    ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());

    ext.setSerial(ExtensionsTest::serialNew);
    ASSERT_EQ(ext.getSerial(), ExtensionsTest::serialNew);
}

/**
 * @brief Tests ExtendedKeyUsageExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, ExtendedKeyUsage) {
   ExtendedKeyUsageExtension ext;
    X509_EXTENSION *extX509;
    ObjectIdentifier oid;
    std::vector<ObjectIdentifier> usage;

    oid = ObjectIdentifierFactory::getObjectIdentifier(ExtensionsTest::extendedKeyUsageOneOid);
    ext.addUsage(oid);

    oid = ObjectIdentifierFactory::getObjectIdentifier(ExtensionsTest::extendedKeyUsageTwoOid);
    ext.addUsage(oid);

    extX509 = ext.getX509Extension();
    ExtendedKeyUsageExtension fromX509(extX509);

    generalTests(ext, Extension::EXTENDED_KEY_USAGE);

    usage = ext.getUsages();
    ASSERT_TRUE(usage.size() == 2);
    ASSERT_EQ(usage[0].getOid(), ExtensionsTest::extendedKeyUsageOneOid);
    ASSERT_EQ(usage[0].getName(), ExtensionsTest::extendedKeyUsageOneName);
    ASSERT_EQ(usage[1].getOid(), ExtensionsTest::extendedKeyUsageTwoOid);
    ASSERT_EQ(usage[1].getName(), ExtensionsTest::extendedKeyUsageTwoName);

    //fromX509 has usage order reversed from original.
    usage = fromX509.getUsages();
    ASSERT_TRUE(usage.size() == 2);
    ASSERT_EQ(usage[1].getOid(), ExtensionsTest::extendedKeyUsageOneOid);
    ASSERT_EQ(usage[1].getName(), ExtensionsTest::extendedKeyUsageOneName);
    ASSERT_EQ(usage[0].getOid(), ExtensionsTest::extendedKeyUsageTwoOid);
    ASSERT_EQ(usage[0].getName(), ExtensionsTest::extendedKeyUsageTwoName);
}

/**
 * @brief Tests IssuerAlternativeNameExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, IssuerAlternativeName) {
    IssuerAlternativeNameExtension ext;
    GeneralNames gns;
    GeneralName gn;
    X509_EXTENSION *extX509;
    std::vector<GeneralName> generalNames;

    gn.setRfc822Name(ExtensionsTest::rfcName);
    gns.addGeneralName(gn);

    gn.setDnsName(ExtensionsTest::dnsName);
    gns.addGeneralName(gn);

    ext.setIssuerAltName(gns);

    gns = ext.getIssuerAltName();
    generalNames = gns.getGeneralNames();
    extX509 = ext.getX509Extension();
    IssuerAlternativeNameExtension fromX509(extX509);

    generalTests(ext, Extension::ISSUER_ALTERNATIVE_NAME);

    ASSERT_EQ(generalNames[0].getRfc822Name(), ExtensionsTest::rfcName);
    ASSERT_EQ(generalNames[1].getDnsName(), ExtensionsTest::dnsName);
    ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());
}

/**
 * @brief Tests KeyUsageExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, KeyUsage) {
    KeyUsageExtension ext;
    X509_EXTENSION *extX509;

    ext.setUsage(KeyUsageExtension::DIGITAL_SIGNATURE, true);
    ext.setUsage(KeyUsageExtension::ENCIPHER_ONLY, true);

    extX509 = ext.getX509Extension();
    KeyUsageExtension fromX509(extX509);

    generalTests(ext, Extension::KEY_USAGE);

    ASSERT_TRUE(ext.getUsage(KeyUsageExtension::DIGITAL_SIGNATURE));
    ASSERT_TRUE(ext.getUsage(KeyUsageExtension::ENCIPHER_ONLY));

    ASSERT_FALSE(ext.getUsage(KeyUsageExtension::KEY_ENCIPHERMENT));
    ASSERT_FALSE(ext.getUsage(KeyUsageExtension::CRL_SIGN));

    ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());
}

/**
 * @brief Tests SubjectAlternativeNameExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, SubjectAlternativeName) {
    SubjectAlternativeNameExtension ext;
    GeneralNames gns;
    GeneralName gn;
    X509_EXTENSION *extX509;
    std::vector<GeneralName> generalNames;

    gn.setRfc822Name(ExtensionsTest::rfcName);
    gns.addGeneralName(gn);

    gn.setDnsName(ExtensionsTest::dnsName);
    gns.addGeneralName(gn);

    ext.setSubjectAltName(gns);

    gns = ext.getSubjectAltName();
    generalNames = gns.getGeneralNames();
    extX509 = ext.getX509Extension();
    SubjectAlternativeNameExtension fromX509(extX509);

    generalTests(ext, Extension::SUBJECT_ALTERNATIVE_NAME);

    ASSERT_EQ(generalNames[0].getRfc822Name(), ExtensionsTest::rfcName);
    ASSERT_EQ(generalNames[1].getDnsName(), ExtensionsTest::dnsName);
    ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());
}

/**
 * @brief Tests SubjectInformationAccessExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, SubjectInformationAccess) {
    SubjectInformationAccessExtension ext;
    SubjectInformationAccessExtension fromX509;
    X509_EXTENSION *extX509;
    AccessDescription ad;
    GeneralName gn;
    ObjectIdentifier oid;
    std::vector< AccessDescription > accessDescriptions;

    gn.setDnsName(ExtensionsTest::dnsName);
    oid = ObjectIdentifierFactory::getObjectIdentifier(ExtensionsTest::subjectAccessInfoOid);
    ad.setAccessLocation(gn);
    ad.setAccessMethod(oid);
    ext.addAccessDescription(ad);

    gn.setRfc822Name(ExtensionsTest::rfcName);
    ad.setAccessLocation(gn);
    ext.addAccessDescription(ad);

    extX509 = ext.getX509Extension();
    fromX509 = SubjectInformationAccessExtension(extX509);

    generalTests(ext, Extension::SUBJECT_INFORMATION_ACCESS);

    accessDescriptions = ext.getAccessDescriptions();
    ASSERT_EQ(accessDescriptions[0].getAccessLocation().getDnsName(), ExtensionsTest::dnsName);
    ASSERT_EQ(accessDescriptions[0].getAccessMethod().getOid(), ExtensionsTest::subjectAccessInfoOid);
    ASSERT_EQ(accessDescriptions[0].getAccessMethod().getName(), ExtensionsTest::subjectAccessInfoName);
    ASSERT_EQ(accessDescriptions[1].getAccessLocation().getDnsName(), ExtensionsTest::rfcName);
    ASSERT_EQ(accessDescriptions[1].getAccessMethod().getOid(), ExtensionsTest::subjectAccessInfoOid);
    ASSERT_EQ(accessDescriptions[0].getAccessMethod().getName(), ExtensionsTest::subjectAccessInfoName);
    ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());
}

/**
 * @brief Tests SubjectKeyIdentifierExtension general and specific functionalities
 */
TEST_F(ExtensionsTest, SubjectKeyIdentifier) {
    SubjectKeyIdentifierExtension ext;
    X509_EXTENSION *extX509;

    ByteArray ba(ExtensionsTest::keyIdentifierValue);
    ByteArray value;

    ext.setKeyIdentifier(ba);
    value = ext.getKeyIdentifier();
    extX509 = ext.getX509Extension();
    SubjectKeyIdentifierExtension fromX509(extX509);

    generalTests(ext, Extension::SUBJECT_KEY_IDENTIFIER);

    ASSERT_EQ(value.toString(), ExtensionsTest::keyIdentifierValue);
    ASSERT_EQ(ext.getXmlEncoded(), fromX509.getXmlEncoded());
}
