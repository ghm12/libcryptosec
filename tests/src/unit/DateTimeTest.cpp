#include <libcryptosec/DateTime.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe DateTime
 */
class DateTimeTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {
        free(dt);
    }

    void testDateTimeValues(DateTime *dt) {
        BigInteger seconds = dt->getSeconds();

        ASSERT_EQ(dt->getDateTime(), epoch);
        ASSERT_EQ(seconds.getValue(), epoch);
        ASSERT_EQ(dt->getISODate(), dateISO);
        ASSERT_EQ(dt->getXmlEncoded(), xmlEncoded);
    }

    void testLimitValues(DateTime *dt) {
        BigInteger seconds = dt->getSeconds();

        ASSERT_EQ(dt->getDateTime(), epochAboveLimit);
        ASSERT_EQ(seconds.getValue(), epochAboveLimit);
        ASSERT_EQ(dt->getISODate(), dateISOLimit);
        ASSERT_EQ(dt->getXmlEncoded(), xmlEncodedLimit);
    }

    DateTime *dt;
    static int leapYear;
    static int year;
    static int month;
    static int day;
    static int hour;
    static int min;
    static int sec;
    static int dayOfWeek;
    static int dayOfYear;
    static long addValue;
    static time_t epoch;
    static time_t addedEpoch;
    static time_t epochAboveLimit;
    static std::string dateISO;
    static std::string dateISOLimit;
    static std::string dateUTC;
    static std::string xmlEncoded;
    static std::string xmlEncodedLimit;
    static std::string addedISO;
    static std::string addedUTC;
    static std::string addedXmlEncoded;
};

/*
 * Initialization of variables used in the tests
 */
int DateTimeTest::leapYear = 2020;
int DateTimeTest::year = 2017;
int DateTimeTest::month = 01;
int DateTimeTest::day = 23;
int DateTimeTest::hour = 22;
int DateTimeTest::min = 45;
int DateTimeTest::sec = 07;
int DateTimeTest::dayOfWeek = 4;
int DateTimeTest::dayOfYear = 53;
long DateTimeTest::addValue = 14;
time_t DateTimeTest::epoch = 1487889907;
time_t DateTimeTest::addedEpoch = 1930654761;
time_t DateTimeTest::epochAboveLimit = 2524608001;
std::string DateTimeTest::dateISO = "2017-02-23T22:45:07";
std::string DateTimeTest::dateISOLimit = "2050-01-01T00:00:01";
std::string DateTimeTest::dateUTC = "20170223224507Z";
std::string DateTimeTest::xmlEncoded = "170223224507Z";
std::string DateTimeTest::xmlEncodedLimit = "20500101000001Z";
std::string DateTimeTest::addedISO = "2031-03-07T12:59:21";
std::string DateTimeTest::addedXmlEncoded = "310307125921Z";

/**
 * @brief Tests creation of DateTime object from time_t structure
 */
TEST_F(DateTimeTest, FromTimeT) {
    dt = new DateTime(DateTimeTest::epoch);
    testDateTimeValues(dt);
}

/**
 * @brief Tests creation of DateTime object from time_t structure when value is above UTC limit
 */
TEST_F(DateTimeTest, FromTimeTAboveLimit) {
    dt = new DateTime(DateTimeTest::epochAboveLimit);
    testLimitValues(dt);
}

/**
 * @brief Tests creation of DateTime object from BigInteger
 */
TEST_F(DateTimeTest, FromBigInteger) {
    BigInteger bi;
    bi.setValue(DateTimeTest::epoch);

    dt = new DateTime(bi);
    testDateTimeValues(dt);
}

/**
 * @brief Tests creation of DateTime object from UTC Date format string
 */
TEST_F(DateTimeTest, FromUTCDate) {
    dt = new DateTime(DateTimeTest::dateUTC);
    testDateTimeValues(dt);
}

/**
 * @brief Tests getter and creation of DateTime object from ASN1_TIME structure
 */
TEST_F(DateTimeTest, ASN1Time) {
    ASN1_TIME *asn1time;

    dt = new DateTime(epoch);
    asn1time = dt->getAsn1Time();
    dt = new DateTime(asn1time);
    testDateTimeValues(dt);
}

/**
 * @brief Tests getter and creation of DateTime object from ASN1_TIME Generalized Time structure
 */
TEST_F(DateTimeTest, GeneralizedTime) {
    ASN1_TIME *asn1time;

    dt = new DateTime(epoch);
    asn1time = dt->getGeneralizedTime();
    dt = new DateTime(asn1time);
    testDateTimeValues(dt);
}

/**
 * @brief Tests getter and creation of DateTime object from ASN1_TIME UTC Time structure
 */
TEST_F(DateTimeTest, UTCTime) {
    ASN1_TIME *asn1time;

    dt = new DateTime(epoch);
    asn1time = dt->getUTCTime();
    dt = new DateTime(asn1time);
    testDateTimeValues(dt);
}

/**
 * @brief Tests SetDateTime methods with all possible parameters
 */
TEST_F(DateTimeTest, SetDateTime) {
    BigInteger bi;

    bi.setValue(DateTimeTest::epoch);

    dt = new DateTime();
    dt->setDateTime(DateTimeTest::epoch);
    testDateTimeValues(dt);

    dt = new DateTime();
    dt->setDateTime(bi);
    testDateTimeValues(dt);
}

/**
 * @brief Tests all addValue methods and their effects on the object's value
 */
TEST_F(DateTimeTest, AddValues) {
    BigInteger seconds;
    dt = new DateTime(epoch);

    dt->addSeconds(DateTimeTest::addValue);
    dt->addMinutes(DateTimeTest::addValue);
    dt->addHours(DateTimeTest::addValue);
    dt->addDays(DateTimeTest::addValue);
    dt->addYears(DateTimeTest::addValue);

    seconds = dt->getSeconds();
    ASSERT_EQ(dt->getDateTime(), DateTimeTest::addedEpoch);
    ASSERT_EQ(seconds.getValue(), DateTimeTest::addedEpoch);
    ASSERT_EQ(dt->getISODate(), DateTimeTest::addedISO);
    ASSERT_EQ(dt->getXmlEncoded(), DateTimeTest::addedXmlEncoded);
}

/**
 * @brief Tests all operators from DateTime class
 */
TEST_F(DateTimeTest, Operators) {
    DateTime other;

    dt = new DateTime(epoch);
    other = *dt;

    ASSERT_EQ(other.getSeconds(), DateTimeTest::epoch);
    ASSERT_TRUE(other == *dt);
    ASSERT_TRUE(other == DateTimeTest::epoch);

    other.addDays(DateTimeTest::addValue);

    ASSERT_TRUE(other > *dt);
    ASSERT_TRUE(*dt < other);
    ASSERT_TRUE(other > DateTimeTest::epoch);
    
    ASSERT_FALSE(other == *dt);
    ASSERT_FALSE(other < *dt);
    ASSERT_FALSE(*dt > other);
    ASSERT_FALSE(other == DateTimeTest::epoch);
    ASSERT_FALSE(other < DateTimeTest::epoch);

    *dt = other;
    ASSERT_TRUE(*dt == other);
    ASSERT_FALSE(*dt == DateTimeTest::epoch);
}

/**
 * @brief Tests the values of getDate method from an epoch value
 */
TEST_F(DateTimeTest, GetDate) {
    BigInteger bi;
    DateTime::DateVal date;
    
    bi.setValue(DateTimeTest::epoch);
    date = DateTime::getDate(bi);

    ASSERT_EQ(date.sec, DateTimeTest::sec);
    ASSERT_EQ(date.min, DateTimeTest::min);
    ASSERT_EQ(date.hour, DateTimeTest::hour);
    ASSERT_EQ(date.dayOfMonth, DateTimeTest::day);
    ASSERT_EQ(date.mon, DateTimeTest::month);
    ASSERT_EQ(date.dayOfWeek, DateTimeTest::dayOfWeek);
    ASSERT_EQ(date.dayOfYear, DateTimeTest::dayOfYear);
}

/**
 * @brief Tests getting the day of the week from a specific month and year
 */
TEST_F(DateTimeTest, GetDayOfWeek) {
    int dayOfWeek;

    dayOfWeek = DateTime::getDayOfWeek(DateTimeTest::year,
                                       DateTimeTest::month,
                                       DateTimeTest::day);
    ASSERT_EQ(dayOfWeek, DateTimeTest::dayOfWeek);
}

/**
 * @brief Tests the convertion from a date to its epoch value
 */
TEST_F(DateTimeTest, Date2Epoch) {
    BigInteger bi = DateTime::date2epoch(DateTimeTest::year,
                                         DateTimeTest::month,
                                         DateTimeTest::day,
                                         DateTimeTest::hour,
                                         DateTimeTest::min,
                                         DateTimeTest::sec);
    ASSERT_EQ(bi.getValue(), DateTimeTest::epoch);

    bi = DateTime::date2epoch(DateTimeTest::dateUTC);
    ASSERT_EQ(bi.getValue(), DateTimeTest::epoch);
}

/**
 * @brief Tests if the input year is a leap year
 */
TEST_F(DateTimeTest, LeapYear) {
    ASSERT_TRUE(DateTime::isLeapYear(DateTimeTest::leapYear));
    ASSERT_FALSE(DateTime::isLeapYear(DateTimeTest::year));
}

/**
 * @brief Tests the amount of days in a given year
 */
TEST_F(DateTimeTest, YearSize) {
    ASSERT_EQ(DateTime::getYearSize(DateTimeTest::leapYear), 366);
    ASSERT_EQ(DateTime::getYearSize(DateTimeTest::year), 365);
}

/**
 * @brief Tests the amount of days in a given month
 */
TEST_F(DateTimeTest, getMonthSize) {
    ASSERT_EQ(DateTime::getMonthSize(DateTimeTest::month ,DateTimeTest::leapYear), 29);
    ASSERT_EQ(DateTime::getMonthSize(DateTimeTest::month, DateTimeTest::year), 28);
}
