/**
Should be one testsuite for TcpTxBuffer too

**/

#include "ns3/mp-tcp-typedefs.h"
#include "ns3/log.h"
#include "ns3/test.h"


NS_LOG_COMPONENT_DEFINE ("MpTcpMappingTestSuite");

using namespace ns3;



class MpTcpMappingTestCase : public TestCase
{
public:
    MpTcpMappingTestCase (SequenceNumber32 headDSN, SequenceNumber32 mappedToSSN,uint16_t length) :
        TestCase("Mptcp mapping testcase"),
        m_headDSN(headDSN),
        m_mappedSSN(mappedToSSN),
        m_length(length)
    {
        NS_LOG_FUNCTION(this);

    }

    virtual ~MpTcpMappingTestCase ()
    {
        NS_LOG_FUNCTION(this);
    }

    virtual void DoRun(void)
    {
      MpTcpMapping map0, map1;
      MpTcpMappingContainer con0;

      map0.Configure(m_headDSN, m_length);
      NS_TEST_EXPECT_MSG_EQ( map0.HeadDSN(), m_headDSN, "Broken setter or getter");
      NS_TEST_EXPECT_MSG_EQ( map0.GetLength(), m_length, "Broken setter");

      map0.MapToSSN( m_mappedSSN );
      map1 = map0;


      NS_TEST_EXPECT_MSG_EQ( map0.TailDSN(), m_headDSN + (uint32_t)m_length-1,"");
      NS_TEST_EXPECT_MSG_EQ( map0.TailSSN(), m_mappedSSN + (uint32_t)m_length-1,"");


//      NS_TEST_ASSERT()

      NS_TEST_EXPECT_MSG_EQ(map1, map0,"Mappings have all values in common");
      map1.MapToSSN(m_headDSN- (uint32_t)m_length);
      // Not true anymore
//      NS_TEST_EXPECT_MSG_EQ(map1, map0, "Mappings should be considered equal even if they are mappped to different SSN");


      //,""
      SequenceNumber32 temp;

      NS_TEST_EXPECT_MSG_EQ(map0.TranslateSSNToDSN(map0.HeadSSN(), temp), true, "temp should overlap the mapping");
      NS_TEST_EXPECT_MSG_EQ(temp, map0.HeadDSN(), "HeadSSN must map to HeadDSN");



      /////////////////////////////////////////////////////////
      /////
      /////
      /////////////////////////////////////////////////////////

      ///// Check SSNoverlap
      ///////////////////////////////////////////
      NS_TEST_EXPECT_MSG_EQ( map0.OverlapRangeSSN(map0.HeadSSN()-4, 2), false,"starting at -4 with length of 2 does not overlap");
      NS_TEST_EXPECT_MSG_EQ( map0.OverlapRangeSSN(map0.HeadSSN(), 1), true, "HeadSSN is part of the mapping so it must overlap");
      NS_TEST_EXPECT_MSG_EQ( map0.OverlapRangeSSN(map0.TailSSN(), 1), true, "TailSSN is part of the mapping so it must overlap");
      NS_TEST_EXPECT_MSG_EQ( map0.OverlapRangeSSN(map0.TailSSN()+1, 4), false, "Data after the mapping, must not overlap");

      ///// Check DSNoverlap
      ///////////////////////////////////////////
      NS_TEST_EXPECT_MSG_EQ( map0.OverlapRangeDSN(map0.HeadDSN()-4, 2), false,"starting at -4 with length of 2 does not overlap");
      NS_TEST_EXPECT_MSG_EQ( map0.OverlapRangeDSN(map0.HeadDSN()-4, 6), true,"starting at -4 with length of 6 does not overlap");
      NS_TEST_EXPECT_MSG_EQ( map0.OverlapRangeDSN(map0.HeadDSN(), 1), true, "HeadDSN is part of the mapping so it must overlap");
      NS_TEST_EXPECT_MSG_EQ( map0.OverlapRangeDSN(map0.TailDSN(), 1), true, "TailDSN is part of the mapping so it must overlap");
      NS_TEST_EXPECT_MSG_EQ( map0.OverlapRangeDSN(map0.TailDSN()+1, 4), false, "Data after the mapping, must not overlap");


      ///// Check DSNInRange
      ///////////////////////////////////////////
      NS_TEST_EXPECT_MSG_EQ( map0.IsDSNInRange(map0.HeadDSN()), true, "test ");
      NS_TEST_EXPECT_MSG_EQ( map0.IsDSNInRange(map0.TailDSN()), true, "");
      NS_TEST_EXPECT_MSG_EQ( map0.IsDSNInRange(map0.HeadDSN()-1 ), false, "");
      NS_TEST_EXPECT_MSG_EQ( map0.IsDSNInRange(map0.TailDSN()+1 ), false,"");

      ///// Check SSNInRange
      ///////////////////////////////////////////
      // TODO maybe do some of the tests only
      NS_TEST_EXPECT_MSG_EQ( map0.IsSSNInRange(map0.HeadSSN()), true, "First byte is part of the mapping");
      NS_TEST_EXPECT_MSG_EQ( map0.IsSSNInRange(map0.TailSSN()), true, "Last byte is part of the mapping");
      NS_TEST_EXPECT_MSG_EQ( map0.IsSSNInRange(map0.HeadSSN()-1), false, "Byte just before first byte is not part of the mapping");
      NS_TEST_EXPECT_MSG_EQ( map0.IsSSNInRange(map0.TailSSN()+1), false, "Byte just after last byte is not part of the mapping");







//      con0.AddMapping(map0);
      NS_TEST_EXPECT_MSG_EQ(con0.AddMapping(map0), true, "This is the first time");
      NS_TEST_EXPECT_MSG_EQ(con0.AddMapping(map0), false, "They should intersect");

//        TestSerialize();
//        TestDeserialize();
    }
protected:
  const SequenceNumber32 m_headDSN;
  const SequenceNumber32 m_mappedSSN;
  const uint16_t m_length;
};



static class MpTcpMappingTestSuite : public TestSuite
{
public:
 MpTcpMappingTestSuite ()
 : TestSuite ("mptcp-mapping", UNIT)
 {
//    for (uint8_t i=0; i< 40; i += 10)
//    {

        ////////////////////////////////////////////////
        ////
        ////

        AddTestCase(new MpTcpMappingTestCase( SequenceNumber32(10), SequenceNumber32(60),40),QUICK);
        AddTestCase(new MpTcpMappingTestCase( SequenceNumber32(50), SequenceNumber32(1),2),QUICK);
        AddTestCase(new MpTcpMappingTestCase( SequenceNumber32(50), SequenceNumber32(1),1),QUICK);

 }

//
//
//
} g_MpTcpMappingTestSuite;
