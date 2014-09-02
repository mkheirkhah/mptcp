/**
Should be one testsuite for TcpTxBuffer too

**/

#include "ns3/mp-tcp-typedefs.h"


NS_LOG_COMPONENT_DEFINE ("MpTcpMappingTestSuite");

using namespace ns3;


template<class T>
class TcpOptionMpTcpTestCase : public TestCase
{
public:
    TcpOptionMpTcpTestCase(Ptr<T> configuredOption,std::string desc) : TestCase(desc)
    {
        NS_LOG_FUNCTION(this);
        m_option = configuredOption;
    }

    virtual ~TcpOptionMpTcpTestCase()
    {
        NS_LOG_FUNCTION(this);
    }

    virtual void DoRun(void)
    {
        TestSerialize();
        TestDeserialize();
    }

};



static class TcpOptionMpTcpTestSuite : public TestSuite
{
public:
 MpTcpMappingTestSuite ()
 : TestSuite ("mptcp-mapping", UNIT)
 {
//    for (uint8_t i=0; i< 40; i += 10)
//    {

        ////////////////////////////////////////////////
        //// MP CAPABLE
        ////
        Ptr<TcpOptionMpTcpCapable> mpc = CreateObject<TcpOptionMpTcpCapable>(),
                mpc2 = CreateObject<TcpOptionMpTcpCapable>();
        mpc->SetRemoteKey(42);
        mpc->SetSenderKey(232323);
        AddTestCase(
            new TcpOptionMpTcpTestCase<TcpOptionMpTcpCapable> (mpc,"MP_CAPABLE with Sender & Peer keys both set"),
            QUICK
            );

 }




} g_TcpOptionTestSuite;
