

#include "ns3/test.h"
#include "ns3/socket-factory.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/simulator.h"
#include "ns3/simple-channel.h"
#include "ns3/simple-net-device.h"
#include "ns3/drop-tail-queue.h"
#include "ns3/config.h"
#include "ns3/ipv4-static-routing.h"
#include "ns3/ipv4-list-routing.h"
#include "ns3/ipv6-static-routing.h"
#include "ns3/ipv6-list-routing.h"
#include "ns3/node.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/uinteger.h"
#include "ns3/log.h"

#include "ns3/ipv4-end-point.h"
#include "ns3/arp-l3-protocol.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/ipv6-l3-protocol.h"
#include "ns3/icmpv4-l4-protocol.h"
#include "ns3/icmpv6-l4-protocol.h"
#include "ns3/udp-l4-protocol.h"
#include "ns3/tcp-l4-protocol.h"

#include "ns3/core-module.h"
#include "ns3/point-to-point-helper.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/applications-module.h"
#include "ns3/network-module.h"
#include "ns3/mp-tcp-socket-factory-impl.h"

#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/network-module.h"
#include "ns3/tcp-newreno.h"
#include "ns3/point-to-point-module.h"
#include "ns3/pcap-file.h"
#include "ns3/tcp-option-mptcp.h"
//#include "ns3/point-to-point-channel.h"
#include <string>

NS_LOG_COMPONENT_DEFINE ("MpTcpTestSuite");

using namespace ns3;

/**
this tests MPTCP (de)serializing options by generating pcap files and
comparing them to reference pcap files.
*/
class MpTcpOptionTestCase : public TestCase
{
  MpTcpOptionTestCase();
  virtual ~MpTcpOptionTestCase();

  virtual void DoSetup(void) = 0;
  virtual void DoRun(void) = 0;
  virtual void DoTeardown (void);

};


MpTcpOptionTestCase::MpTcpOptionTestCase() : TestCase("MptcpOption")
{
    NS_LOG_FUNCTION(this);
}


MpTcpOptionTestCase::~MpTcpOptionTestCase()
{

}


void
MpTcpOptionTestCase::DoSetup(void)
{
    NS_LOG_INFO("Setup of MPTCP options test");
}


void
MpTcpOptionTestCase::DoRun(void)
{
    // Generate TcpHeader
//    Ipv4Header ipHeader;
//
//  TcpHeader h;
//  h.SetFlags( TcpHeader::SYN );
//  h.SetSequenceNumber(SequenceNumber32());
//  h.SetAckNumber(SequenceNumber32());
//  h.SetSourcePort(1);
//  h.SetDestinationPort(2);
//  h.SetWindowSize(10);

    Buffer buffer;
//    Ptr<TcpOptionMpTcpCapable> option = Create<TcpOptionMpTcpCapable>();
    TcpOptionMpTcpCapable option, option2;
    option.SetSenderKey(1);
    option.SetRemoteKey(2);

    m_buffer.AddAtStart (opt.GetSerializedSize ());

    opt.Serialize (m_buffer.Begin ());

    h.Serialize( buffer.Begin() );
    TcpOptionTS opt;

    Buffer::Iterator start = m_buffer.Begin ();
    uint8_t kind = start.ReadU8 ();

    NS_TEST_EXPECT_MSG_EQ (kind, TcpOption::TS, "Different kind found");

    opt.Deserialize (start);
    uint32_t read = option2.Deserialize( buffer.Begin() );

    NS_TEST_EXPECT_MSG_EQ ( read, option.GetSerializedSize(), "PcapDiff(file, file) must always be false");
    NS_TEST_EXPECT_MSG_EQ ( option.GetLocalKey(), option2.GetLocalKey(), "Keys should be identic");

//    PcapFile
//    uint32_t sec(0), usec(0);
//    static bool 	Diff (std::string const &f1, std::string const &f2, uint32_t &sec, uint32_t &usec, uint32_t snapLen=SNAPLEN_DEFAULT
//    bool diff = ns3::PcapFile::Diff (std::string const &f1, std::string const &f2, sec, usec, SNAPLEN_DEFAULT);
//    std::string fullPath = CreateDataDirFilename();
//    CreateTempDirFilename

// 0x1e0c0081ec98f2ec7e8654d0
//    NS_TEST_EXPECT_MSG_EQ (diff, false, "PcapDiff(file, file) must always be false");
//    TcpOptionMpTcpCapable

    /////////////////////////////////////////////////
    /// DSS check
//    0x1e142005b7d964e16860e7ac0000000100186118

}


void
MpTcpOptionTestCase::DoTeardown(void)
{

}

