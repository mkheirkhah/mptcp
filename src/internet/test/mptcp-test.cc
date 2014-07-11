
/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2007 Georgia Tech Research Corporation
 * Copyright (c) 2009 INRIA
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 *          Raj Bhattacharjea <raj.b@gatech.edu>
 */

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
#include <string>

NS_LOG_COMPONENT_DEFINE ("MpTcpTestSuite");

using namespace ns3;


/**
To run with
NS_LOG="MpTcpTestSuite" ./waf --run "test-runner --suite=mptcp"
we should try not to add to internet dependancies ['bridge', 'mpi', 'network', 'core']
**/


//typedef MpTcpSocketBase SocketToBeTested;
typedef TcpNewReno SocketToBeTested;




class MpTcpTestCase : public TestCase
{
public:
  MpTcpTestCase(std::string name);
  virtual ~MpTcpTestCase ();

protected:
    void
  SetupDefaultSim (void);
private:
//  virtual void DoSetup(void) = 0;
  virtual void DoRun(void) = 0;
  virtual void DoTeardown (void);


  void ServerHandleConnectionCreated (Ptr<Socket> s, const Address & addr);
  void ServerHandleRecv (Ptr<Socket> sock);
  void ServerHandleSend (Ptr<Socket> sock, uint32_t available);
  void SourceHandleSend (Ptr<Socket> sock, uint32_t available);
  void SourceHandleRecv (Ptr<Socket> sock);



  Ptr<Node> m_client;
  Ptr<Node> m_server;
};

class MpTcpAddressTestCase : public MpTcpTestCase
{
public:
  MpTcpAddressTestCase();
  virtual ~MpTcpAddressTestCase () {}


private:
  virtual void DoRun(void);

};

MpTcpTestCase::MpTcpTestCase(std::string name) : TestCase(name)
{
  NS_LOG_LOGIC (this);

}

MpTcpTestCase::~MpTcpTestCase()
{
}



MpTcpAddressTestCase::MpTcpAddressTestCase() : MpTcpTestCase("Mptcp address handling")
{
  NS_LOG_LOGIC (this);
}

//MpTcpAddressTestCase::~MpTcpAddressTestCase()
//{
//
//}


void
MpTcpTestCase::DoTeardown (void)
{
  Simulator::Destroy();
}


//void
//MpTcpAddressTestCase::DoRun (void)
//{
//  NS_LOG_LOGIC ("Doing run MpTcpAddressTestCase");
//  MpTcpTestCase::DoRun ();
//}


void
MpTcpAddressTestCase::DoRun (void)
{
  NS_LOG_LOGIC ("Doing run in MpTcpAddressTestCase");
  SetupDefaultSim();
  Simulator::Run();

  NS_LOG_LOGIC("Simulation ended");

  NS_TEST_EXPECT_MSG_EQ (0, 1, "This test must fail (not ready)");
  NS_TEST_ASSERT_MSG_EQ (true, true, "true doesn't equal true for some reason");
}

//MpTcpAddressTestCase
void
MpTcpTestCase::SetupDefaultSim (void)
{

ns3::PacketMetadata::Enable ();
//  const char* netmask = "255.255.255.0";
//  const char* ipaddr0 = "192.168.1.1";
//  const char* ipaddr1 = "192.168.1.2";
  uint16_t port = 50000;


  NodeContainer nodes;//ContainerHelper;
  PointToPointHelper pointToPointHelper;
  InternetStackHelper stackHelper;
  NetDeviceContainer devices;
  Ipv4AddressHelper addressHelper;  //!< To install


  nodes.Create(2);
  m_client = nodes.Get(0);
  m_server = nodes.Get(1);
  pointToPointHelper.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
  pointToPointHelper.SetChannelAttribute ("Delay", StringValue ("2ms"));

  // Creates netdevices in nodes, can I install it several times ?
  devices = pointToPointHelper.Install(nodes);

  stackHelper.Install(nodes);

  addressHelper.SetBase ("10.1.1.0", "255.255.255.0");
  addressHelper.Assign(devices);

  // 0,0 is localhost or so it seems
  Ipv4Address addr = m_server->GetObject<Ipv4>()->GetAddress(1,0).GetLocal();

  InetSocketAddress serverLocalAddr (Ipv4Address::GetAny (), port);
  NS_LOG_INFO("Server Address " << addr);
//  NS_LOG_INFO( );
  //AddressValue IPv4Address::ConvertFrom
  InetSocketAddress serverRemoteAddr (addr, port);

//  m_server->
//  m_client->Connect( serverremoteaddr );
// lSocket
  
  Ptr<MpTcpSocketFactoryImpl> sockFactory0 = CreateObject<MpTcpSocketFactoryImpl> ();
  sockFactory0->SetTcp(m_server->GetObject<TcpL4Protocol> ());
  
  m_server->AggregateObject(sockFactory0);
//  Ptr<SocketFactory> sockFactory1 = m_client->GetObject<MpTcpSocketFactory> ();
  
  Ptr<Socket> serverSock = sockFactory0->CreateSocket ();
  Ptr<Socket> clientSock = sockFactory0->CreateSocket ();

  serverSock->Bind(serverLocalAddr);
  serverSock->Listen();
  serverSock->SetAcceptCallback (MakeNullCallback<bool, Ptr< Socket >, const Address &> (),
                             MakeCallback (&MpTcpTestCase::ServerHandleConnectionCreated,this));

  clientSock->Bind(); // is that one useful ?
  //serverremoteaddr
  //  m_server->GetObject<Ipv4>()->GetAddress(0,0).GetLocal()




  clientSock->SetRecvCallback (MakeCallback (&MpTcpTestCase::SourceHandleRecv, this));
  clientSock->SetSendCallback (MakeCallback (&MpTcpTestCase::SourceHandleSend, this));


  clientSock->Connect( serverRemoteAddr  );
//  clientSock->AdvertiseAvailableAddresses();
}


/*
Todo this one is important: should be called first
*/
void
MpTcpTestCase::ServerHandleConnectionCreated (Ptr<Socket> s, const Address & addr)
{
  NS_LOG_UNCOND("CALLBACK CALLLED !!! Server ServerHandleConnectionCreated ");
//
//  s->SetRecvCallback (MakeCallback (&TcpTestCase::ServerHandleRecv, this));
//  s->SetSendCallback (MakeCallback (&TcpTestCase::ServerHandleSend, this));
}

void
MpTcpTestCase::ServerHandleRecv (Ptr<Socket> sock)
{
  NS_LOG_INFO("Server handle rcv ");
}

void
MpTcpTestCase::ServerHandleSend (Ptr<Socket> sock, uint32_t available)
{
    NS_LOG_INFO("Server Handle send ");
}

void
MpTcpTestCase::SourceHandleSend (Ptr<Socket> sock, uint32_t available)
{
  NS_LOG_INFO("Src handle send ");
}


//  virtual void DoSetup (void);
void
MpTcpTestCase::SourceHandleRecv (Ptr<Socket> sock)
{
  NS_LOG_INFO("Server handle recv");
}
//NS_TEST_EXPECT_MSG_EQ



static class MpTcpTestSuite : public TestSuite
{
public:
  MpTcpTestSuite ()
    : TestSuite ("mptcp-testsuite", UNIT)
  {
    // Arguments to these test cases are 1) totalStreamSize,
    // 2) source write size, 3) source read size
    // 4) server write size, and 5) server read size
    // with units of bytes
    AddTestCase (new MpTcpAddressTestCase(), TestCase::QUICK);
//    AddTestCase (new MpTcpTestCase (13, 1, 1, 1, 1, false), TestCase::QUICK);
//    AddTestCase (new MpTcpTestCase (100000, 100, 50, 100, 20, false), TestCase::QUICK);
//
//    AddTestCase (new MpTcpTestCase (13, 200, 200, 200, 200, true), TestCase::QUICK);
//    AddTestCase (new MpTcpTestCase (13, 1, 1, 1, 1, true), TestCase::QUICK);
//    AddTestCase (new MpTcpTestCase (100000, 100, 50, 100, 20, true), TestCase::QUICK);
  }

} g_MpTcpTestSuite;

