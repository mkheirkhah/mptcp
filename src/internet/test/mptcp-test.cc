
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
#include "ns3/point-to-point-module.h"
//#include "ns3/point-to-point-channel.h"
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


      #if 0
      // TODO That should go into a helper
      // Object from L3 to access to routing protocol, Interfaces and NetDevices and so on.
      Ptr<Ipv4L3Protocol> ipv4 = m_node->GetObject<Ipv4L3Protocol>();
      for (uint32_t i = 0; i < ipv4->GetNInterfaces(); i++)
        {
          //Ptr<NetDevice> device = m_node->GetDevice(i);
          Ptr<Ipv4Interface> interface = ipv4->GetInterface(i);
          Ipv4InterfaceAddress interfaceAddr = interface->GetAddress(0);

          // Skip the loop-back
          if (interfaceAddr.GetLocal() == Ipv4Address::GetLoopback())
            continue;

          addrInfo = new MpTcpAddressInfo();
          addrInfo->addrID = i;
          addrInfo->ipv4Addr = interfaceAddr.GetLocal();
          addrInfo->mask = interfaceAddr.GetMask();
      header.AddOptADDR(OPT_ADDR, addrInfo->addrID, addrInfo->ipv4Addr);
      olen += 6;
          m_localAddrs.insert(m_localAddrs.end(), addrInfo);
        }
      #endif

/**
Provide basic functions to generate a topology (or outsource them ?)

Control the Number of interfaces per node
**/
class MpTcpTestCase : public TestCase
{
public:
  MpTcpTestCase(std::string name);
  virtual ~MpTcpTestCase ();

protected:
  virtual void SetupNodes();

  virtual void SetupDefaultSim (
//      Ptr<Node> n0, Ptr<Node> n1, int nbOfParallelLinks
      );
//private:
  virtual void DoSetup(void);
  virtual void DoRun(void) = 0;
  virtual void DoTeardown (void);


  void ServerHandleConnectionCreated (Ptr<Socket> s, const Address & addr);
  void ServerHandleRecv (Ptr<Socket> sock);
  void ServerHandleSend (Ptr<Socket> sock, uint32_t available);
  void SourceHandleSend (Ptr<Socket> sock, uint32_t available);
  void SourceHandleRecv (Ptr<Socket> sock);


  uint8_t m_nbInterfacesClient;
  uint8_t m_nbInterfacesServer;

  Ptr<Node> m_client;
  Ptr<Node> m_server;
};


/**
Number of interfaces per node
**/
class MpTcpAddressTestCase : public MpTcpTestCase
{
public:
  MpTcpAddressTestCase();
  virtual ~MpTcpAddressTestCase () {}


private:
  virtual void DoRun(void);

};

MpTcpTestCase::MpTcpTestCase(std::string name) :
  TestCase(name),
  m_nbInterfacesClient(1),
  m_nbInterfacesServer(m_nbInterfacesClient)  // Too complex to have an odd fullmesh
{
  NS_LOG_LOGIC (this);

}

MpTcpTestCase::~MpTcpTestCase()
{
}

void
MpTcpTestCase::SetupNodes()
{

  Ipv4AddressHelper addressHelper;  //!< To install


  m_client = CreateObject<Node>();
  m_server = CreateObject<Node>();


  //PointToPointStarHelper

  // client
  //PointToPointHelper pointToPointHelper;
  for(int i = 0; i < m_nbInterfacesClient; i++ )
  {
    Ptr<PointToPointNetDevice> devClient = CreateObject<PointToPointNetDevice>();
    devClient->SetDataRate( DataRate ("5Mb/s")  );
    devClient->SetAddress(Mac48Address::Allocate ());
    devClient->SetQueue (CreateObject<DropTailQueue> ());
    m_client->AddDevice( devClient );

      // Server
//      for(int j = 0; j < m_nbInterfacesServer; j++ )
//      {
        Ptr<PointToPointNetDevice> devServer = CreateObject<PointToPointNetDevice>();
        devServer->SetDataRate( DataRate ("5Mb/s") );
        devServer->SetAddress(Mac48Address::Allocate ());
        devServer->SetQueue (CreateObject<DropTailQueue> ());

        // Attach
        m_server->AddDevice( devServer );

        // TODO attach link
        Ptr<PointToPointChannel> channel = CreateObject<PointToPointChannel>();
        devServer->Attach( channel );
        devClient->Attach( channel );

        NetDeviceContainer devicesContainer;
        devicesContainer.Add(devClient);
        devicesContainer.Add(devServer);

        std::stringstream netAddr;
        netAddr << "10." << i << ".1.0";
        addressHelper.SetBase ( netAddr.str().c_str() , "255.255.0.0");
        addressHelper.Assign( devicesContainer );
//      }


  }

  // Server
//  for(int i = 0; i < m_nbInterfacesServer; i++ )
//  {
//    Ptr<PointToPointNetDevice> device = CreateObject<PointToPointNetDevice>();
//    device->SetDataRate( DataRate ("5Mb/s") );
//    // Attach
//    m_server->AddDevice( device );
//
//  }

  // TODO create interfaces for each node
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
MpTcpTestCase::DoSetup()
{
  SetupNodes();

}


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
//  SetupDefaultSim();
  Simulator::Run();

  NS_LOG_LOGIC("Simulation ended");

  NS_TEST_EXPECT_MSG_EQ (0, 1, "This test must fail (not ready)");
  NS_TEST_ASSERT_MSG_EQ (true, true, "true doesn't equal true for some reason");
}

//MpTcpAddressTestCase
void
MpTcpTestCase::SetupDefaultSim (void)
{
  ////////////////////////////////////////////////////////
  // Topology construction
  //

  // TODO change program so that it becomes useless
  ns3::PacketMetadata::Enable ();
//  const char* netmask = "255.255.255.0";
//  const char* ipaddr0 = "192.168.1.1";
//  const char* ipaddr1 = "192.168.1.2";
  uint16_t port = 50000;


//  NodeContainer nodes;//ContainerHelper;
  PointToPointHelper pointToPointHelper;
  InternetStackHelper stackHelper;
  NetDeviceContainer devices;
  Ipv4AddressHelper addressHelper;  //!< To install
#if 0


//  nodes.Create(2);
//  m_client = nodes.Get(0);
//  m_server = nodes.Get(1);

  // TODO should be able to configure that through a ConfigStore ?
  pointToPointHelper.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
  pointToPointHelper.SetChannelAttribute ("Delay", StringValue ("2ms"));

  // Creates netdevices in nodes, can I install it several times ?
  devices = pointToPointHelper.Install(nodes);
#endif
  stackHelper.Install( m_client );
  stackHelper.Install( m_server );

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

// Should work too ?! more straightforward ! TODO try
 Ptr<Socket> serverSock =  Socket::CreateSocket ( m_server,  MpTcpSocketFactory::GetTypeId ());
  Ptr<MpTcpSocketFactoryImpl> sockFactory0 = CreateObject<MpTcpSocketFactoryImpl> ();
  sockFactory0->SetTcp(m_server->GetObject<TcpL4Protocol> ());
//
//  m_server->AggregateObject(sockFactory0);
//  Ptr<SocketFactory> sockFactory1 = m_client->GetObject<MpTcpSocketFactory> ();

//  Ptr<MpTcpSocketBase> serverSock = sockFactory0->CreateSocket ();
  Ptr<Socket> clientSock = sockFactory0->CreateSocket ();

  serverSock->Bind(serverLocalAddr);
  serverSock->Listen();
  serverSock->SetAcceptCallback (MakeNullCallback<bool, Ptr< Socket >, const Address &> (),
                             MakeCallback (&MpTcpTestCase::ServerHandleConnectionCreated,this));


// 1 cb on add/1 on remove from remote side
//Remote
// SetOnPathIdEventRcv()
//  serverSock->SetAddrMgmtCallback();

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
    : TestSuite ("mptcp", UNIT)
  {
//    CommandLine cmd;

    // KESAKO ?
    Packet::EnablePrinting ();  // Enable packet metadata for all test cases
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

