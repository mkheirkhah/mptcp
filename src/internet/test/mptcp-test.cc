
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


/**
Provide basic functions to generate a topology (or outsource them ?)

Control the Number of interfaces per node
**/
class MpTcpTestCase : public TestCase
{
public:
  MpTcpTestCase(std::string name);
  virtual ~MpTcpTestCase ();

//  virtual void AdvertiseAllAddressesOfNode();

protected:
  virtual void CreateNodes();

  virtual void SetupDefaultSim (
//      Ptr<Node> n0, Ptr<Node> n1, int nbOfParallelLinks
      );
//private:
  virtual void DoSetup(void) = 0;
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
  Ptr<MpTcpSocketBase> m_clientSock;
  Ptr<Node> m_server;
  Ptr<MpTcpSocketBase> m_serverSock;
};



void getAllIpsOfANode(Ptr<Node> node, std::vector<Ipv4Address>& addr )
{
  NS_ASSERT(node);

  // TODO That should go into a helper
  // Object from L3 to access to routing protocol, Interfaces and NetDevices and so on.
  Ptr<Ipv4L3Protocol> ipv4 = node->GetObject<Ipv4L3Protocol>();

  for (uint32_t i = 0; i < ipv4->GetNInterfaces(); i++)
  {
      //Ptr<NetDevice> device = m_node->GetDevice(i);
      // Pourrait y avoir plusieurs IPs sur l'interface
      Ptr<Ipv4Interface> interface = ipv4->GetInterface(i);
      for( uint32_t j = 0; j < interface->GetNAddresses(); j++ )
      {
        Ipv4InterfaceAddress interfaceAddr = interface->GetAddress(j);


        // Skip the loop-back
        if (interfaceAddr.GetLocal() == Ipv4Address::GetLoopback())
          continue;


        addr.push_back( interfaceAddr.GetLocal() );
      }




  }
}

/**


**/
class PathEventTracker
{
public:
  PathEventTracker();
  ~PathEventTracker() {}


};

PathEventTracker::PathEventTracker()
{
}

/**
can be kept global ? MpTcpTestCase
, std::vector<uint16_t> ports
**/
void AdvertiseAllAddresses(Ptr<MpTcpSocketBase> mptcp)
{
  NS_ASSERT(mptcp);

  Ptr<Node> m_node = mptcp->GetNode();
      // Il peut en avoir plusieurs ?
//      Ptr<MpTcpSocketBase> mptcp = m_node->GetObject<MpTcpSocketBase>();
//      if(!mptcp)
//      {
//        NS_LOG_ERROR("This node has no MPTCP socket");
//        return;
//      }
//      else
      if (!mptcp->IsConnected())
      {
        NS_LOG_ERROR("This node has no established MPTCP connection");
        return;
      }

      std::vector<Ipv4Address> addresses;

      getAllIpsOfANode( m_node, addresses);

      for(std::vector<Ipv4Address>::const_iterator i = addresses.begin(); i != addresses.end(); i++ )
      {

        mptcp->GetSubFlow(0)->AdvertiseAddress( *i, 0 );
      }


}


//class MpTcpTestCase : public MpTcpTestCase
//{
//public:
//
//}

/**
Number of interfaces per node
**/
class MpTcpAddressTestCase : public MpTcpTestCase
{
public:
  /* Depending on the test */
  typedef enum {
  TEST0,
  TEST1
  } TestType;

  MpTcpAddressTestCase(TestType testType);
  virtual ~MpTcpAddressTestCase () {}

  virtual void DoSetup();

//  virtual Ptr<Node> CreateMonohomedNode(uint8_t nbOfInterfaces);
//  virtual Ptr<Node> CreateNode(uint8_t nbOfInterfaces);

  void AdvertiseAllAvailableAddresses();
//  void AdvertiseThenRemoveAllAdvertisedAddresses();
//  void AdvertiseThenCreateRemoveAllAdvertisedAddresses();
//  void CreateNsubflows();
//  void CreateFullmesh();

private:
  virtual void DoRun(void);
  TestType m_testType;
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

//Ptr<Node>
//MpTcpTestCase::CreateNode(uint8_t nbOfInterfaces)
//{
//  Ptr<Node> node = CreateObject<Node>();
//  for(int i = 0; i < m_nbInterfacesClient; i++ )
//  {
//    Ptr<PointToPointNetDevice> devClient = CreateObject<PointToPointNetDevice>();
//    devClient->SetDataRate( DataRate ("5Mb/s")  );
//    devClient->SetAddress(Mac48Address::Allocate ());
//    devClient->SetQueue (CreateObject<DropTailQueue> ());
//    node->AddDevice( devClient );
//  }
//}

void
MpTcpTestCase::CreateNodes()
{
  Config::SetDefault("ns3::TcpL4Protocol::SocketType",
			             TypeIdValue (MpTcpSocketBase::GetTypeId()));
//  Config::SetDefault ("ns3::TcpSocket::SegmentSize", UintegerValue (1000));
//  Config::SetDefault ("ns3::TcpSocket::DelAckCount", UintegerValue (1));
//  Config::SetDefault ("ns3::DropTailQueue::MaxPackets", UintegerValue (20));


  uint16_t port = 50000;
  Ipv4AddressHelper addressHelper;  //!< To install
  InternetStackHelper stackHelper;

  m_client = CreateObject<Node>();
  m_server = CreateObject<Node>();

  stackHelper.Install(m_client);
  stackHelper.Install(m_server);


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

//        NetDeviceContainer devicesContainer;
//        devicesContainer.Add(devClient);
//        devicesContainer.Add(devServer);

        std::stringstream netAddr;
        netAddr << "10." << i << ".1.0";
        addressHelper.SetBase ( netAddr.str().c_str() , "255.255.255.0");
        addressHelper.Assign( devServer );
//        addressHelper.Assign( devServer );

//        devServer->GetIfIndex( );
//
//        addressHelper.NewAddress();
//      }
    //)
      std::vector<Ipv4Address> temp;
      getAllIpsOfANode(m_server, temp);
      NS_TEST_ASSERT_MSG_EQ( temp.size(), 32 , "should be 2");
  }

//  #if 0
  /**
  TODO later
  **/

  /////////////////////////////////////////////
  // 1st way of creating a socket
  /////////////////////////////////////////////
  Ptr<Socket> serverSock =  m_server->GetObject<TcpL4Protocol>()->CreateSocket();
  m_serverSock = DynamicCast<MpTcpSocketBase>( serverSock );
  NS_LOG_UNCOND("m_serverSock" << m_serverSock);


  /////////////////////////////////////////////
  // 2nd way of creating an MPTCP socket
  /////////////////////////////////////////////
  Ptr<MpTcpSocketFactoryImpl> sockFactory0 = CreateObject<MpTcpSocketFactoryImpl> ();
  sockFactory0->SetTcp( m_client->GetObject<TcpL4Protocol> () );
  //CreateObject<MpTcpSocketFactoryImpl>()
  m_client->AggregateObject( sockFactory0 );
  Ptr<Socket> clientSock = Socket::CreateSocket ( m_client,  MpTcpSocketFactoryImpl::GetTypeId ());
  m_clientSock = DynamicCast<MpTcpSocketBase>( clientSock );
  NS_LOG_UNCOND("m_clientSock" << m_clientSock);
// Config::SetDefault


//  Ptr<Socket> serverSock = sockFactory0->CreateSocket ();
//  NS_LOG_UNCOND("serverSock" << serverSock);


//  #endif
//sockFactory0->SetTcp( m_server->GetObject<TcpL4Protocol> () );
//  m_serverSock = CreateObject<MpTcpSocketBase>();
//  m_clientSock = CreateObject<MpTcpSocketBase>();







  InetSocketAddress serverLocalAddr (Ipv4Address::GetAny (), port);
  //
  m_serverSock->Bind(serverLocalAddr);
  m_serverSock->Listen();
//  m_serverSock->SetAcceptCallback (MakeNullCallback<bool, Ptr< Socket >, const Address &> (),
//                             MakeCallback (&MpTcpTestCase::ServerHandleConnectionCreated,this)
//                             );


//Program received signal SIGSEGV, Segmentation fault.
//0x00007ffff319addc in ns3::TcpL4Protocol::Allocate (this=0x0)
//    at ../src/internet/model/tcp-l4-protocol.cc:203
//203	  return m_endPoints->Allocate();

  m_clientSock->Bind(); // is that one useful ?

  m_clientSock->SetRecvCallback (MakeCallback (&MpTcpTestCase::SourceHandleRecv, this));
  m_clientSock->SetSendCallback (MakeCallback (&MpTcpTestCase::SourceHandleSend, this));


//  m_clientSock->Connect( serverRemoteAddr  );


  // Here I should create the sockets
//  m_clientSock = DynamicCast<MpTcpSocketBase>(clientSock);

  // Server
//  for(int i = 0; i < m_nbInterfacesServer; i++ )

  // TODO create interfaces for each node
}

MpTcpAddressTestCase::MpTcpAddressTestCase(TestType testType) :
        MpTcpTestCase("Mptcp address handling"),
        m_testType(testType)
{
  NS_LOG_LOGIC (this);
  m_testType = testType;
}

//MpTcpAddressTestCase::~MpTcpAddressTestCase()
//{
//
//}

void
MpTcpAddressTestCase::DoSetup()
{
  CreateNodes();
  NS_ASSERT_MSG(m_serverSock, "Server socket non-existing");


  switch(m_testType)
  {
    // Single device with several Ips
    case TEST0:
//      m_serverSock->SetAcceptCallback (MakeNullCallback<bool, Ptr< Socket >, const Address &> (),
//                             MakeCallback (&MpTcpAddressTestCase::ServerHandleConnectionCreated,this)
//                             );
      break;
    default:
      break;
  }
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

  switch(m_testType)
  {
    case 0:
      {
        std::vector<InetSocketAddress> advertisedInet;
        std::vector<Ipv4Address> serverAddresses;
        getAllIpsOfANode(m_server, serverAddresses);
        m_clientSock->GetAllAdvertisedDestinations(advertisedInet);
        NS_TEST_EXPECT_MSG_EQ ( advertisedInet.size(), serverAddresses.size() ,"Number of seen ADD_ADDR should be equal to the number of IPs of the server" );
      }
      break;
    case 1:
    default:
      break;
  }

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
#if 0

  uint16_t port = 50000;


//  NodeContainer nodes;//ContainerHelper;
  PointToPointHelper pointToPointHelper;
  InternetStackHelper stackHelper;
  NetDeviceContainer devices;
  Ipv4AddressHelper addressHelper;  //!< To install


//  nodes.Create(2);
//  m_client = nodes.Get(0);
//  m_server = nodes.Get(1);

  // TODO should be able to configure that through a ConfigStore ?
  pointToPointHelper.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
  pointToPointHelper.SetChannelAttribute ("Delay", StringValue ("2ms"));

  // Creates netdevices in nodes, can I install it several times ?
  devices = pointToPointHelper.Install(nodes);

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
                             MakeCallback (&MpTcpTestCase::ServerHandleConnectionCreated,this)
                             );


// 1 cb on add/1 on remove from remote side
//Remote
// SetOnPathIdEventRcv()
//  serverSock->SetAddrMgmtCallback();

  clientSock->Bind(); // is that one useful ?
  //serverremoteaddr
  //  m_server->GetObject<Ipv4>()->GetAddress(0,0).GetLocal()


  Ptr<MpTcpSocketBase> clientSock2 = DynamicCast<MpTcpSocketBase>(clientSock);
//  clientSock2->SetNewAddrCallback();

  clientSock->SetRecvCallback (MakeCallback (&MpTcpTestCase::SourceHandleRecv, this));
  clientSock->SetSendCallback (MakeCallback (&MpTcpTestCase::SourceHandleSend, this));


  clientSock->Connect( serverRemoteAddr  );
//  clientSock->AdvertiseAvailableAddresses();
  #endif
}

/*
Todo this one is important: should be called first
*/
void
MpTcpTestCase::ServerHandleConnectionCreated (Ptr<Socket> s, const Address & addr)
{
  NS_LOG_UNCOND("CALLBACK CALLLED !!! Server ServerHandleConnectionCreated ");

  // TODO advertise all addresses to client
  Ptr<MpTcpSocketBase> mptcp = DynamicCast<MpTcpSocketBase>(s);
  AdvertiseAllAddresses(mptcp);

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
    AddTestCase (new MpTcpAddressTestCase(MpTcpAddressTestCase::TEST0), TestCase::QUICK);
//    AddTestCase (new MpTcpTestCase (13, 1, 1, 1, 1, false), TestCase::QUICK);
//    AddTestCase (new MpTcpTestCase (100000, 100, 50, 100, 20, false), TestCase::QUICK);
//
//    AddTestCase (new MpTcpTestCase (13, 200, 200, 200, 200, true), TestCase::QUICK);
//    AddTestCase (new MpTcpTestCase (13, 1, 1, 1, 1, true), TestCase::QUICK);
//    AddTestCase (new MpTcpTestCase (100000, 100, 50, 100, 20, true), TestCase::QUICK);
  }

} g_MpTcpTestSuite;

