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
#include "ns3/string.h"
#include "ns3/tcp-socket-base.h"
#include "ns3/mp-tcp-socket-base.h"

#include "ns3/ipv4-end-point.h"
#include "ns3/arp-l3-protocol.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/ipv6-l3-protocol.h"
#include "ns3/icmpv4-l4-protocol.h"
#include "ns3/icmpv6-l4-protocol.h"
#include "ns3/udp-l4-protocol.h"
#include "ns3/tcp-l4-protocol.h"
#include "ns3/trace-helper.h"
#include "ns3/point-to-point-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/sequence-number.h"
#include "ns3/trace-helper.h"

#include <string>
#include <fstream>

NS_LOG_COMPONENT_DEFINE ("MpTcpMultiSuite");

using namespace ns3;

//std::ofstream source_f;
//std::ofstream server_f;

// rename to serverPort
const uint16_t serverPort = 50000;



class MpTcpMultihomedTestCase : public TestCase
{
public:
  MpTcpMultihomedTestCase (uint32_t totalStreamSize,
               uint32_t sourceWriteSize,
               uint32_t sourceReadSize,
               uint32_t serverWriteSize,
               uint32_t serverReadSize,
               bool useIpv6);
private:
  virtual void DoRun (void);
  virtual void DoTeardown (void);
  void SetupDefaultSim (void);
  void SetupDefaultSim6 (void);

  Ptr<Node> CreateInternetNode (void);
  Ptr<Node> CreateInternetNode6 (void);
  Ptr<SimpleNetDevice> AddSimpleNetDevice (Ptr<Node> node, const char* ipaddr, const char* netmask);
  Ptr<SimpleNetDevice> AddSimpleNetDevice6 (Ptr<Node> node, Ipv6Address ipaddr, Ipv6Prefix prefix);
  void ServerHandleConnectionCreated (Ptr<Socket> s, const Address & addr);
  void ServerHandleRecv (Ptr<Socket> sock);
  void ServerHandleSend (Ptr<Socket> sock, uint32_t available);
  void SourceHandleSend (Ptr<Socket> sock, uint32_t available);
  void SourceHandleRecv (Ptr<Socket> sock);
  void SourceConnectionSuccessful (Ptr<Socket> sock);
  void SourceConnectionFailed (Ptr<Socket> sock);

  uint32_t m_totalBytes;
  uint32_t m_sourceWriteSize;
  uint32_t m_sourceReadSize;
  uint32_t m_serverWriteSize;
  uint32_t m_serverReadSize;
  uint32_t m_currentSourceTxBytes;
  uint32_t m_currentSourceRxBytes;
  uint32_t m_currentServerRxBytes;
  uint32_t m_currentServerTxBytes;
  uint8_t *m_sourceTxPayload;
  uint8_t *m_sourceRxPayload;
  uint8_t* m_serverRxPayload;

  bool m_connect_cb_called;
  bool m_useIpv6;

  Ptr<Node> m_serverNode;
  Ptr<Node> m_sourceNode;
};

static std::string Name (std::string str, uint32_t totalStreamSize,
                         uint32_t sourceWriteSize,
                         uint32_t serverReadSize,
                         uint32_t serverWriteSize,
                         uint32_t sourceReadSize,
                         bool useIpv6)
{
  std::ostringstream oss;
  oss << str << " total=" << totalStreamSize << " sourceWrite=" << sourceWriteSize
      << " sourceRead=" << sourceReadSize << " serverRead=" << serverReadSize
      << " serverWrite=" << serverWriteSize << " useIpv6=" << useIpv6;
  return oss.str ();
}

#ifdef NS3_LOG_ENABLE
static std::string GetString (Ptr<Packet> p)
{
  std::ostringstream oss;
  p->CopyData (&oss, p->GetSize ());
  return oss.str ();
}
#endif /* NS3_LOG_ENABLE */

MpTcpMultihomedTestCase::MpTcpMultihomedTestCase (uint32_t totalStreamSize,
                          uint32_t sourceWriteSize,
                          uint32_t sourceReadSize,
                          uint32_t serverWriteSize,
                          uint32_t serverReadSize,
                          bool useIpv6)
  : TestCase (Name ("Send string data from client to server and back",
                    totalStreamSize,
                    sourceWriteSize,
                    serverReadSize,
                    serverWriteSize,
                    sourceReadSize,
                    useIpv6)),
    m_totalBytes (totalStreamSize),
    m_sourceWriteSize (sourceWriteSize),
    m_sourceReadSize (sourceReadSize),
    m_serverWriteSize (serverWriteSize),
    m_serverReadSize (serverReadSize),
    m_connect_cb_called(false),
    m_useIpv6 (useIpv6)
{
}

void
MpTcpMultihomedTestCase::DoRun (void)
{
  m_currentSourceTxBytes = 0;
  m_currentSourceRxBytes = 0;
  m_currentServerRxBytes = 0;
  m_currentServerTxBytes = 0;
  m_sourceTxPayload = new uint8_t [m_totalBytes];
  m_sourceRxPayload = new uint8_t [m_totalBytes];
  m_serverRxPayload = new uint8_t [m_totalBytes];
  for(uint32_t i = 0; i < m_totalBytes; ++i)
    {
      uint8_t m = (uint8_t)(97 + (i % 26));
      m_sourceTxPayload[i] = m;
    }
  memset (m_sourceRxPayload, 0, m_totalBytes);
  memset (m_serverRxPayload, 0, m_totalBytes);

  if (m_useIpv6 == true)
    {
      SetupDefaultSim6 ();
    }
  else
    {
      SetupDefaultSim ();
    }

  Simulator::Run ();

  NS_TEST_EXPECT_MSG_EQ (m_connect_cb_called, true, "Callback was called on successful connection");
  NS_TEST_EXPECT_MSG_EQ (m_currentSourceTxBytes, m_totalBytes, "Source sent all bytes");
  NS_TEST_EXPECT_MSG_EQ (m_currentServerRxBytes, m_totalBytes, "Server received all bytes");
  NS_TEST_EXPECT_MSG_EQ (m_currentSourceRxBytes, m_totalBytes, "Source received all bytes");
  NS_TEST_EXPECT_MSG_EQ (memcmp (m_sourceTxPayload, m_serverRxPayload, m_totalBytes), 0,
                         "Server received expected data buffers");
  NS_TEST_EXPECT_MSG_EQ (memcmp (m_sourceTxPayload, m_sourceRxPayload, m_totalBytes), 0,
                         "Source received back expected data buffers");
}
void
MpTcpMultihomedTestCase::DoTeardown (void)
{
  delete [] m_sourceTxPayload;
  delete [] m_sourceRxPayload;
  delete [] m_serverRxPayload;
  Simulator::Destroy ();
}


/**
Normally this should be called twice ...
**/
void
MpTcpMultihomedTestCase::SourceConnectionSuccessful(Ptr<Socket> sock)
{

  Ptr<MpTcpSocketBase> meta =  DynamicCast<MpTcpSocketBase>(sock);

  NS_LOG_LOGIC("connection successful. Meta state=" << TcpSocket::TcpStateName[meta->GetState() ]
              << " received a DSS: " << meta->m_receivedDSS
              );

  if(! meta->m_receivedDSS) {
    //!
    NS_LOG_DEBUG("No DSS received yet");
    return;
  }


//  NS_LOG_WARN("TODO check this is called after the receival of 1st DSS !!!");
  m_connect_cb_called = true;
//  NS_FATAL_ERROR("Connect failed");
   // TODO now we can create an additionnal subflow


   Ptr<MpTcpSocketBase> sourceMeta = DynamicCast<MpTcpSocketBase>(sock);
   NS_ASSERT_MSG(sourceMeta, "WTF ?!!");

//   NS_LOG_DEBUG("meta in state " << meta->m_state);

  /*
  first address on 2nd interface
  */
  Ipv4Address serverAddr = m_serverNode->GetObject<Ipv4>()->GetAddress(2,0).GetLocal();
  Ipv4Address sourceAddr = m_sourceNode->GetObject<Ipv4>()->GetAddress(2,0).GetLocal();

  InetSocketAddress local( sourceAddr, serverPort);
  InetSocketAddress remote(serverAddr);

//  sourceMeta ->ConnectNewSubflow(local, remote);
//  Simulator::Schedule( )
}



void
MpTcpMultihomedTestCase::SourceConnectionFailed(Ptr<Socket> sock)
{

  NS_FATAL_ERROR("Connect failed");
}

void
MpTcpMultihomedTestCase::ServerHandleConnectionCreated (Ptr<Socket> s, const Address & addr)
{
  NS_LOG_DEBUG("ServerHandleConnectionCreated");
  s->SetRecvCallback (MakeCallback (&MpTcpMultihomedTestCase::ServerHandleRecv, this));
  s->SetSendCallback (MakeCallback (&MpTcpMultihomedTestCase::ServerHandleSend, this));

  // TODO setup tracing there !

  Ptr<MpTcpSocketBase> server_meta = DynamicCast<MpTcpSocketBase>(s);
  server_meta->SetupMetaTracing("server");
}

void
MpTcpMultihomedTestCase::ServerHandleRecv (Ptr<Socket> sock)
{
  NS_LOG_DEBUG("ServerHandleRecv, Rx available [" << sock->GetRxAvailable () << "]");
  while (sock->GetRxAvailable () > 0)
    {

      uint32_t toRead = std::min (m_serverReadSize, sock->GetRxAvailable ());
      NS_LOG_DEBUG("Rx Available [" << toRead );
      Ptr<Packet> p = sock->Recv (toRead, 0);
      if (p == 0 && sock->GetErrno () != Socket::ERROR_NOTERROR)
        {
          NS_FATAL_ERROR ("Server could not read stream at byte " << m_currentServerRxBytes);
        }
      NS_TEST_EXPECT_MSG_EQ ((m_currentServerRxBytes + p->GetSize () <= m_totalBytes), true,
                             "Server received too many bytes");
      NS_LOG_DEBUG ("Server recv data=\"" << GetString (p) << "\"");
      p->CopyData (&m_serverRxPayload[m_currentServerRxBytes], p->GetSize ());
      m_currentServerRxBytes += p->GetSize ();
      ServerHandleSend (sock, sock->GetTxAvailable ());
    }
}

void
MpTcpMultihomedTestCase::ServerHandleSend (Ptr<Socket> sock, uint32_t available)
{
  NS_LOG_DEBUG("ServerHandleSend: TxAvailable=" << available
        << " m_currentServerTxBytes=" << m_currentServerTxBytes
        << " m_currentServerRxBytes=" << m_currentServerRxBytes

        );

  // en fait la seconde condition est zarb : kesako ?
  while (sock->GetTxAvailable () > 0 && m_currentServerTxBytes < m_currentServerRxBytes)
    {
      uint32_t left = m_currentServerRxBytes - m_currentServerTxBytes;
      uint32_t toSend = std::min (left, sock->GetTxAvailable ());
      NS_LOG_DEBUG ("toSend=min(nbBytesLeft=" << left << ",m_serverWriteSize=" << m_serverWriteSize << ")");
      toSend = std::min (toSend, m_serverWriteSize);
      Ptr<Packet> p = Create<Packet> (&m_serverRxPayload[m_currentServerTxBytes], toSend);
      NS_LOG_DEBUG ("Server send data=\"" << GetString (p) << "\"");
      int sent = sock->Send (p);
      NS_TEST_EXPECT_MSG_EQ ((sent != -1), true, "Server error during send ?");
      m_currentServerTxBytes += sent;
    }
  if (m_currentServerTxBytes == m_totalBytes)
    {
      NS_LOG_DEBUG ("Server received all the data. Closing socket.");
      sock->Close ();
    }
}

void
MpTcpMultihomedTestCase::SourceHandleSend (Ptr<Socket> sock, uint32_t available)
{
  NS_LOG_DEBUG("SourceHandleSend with available = " << available
                  << " m_currentSourceTxBytes=" << m_currentSourceTxBytes
                  << " m_totalBytes=" << m_totalBytes
                  );
  while (sock->GetTxAvailable () > 0 && m_currentSourceTxBytes < m_totalBytes)
    {
      uint32_t left = m_totalBytes - m_currentSourceTxBytes;
      uint32_t toSend = std::min (left, sock->GetTxAvailable ());
      toSend = std::min (toSend, m_sourceWriteSize);
      NS_LOG_DEBUG ("toSend=min(nbBytesLeft=" << left << ",sourceWriteSize=" << m_sourceWriteSize << ")");
      Ptr<Packet> p = Create<Packet> (&m_sourceTxPayload[m_currentSourceTxBytes], toSend);
      NS_LOG_DEBUG ("Source send data=\"" << GetString (p) << "\"");
      int sent = sock->Send (p);
      NS_TEST_EXPECT_MSG_EQ ((sent != -1), true, "Error during send ?");
      m_currentSourceTxBytes += sent;
    }
}

void
MpTcpMultihomedTestCase::SourceHandleRecv (Ptr<Socket> sock)
{
  NS_LOG_DEBUG("SourceHandleRecv : m_currentSourceRxBytes=" << m_currentSourceRxBytes);
  while (sock->GetRxAvailable () > 0 && m_currentSourceRxBytes < m_totalBytes)
    {
      uint32_t toRead = std::min (m_sourceReadSize, sock->GetRxAvailable ());
      Ptr<Packet> p = sock->Recv (toRead, 0);
      if (p == 0 && sock->GetErrno () != Socket::ERROR_NOTERROR)
        {
          NS_FATAL_ERROR ("Source could not read stream at byte " << m_currentSourceRxBytes);
        }
      NS_TEST_EXPECT_MSG_EQ ((m_currentSourceRxBytes + p->GetSize () <= m_totalBytes), true,
                             "Source received too many bytes");

      p->CopyData (&m_sourceRxPayload[m_currentSourceRxBytes], p->GetSize ());
      m_currentSourceRxBytes += p->GetSize ();

      NS_LOG_DEBUG ("Source recv data=\"" << GetString (p) << "\". m_currentSourceRxBytes=" << m_currentSourceRxBytes);
    }
  if (m_currentSourceRxBytes == m_totalBytes)
    {
      NS_LOG_DEBUG ("Client received all the data. Closing socket.");
      sock->Close ();
    }
}

Ptr<Node>
MpTcpMultihomedTestCase::CreateInternetNode ()
{
  Ptr<Node> node = CreateObject<Node> ();
  //ARP
  Ptr<ArpL3Protocol> arp = CreateObject<ArpL3Protocol> ();
  node->AggregateObject (arp);
  //IPV4
  Ptr<Ipv4L3Protocol> ipv4 = CreateObject<Ipv4L3Protocol> ();
  //Routing for Ipv4
  Ptr<Ipv4ListRouting> ipv4Routing = CreateObject<Ipv4ListRouting> ();
  ipv4->SetRoutingProtocol (ipv4Routing);
  Ptr<Ipv4StaticRouting> ipv4staticRouting = CreateObject<Ipv4StaticRouting> ();
  ipv4Routing->AddRoutingProtocol (ipv4staticRouting, 0);
  node->AggregateObject (ipv4);
  //ICMP
  Ptr<Icmpv4L4Protocol> icmp = CreateObject<Icmpv4L4Protocol> ();
  node->AggregateObject (icmp);
  //UDP
  Ptr<UdpL4Protocol> udp = CreateObject<UdpL4Protocol> ();
  node->AggregateObject (udp);



  Ptr<TcpL4Protocol> tcp = CreateObject<TcpL4Protocol> ();
  node->AggregateObject (tcp);
  return node;
}

Ptr<SimpleNetDevice>
MpTcpMultihomedTestCase::AddSimpleNetDevice (Ptr<Node> node, const char* ipaddr, const char* netmask)
{
  Ptr<SimpleNetDevice> dev = CreateObject<SimpleNetDevice> ();
  dev->SetAddress (Mac48Address::ConvertFrom (Mac48Address::Allocate ()));
  node->AddDevice (dev);
  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
  uint32_t ndid = ipv4->AddInterface (dev);
  Ipv4InterfaceAddress ipv4Addr = Ipv4InterfaceAddress (Ipv4Address (ipaddr), Ipv4Mask (netmask));
  ipv4->AddAddress (ndid, ipv4Addr);
  ipv4->SetUp (ndid);
  return dev;
}

#if 0
Assign (const Ptr<NetDevice> &device)
{
  Ipv4InterfaceContainer retval;

  Ptr<Node> node = device->GetNode ();
  NS_ASSERT_MSG (node, "Ipv4AddressHelper::Assign(): NetDevice is not not associated "
                   "with any node -> fail");

  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
  NS_ASSERT_MSG (ipv4, "Ipv4AddressHelper::Assign(): NetDevice is associated"
                 " with a node without IPv4 stack installed -> fail "
                 "(maybe need to use InternetStackHelper?)");

  int32_t interface = ipv4->GetInterfaceForDevice (device);
  if (interface == -1)
    {
      interface = ipv4->AddInterface (device);
    }
  NS_ASSERT_MSG (interface >= 0, "Ipv4AddressHelper::Assign(): "
                 "Interface index not found");

  Ipv4InterfaceAddress ipv4Addr = Ipv4InterfaceAddress (, m_mask);
  ipv4->AddAddress (interface, ipv4Addr);
  ipv4->SetMetric (interface, 1);
  ipv4->SetUp (interface);
  retval.Add (ipv4, interface);
  return retval;
}
#endif


/**
relier chaque interface
nbIf
fullMesh /
In the future we should be able to havemore complex topologies
**/
void
MpTcpMultihomedTestCase::SetupDefaultSim (void)
{
  // TODO this number should be made configurable
  int nbOfDevices = 2;

  const char* netmask = "255.255.255.0";

//  const char* ipaddr1 = "192.168.1.2";
//  Ptr<Node> m_serverNode = CreateInternetNode ();
//  Ptr<Node> m_sourceNode = CreateInternetNode ();
  m_serverNode = CreateInternetNode ();
  m_sourceNode = CreateInternetNode ();


  for(int i = 0; i < nbOfDevices; ++i)
  {
//0s -1 MpTcpMultiSuite:SetupDefaultSim(): [DEBUG] setting ipv4 base 192.168.0.0
//0s -1 MpTcpMultiSuite:SetupDefaultSim(): [DEBUG] setting ipv4 base 192.168.1.0
//    const char* ipaddr0 = "";
    std::stringstream netAddr;
    netAddr << "192.168." << i << ".0";

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute ("DataRate", StringValue ("100Mbps"));
    p2p.SetChannelAttribute ("Delay", StringValue ("10ms"));
    NetDeviceContainer cont = p2p.Install(m_serverNode,m_sourceNode);
    p2p.EnablePcapAll("test", true);

    Ipv4AddressHelper ipv4;
    NS_LOG_DEBUG("setting ipv4 base " << netAddr.str());
    ipv4.SetBase( netAddr.str().c_str(), netmask);
    ipv4.Assign(cont);
    //ipv4.Assign(m_sourceNode);
    //Ptr<SimpleNetDevice> dev0 = AddSimpleNetDevice (m_serverNode, ipaddr0, netmask);
    //Ptr<SimpleNetDevice> dev1 = AddSimpleNetDevice (m_sourceNode, ipaddr1, netmask);

    /// Added by matt for debugging purposes
    //EnablePcapAll ("tcp-bulk-send", false);
    //TCP
  //  PcapHelperForDevice helper;
    //PointToPointHelper helper;
    //helper.EnablePcapAll("test",true);
    //helper.EnablePcapAll("testmptcp",false);

  }
  //pcap.EnablePcapInternal("mptcp",dev,true,true);

  //Ptr<SimpleChannel> channel = CreateObject<SimpleChannel> ();
  //dev0->SetChannel (channel);
  //dev1->SetChannel (channel);


//  Ptr<SocketFactory> sockFactory0 = m_serverNode->GetObject<MpTcpSocketFactory> ();
  Ptr<SocketFactory> sockFactory0 = m_serverNode->GetObject<TcpSocketFactory> ();
  Ptr<SocketFactory> sockFactory1 = m_sourceNode->GetObject<TcpSocketFactory> ();

  Ptr<Socket> server = sockFactory0->CreateSocket ();
  Ptr<Socket> source = sockFactory1->CreateSocket ();

  Ptr<MpTcpSocketBase> server_meta = DynamicCast<MpTcpSocketBase>(server);
  Ptr<MpTcpSocketBase> source_meta = DynamicCast<MpTcpSocketBase>(source);

//  server_meta->SetupMetaTracing("server");
  source_meta->SetupMetaTracing("source");




  /* We want to control over which socket the meta binds first
   GetAddress(interface, noIp);
   sachant que l'interface 0 est le loopback en fait
  */
  Ipv4Address serverMainAddr = m_serverNode->GetObject<Ipv4>()->GetAddress(1,0).GetLocal();
  InetSocketAddress serverlocaladdr (serverMainAddr, serverPort);
  InetSocketAddress serverremoteaddr (serverMainAddr, serverPort);
  NS_LOG_DEBUG("serverMainAddr" << serverlocaladdr);
  server->Bind (serverlocaladdr);
  server->Listen ();
  server->SetAcceptCallback (MakeNullCallback<bool, Ptr< Socket >, const Address &> (),
                             MakeCallback (&MpTcpMultihomedTestCase::ServerHandleConnectionCreated,this));

//  NS_LOG_INFO( "test" << server);
  source->SetRecvCallback (MakeCallback (&MpTcpMultihomedTestCase::SourceHandleRecv, this));
  source->SetSendCallback (MakeCallback (&MpTcpMultihomedTestCase::SourceHandleSend, this));

  source->Connect (serverremoteaddr);

  source->SetConnectCallback (
//    Callback< void, Ptr< Socket > > connectionSucceeded, Callback< void, Ptr< Socket > > connectionFailed
    MakeCallback (&MpTcpMultihomedTestCase::SourceConnectionSuccessful, this),
    MakeCallback (&MpTcpMultihomedTestCase::SourceConnectionFailed, this)

    );
}

void
MpTcpMultihomedTestCase::SetupDefaultSim6 (void)
{
  Ipv6Prefix prefix = Ipv6Prefix(64);
  Ipv6Address ipaddr0 = Ipv6Address("2001:0100:f00d:cafe::1");
  Ipv6Address ipaddr1 = Ipv6Address("2001:0100:f00d:cafe::2");
  Ptr<Node> m_serverNode = CreateInternetNode6 ();
  Ptr<Node> m_sourceNode = CreateInternetNode6 ();
  Ptr<SimpleNetDevice> dev0 = AddSimpleNetDevice6 (m_serverNode, ipaddr0, prefix);
  Ptr<SimpleNetDevice> dev1 = AddSimpleNetDevice6 (m_sourceNode, ipaddr1, prefix);

  Ptr<SimpleChannel> channel = CreateObject<SimpleChannel> ();
  dev0->SetChannel (channel);
  dev1->SetChannel (channel);

  Ptr<SocketFactory> sockFactory0 = m_serverNode->GetObject<TcpSocketFactory> ();
  Ptr<SocketFactory> sockFactory1 = m_sourceNode->GetObject<TcpSocketFactory> ();

  Ptr<Socket> server = sockFactory0->CreateSocket ();
  Ptr<Socket> source = sockFactory1->CreateSocket ();

  uint16_t serverPort = 50000;
  Inet6SocketAddress serverlocaladdr (Ipv6Address::GetAny (), serverPort);
  Inet6SocketAddress serverremoteaddr (ipaddr0, serverPort);

  server->Bind (serverlocaladdr);
  server->Listen ();
  server->SetAcceptCallback (MakeNullCallback<bool, Ptr< Socket >, const Address &> (),
                             MakeCallback (&MpTcpMultihomedTestCase::ServerHandleConnectionCreated,this));

  source->SetRecvCallback (MakeCallback (&MpTcpMultihomedTestCase::SourceHandleRecv, this));
  source->SetSendCallback (MakeCallback (&MpTcpMultihomedTestCase::SourceHandleSend, this));

  source->Connect (serverremoteaddr);
}

Ptr<Node>
MpTcpMultihomedTestCase::CreateInternetNode6 ()
{
  Ptr<Node> node = CreateObject<Node> ();
  //IPV6
  Ptr<Ipv6L3Protocol> ipv6 = CreateObject<Ipv6L3Protocol> ();
  //Routing for Ipv6
  Ptr<Ipv6ListRouting> ipv6Routing = CreateObject<Ipv6ListRouting> ();
  ipv6->SetRoutingProtocol (ipv6Routing);
  Ptr<Ipv6StaticRouting> ipv6staticRouting = CreateObject<Ipv6StaticRouting> ();
  ipv6Routing->AddRoutingProtocol (ipv6staticRouting, 0);
  node->AggregateObject (ipv6);
  //ICMP
  Ptr<Icmpv6L4Protocol> icmp = CreateObject<Icmpv6L4Protocol> ();
  node->AggregateObject (icmp);
  //Ipv6 Extensions
  ipv6->RegisterExtensions ();
  ipv6->RegisterOptions ();
  //UDP
  Ptr<UdpL4Protocol> udp = CreateObject<UdpL4Protocol> ();
  node->AggregateObject (udp);
  //TCP
  Ptr<TcpL4Protocol> tcp = CreateObject<TcpL4Protocol> ();
  node->AggregateObject (tcp);
  return node;
}

Ptr<SimpleNetDevice>
MpTcpMultihomedTestCase::AddSimpleNetDevice6 (Ptr<Node> node, Ipv6Address ipaddr, Ipv6Prefix prefix)
{
  Ptr<SimpleNetDevice> dev = CreateObject<SimpleNetDevice> ();
  dev->SetAddress (Mac48Address::ConvertFrom (Mac48Address::Allocate ()));
  node->AddDevice (dev);
  Ptr<Ipv6> ipv6 = node->GetObject<Ipv6> ();
  uint32_t ndid = ipv6->AddInterface (dev);
  Ipv6InterfaceAddress ipv6Addr = Ipv6InterfaceAddress (ipaddr, prefix);
  ipv6->AddAddress (ndid, ipv6Addr);
  ipv6->SetUp (ndid);
  return dev;
}

static class MpTcpMultihomedTestSuite : public TestSuite
{
public:
  MpTcpMultihomedTestSuite ()
    : TestSuite ("mptcp-tcp-multi", UNIT)
  {


    // TODO addition by matt
//    Config::SetDefault ("ns3::TcpL4Protocol::SocketType", StringValue("ns3::MpTcpCCOlia") );
    Config::SetDefault ("ns3::TcpL4Protocol::SocketType", StringValue("ns3::MpTcpCCUncoupled") );
//    Time::SetResolution (Time::MS);
    // Arguments to these test cases are 1) totalStreamSize,
    // 2) source write size, 3) source read size
    // 4) server write size, and 5) server read size
    // with units of bytes
//    AddTestCase (new MpTcpMultihomedTestCase (13, 200, 200, 200, 200, false), TestCase::QUICK);
//    AddTestCase (new MpTcpMultihomedTestCase (13, 1, 1, 1, 1, false), TestCase::QUICK);
//    AddTestCase (new MpTcpMultihomedTestCase (100000, 100, 50, 100, 20, false), TestCase::QUICK);

// here it's a test where I lower streamsize to see where it starts failing.
// 2100 is ok, 2200 fails
//    AddTestCase (new MpTcpMultihomedTestCase (5000, 100, 50, 100, 20, false), TestCase::EXTENSIVE);
    AddTestCase (new MpTcpMultihomedTestCase (5000, 100, 50, 100, 20, false), TestCase::QUICK);


    // Disable IPv6 tests; not supported yet
//    AddTestCase (new MpTcpMultihomedTestCase (13, 200, 200, 200, 200, true), TestCase::QUICK);
//    AddTestCase (new MpTcpMultihomedTestCase (13, 1, 1, 1, 1, true), TestCase::QUICK);
//    AddTestCase (new MpTcpMultihomedTestCase (100000, 100, 50, 100, 20, true), TestCase::QUICK);
  }

} g_tcpTestSuite;
