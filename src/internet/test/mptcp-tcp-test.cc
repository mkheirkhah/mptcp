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

NS_LOG_COMPONENT_DEFINE ("MpTcpTestSuite");

using namespace ns3;

//std::ofstream source_f;
//std::ofstream server_f;

//void
////dumpNextTxSequence(Ptr<OutputStreamWrapper> stream, SequenceNumber32 oldSeq, SequenceNumber32 newSeq)
//dumpNextTxSequence(Ptr<OutputStreamWrapper> stream, std::string context, SequenceNumber32 oldSeq, SequenceNumber32 newSeq)
//{
//  //<< context <<
////  if (context == "NextTxSequence")
//
//  *stream->GetStream() << Simulator::Now() << "," << oldSeq << "," << newSeq << "\n";
//}
//
//
//void
//dumpUint32(Ptr<OutputStreamWrapper> stream, std::string context, uint32_t oldVal, uint32_t newVal) {
//
////  NS_LOG_UNCOND("Context " << context << "oldVal=" << oldVal << "newVal=" << newVal);
//
//  *stream->GetStream() << Simulator::Now() << "," << oldVal << "," << newVal << "\n";
//}



class MpTcpTestCase : public TestCase
{
public:
  MpTcpTestCase (uint32_t totalStreamSize,
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

  bool m_useIpv6;
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

MpTcpTestCase::MpTcpTestCase (uint32_t totalStreamSize,
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
    m_useIpv6 (useIpv6)
{
}

void
MpTcpTestCase::DoRun (void)
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

  NS_TEST_EXPECT_MSG_EQ (m_currentSourceTxBytes, m_totalBytes, "Source sent all bytes");
  NS_TEST_EXPECT_MSG_EQ (m_currentServerRxBytes, m_totalBytes, "Server received all bytes");
  NS_TEST_EXPECT_MSG_EQ (m_currentSourceRxBytes, m_totalBytes, "Source received all bytes");
  NS_TEST_EXPECT_MSG_EQ (memcmp (m_sourceTxPayload, m_serverRxPayload, m_totalBytes), 0,
                         "Server received expected data buffers");
  NS_TEST_EXPECT_MSG_EQ (memcmp (m_sourceTxPayload, m_sourceRxPayload, m_totalBytes), 0,
                         "Source received back expected data buffers");
}
void
MpTcpTestCase::DoTeardown (void)
{
  delete [] m_sourceTxPayload;
  delete [] m_sourceRxPayload;
  delete [] m_serverRxPayload;
  Simulator::Destroy ();
}

void
MpTcpTestCase::ServerHandleConnectionCreated (Ptr<Socket> s, const Address & addr)
{
  NS_LOG_DEBUG("ServerHandleConnectionCreated");
  s->SetRecvCallback (MakeCallback (&MpTcpTestCase::ServerHandleRecv, this));
  s->SetSendCallback (MakeCallback (&MpTcpTestCase::ServerHandleSend, this));

  // TODO setup tracing there !

  Ptr<MpTcpSocketBase> server_meta = DynamicCast<MpTcpSocketBase>(s);
  server_meta->SetupMetaTracing("server");
}

void
MpTcpTestCase::ServerHandleRecv (Ptr<Socket> sock)
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
MpTcpTestCase::ServerHandleSend (Ptr<Socket> sock, uint32_t available)
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
MpTcpTestCase::SourceHandleSend (Ptr<Socket> sock, uint32_t available)
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
MpTcpTestCase::SourceHandleRecv (Ptr<Socket> sock)
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
MpTcpTestCase::CreateInternetNode ()
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
MpTcpTestCase::AddSimpleNetDevice (Ptr<Node> node, const char* ipaddr, const char* netmask)
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

// Attach callbacks
//void
//SetupCallbacks(Ptr<Socket> sock,
////std::ofstream f,
//const std::string prefix)
//{
////  f.open(filename, std::ofstream::out | std::ofstream::trunc);
//
//  AsciiTraceHelper asciiTraceHelper;
//  Ptr<OutputStreamWrapper> streamNextTx = asciiTraceHelper.CreateFileStream (prefix+"_nextTx.csv");
//  Ptr<OutputStreamWrapper> streamHighest = asciiTraceHelper.CreateFileStream (prefix+"_highest.csv");
//  Ptr<OutputStreamWrapper> streamRxAvailable = asciiTraceHelper.CreateFileStream (prefix+"_RxAvailable.csv");
//  Ptr<OutputStreamWrapper> streamRxTotal = asciiTraceHelper.CreateFileStream (prefix+"_RxTotal.csv");
//  Ptr<OutputStreamWrapper> streamTx = asciiTraceHelper.CreateFileStream (prefix+"_Tx.csv");
//
//  *streamNextTx->GetStream() << "Time,oldNextTxSequence,newNextTxSequence\n";
//  *streamHighest->GetStream() << "Time,oldHighestSequence,newHighestSequence\n";
//  *streamRxAvailable->GetStream() << "Time,oldRxAvailable,newRxAvailable\n";
//  *streamRxTotal->GetStream() << "Time,oldRxTotal,newRxTotal\n";
//  *streamTx->GetStream() << "Time,oldTx,newTx\n";
//
////  , HighestSequence, RWND\n";
//
////  NS_ASSERT(f.is_open());
//
//  // TODO je devrais etre capable de voir les CongestionWindow + tailles de buffer/ Out of order
////  CongestionWindow
//
//  sock->TraceConnect ("NextTxSequence", "NextTxSequence", MakeBoundCallback(&dumpNextTxSequence, streamNextTx) );
////  sock->TraceConnect ("NextTxSequence", "NextTxSequence", MakeBoundCallback(&dumpNextTxSequence, streamNextTx) );
////  sock->TraceConnectWithoutContext ("NextTxSequence", MakeBoundCallback(&dumpNextTxSequence, stream) );
////  sock->TraceConnect ("NextTxSequence", "server", MakeBoundCallback(&dumpNextTxSequence) );
//
//
//  sock->TraceConnect ("HighestSequence", "HighestSequence", MakeBoundCallback(&dumpNextTxSequence, streamHighest) );
//
//  Ptr<MpTcpSocketBase> sock2 = DynamicCast<MpTcpSocketBase>(sock);
//  sock2->m_rxBuffer.TraceConnect ("RxTotal", "RxTotal", MakeBoundCallback(&dumpNextTxSequence, streamRxTotal) );
//  sock2->m_rxBuffer.TraceConnect ("RxAvailable", "RxAvailable", MakeBoundCallback(&dumpNextTxSequence, streamRxAvailable) );
//  sock2->m_txBuffer.TraceConnect ("UnackSequence", "UnackSequence", MakeBoundCallback(&dumpNextTxSequence, streamTx) );
////  sock->TraceConnect ("RWND", "RWND", MakeBoundCallback(&dumpUint32), stream);
//}


void
MpTcpTestCase::SetupDefaultSim (void)
{
  const char* netmask = "255.255.255.0";
  const char* ipaddr0 = "192.168.1.0";
//  const char* ipaddr1 = "192.168.1.2";
  Ptr<Node> node0 = CreateInternetNode ();
  Ptr<Node> node1 = CreateInternetNode ();

  PointToPointHelper p2p;

  p2p.SetDeviceAttribute ("DataRate", StringValue ("100Mbps"));
  p2p.SetChannelAttribute ("Delay", StringValue ("10ms"));
  NetDeviceContainer cont = p2p.Install(node0,node1);
  p2p.EnablePcapAll("test", true);

  Ipv4AddressHelper ipv4;
  ipv4.SetBase(ipaddr0,netmask);
  ipv4.Assign(cont);
  //ipv4.Assign(node1);
  //Ptr<SimpleNetDevice> dev0 = AddSimpleNetDevice (node0, ipaddr0, netmask);
  //Ptr<SimpleNetDevice> dev1 = AddSimpleNetDevice (node1, ipaddr1, netmask);

  /// Added by matt for debugging purposes
  //EnablePcapAll ("tcp-bulk-send", false);
  //TCP
//  PcapHelperForDevice helper;
  //PointToPointHelper helper;
  //helper.EnablePcapAll("test",true);
  //helper.EnablePcapAll("testmptcp",false);


  //pcap.EnablePcapInternal("mptcp",dev,true,true);

  //Ptr<SimpleChannel> channel = CreateObject<SimpleChannel> ();
  //dev0->SetChannel (channel);
  //dev1->SetChannel (channel);


//  Ptr<SocketFactory> sockFactory0 = node0->GetObject<MpTcpSocketFactory> ();
  Ptr<SocketFactory> sockFactory0 = node0->GetObject<TcpSocketFactory> ();
  Ptr<SocketFactory> sockFactory1 = node1->GetObject<TcpSocketFactory> ();

  Ptr<Socket> server = sockFactory0->CreateSocket ();
  Ptr<Socket> source = sockFactory1->CreateSocket ();

  Ptr<MpTcpSocketBase> server_meta = DynamicCast<MpTcpSocketBase>(server);
  Ptr<MpTcpSocketBase> source_meta = DynamicCast<MpTcpSocketBase>(source);

//  server_meta->SetupMetaTracing("server");
  source_meta->SetupMetaTracing("source");


  uint16_t port = 50000;
  InetSocketAddress serverlocaladdr (Ipv4Address::GetAny (), port);
  InetSocketAddress serverremoteaddr ( node0->GetObject<Ipv4>()->GetAddress(1,0).GetLocal(), port);

  server->Bind (serverlocaladdr);
  server->Listen ();
  server->SetAcceptCallback (MakeNullCallback<bool, Ptr< Socket >, const Address &> (),
                             MakeCallback (&MpTcpTestCase::ServerHandleConnectionCreated,this));

//  NS_LOG_INFO( "test" << server);
  source->SetRecvCallback (MakeCallback (&MpTcpTestCase::SourceHandleRecv, this));
  source->SetSendCallback (MakeCallback (&MpTcpTestCase::SourceHandleSend, this));

  source->Connect (serverremoteaddr);

}

void
MpTcpTestCase::SetupDefaultSim6 (void)
{
  Ipv6Prefix prefix = Ipv6Prefix(64);
  Ipv6Address ipaddr0 = Ipv6Address("2001:0100:f00d:cafe::1");
  Ipv6Address ipaddr1 = Ipv6Address("2001:0100:f00d:cafe::2");
  Ptr<Node> node0 = CreateInternetNode6 ();
  Ptr<Node> node1 = CreateInternetNode6 ();
  Ptr<SimpleNetDevice> dev0 = AddSimpleNetDevice6 (node0, ipaddr0, prefix);
  Ptr<SimpleNetDevice> dev1 = AddSimpleNetDevice6 (node1, ipaddr1, prefix);

  Ptr<SimpleChannel> channel = CreateObject<SimpleChannel> ();
  dev0->SetChannel (channel);
  dev1->SetChannel (channel);

  Ptr<SocketFactory> sockFactory0 = node0->GetObject<TcpSocketFactory> ();
  Ptr<SocketFactory> sockFactory1 = node1->GetObject<TcpSocketFactory> ();

  Ptr<Socket> server = sockFactory0->CreateSocket ();
  Ptr<Socket> source = sockFactory1->CreateSocket ();

  uint16_t port = 50000;
  Inet6SocketAddress serverlocaladdr (Ipv6Address::GetAny (), port);
  Inet6SocketAddress serverremoteaddr (ipaddr0, port);

  server->Bind (serverlocaladdr);
  server->Listen ();
  server->SetAcceptCallback (MakeNullCallback<bool, Ptr< Socket >, const Address &> (),
                             MakeCallback (&MpTcpTestCase::ServerHandleConnectionCreated,this));

  source->SetRecvCallback (MakeCallback (&MpTcpTestCase::SourceHandleRecv, this));
  source->SetSendCallback (MakeCallback (&MpTcpTestCase::SourceHandleSend, this));

  source->Connect (serverremoteaddr);
}

Ptr<Node>
MpTcpTestCase::CreateInternetNode6 ()
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
MpTcpTestCase::AddSimpleNetDevice6 (Ptr<Node> node, Ipv6Address ipaddr, Ipv6Prefix prefix)
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

static class MpTcpTestSuite : public TestSuite
{
public:
  MpTcpTestSuite ()
    : TestSuite ("mptcp-tcp", UNIT)
  {

    // TODO addition by matt
//    Config::SetDefault ("ns3::TcpL4Protocol::SocketType", StringValue("ns3::MpTcpCCOlia") );
    Config::SetDefault ("ns3::TcpL4Protocol::SocketType", StringValue("ns3::MpTcpCCUncoupled") );

    Time::SetResolution (Time::MS);
    // Arguments to these test cases are 1) totalStreamSize,
    // 2) source write size, 3) source read size
    // 4) server write size, and 5) server read size
    // with units of bytes
//    AddTestCase (new MpTcpTestCase (13, 200, 200, 200, 200, false), TestCase::QUICK);
//    AddTestCase (new MpTcpTestCase (13, 1, 1, 1, 1, false), TestCase::QUICK);
//    AddTestCase (new MpTcpTestCase (100000, 100, 50, 100, 20, false), TestCase::QUICK);

// here it's a test where I lower streamsize to see where it starts failing.
// 2100 is ok, 2200 fails
//    AddTestCase (new MpTcpTestCase (5000, 100, 50, 100, 20, false), TestCase::EXTENSIVE);
    AddTestCase (new MpTcpTestCase (5000, 100, 50, 100, 20, false), TestCase::QUICK);


    // Disable IPv6 tests; not supported yet
//    AddTestCase (new MpTcpTestCase (13, 200, 200, 200, 200, true), TestCase::QUICK);
//    AddTestCase (new MpTcpTestCase (13, 1, 1, 1, 1, true), TestCase::QUICK);
//    AddTestCase (new MpTcpTestCase (100000, 100, 50, 100, 20, true), TestCase::QUICK);
  }

} g_tcpTestSuite;
