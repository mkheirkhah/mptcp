// Network topology:
//
//           n2
//          /  \ all links
//         /    \  point-to-point
//  n0---n1--n3--n5----n6
//         \    /
//          \  /
//           n4
//
// - multiple TCP flows from n0 to n6 (At most 3 flows)
// - we want to see how load splits as only source port is different in each flow!
#include <stdint.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cassert>
#include "ns3/log.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/internet-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ECMP2");

int
main(int argc, char *argv[])
{
  // Add some logging
  LogComponentEnable("ECMP2", LOG_ALL);
  //LogComponentEnable("Ipv4GlobalRouting", LOG_DEBUG);
//  LogComponentEnable("MpTcpSocketBase", LOG_INFO);
  LogComponentEnable("MpTcpBulkSendApplication", LOG_ALL);
//  LogComponentEnable("MpTcpSocketBase", LOG_FUNCTION);

  // Activate the ECMP per flow
  Config::SetDefault("ns3::Ipv4GlobalRouting::FlowEcmpRouting", BooleanValue(true));

  NS_LOG_INFO("Create nodes");
  NodeContainer c;
  c.Create(7);

  // Topology construction
  NodeContainer n0n1 = NodeContainer(c.Get(0), c.Get(1));
  NodeContainer n1n2 = NodeContainer(c.Get(1), c.Get(2));
  NodeContainer n1n3 = NodeContainer(c.Get(1), c.Get(3));
  NodeContainer n1n4 = NodeContainer(c.Get(1), c.Get(4));
  NodeContainer n2n5 = NodeContainer(c.Get(2), c.Get(5));
  NodeContainer n3n5 = NodeContainer(c.Get(3), c.Get(5));
  NodeContainer n4n5 = NodeContainer(c.Get(4), c.Get(5));
  NodeContainer n5n6 = NodeContainer(c.Get(5), c.Get(6));

  NS_LOG_INFO("Install network stack");
  InternetStackHelper netStack;
  netStack.Install(c);

  NS_LOG_INFO("Create channel");
  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("0.5ms"));
  NetDeviceContainer d0d1 = p2p.Install(n0n1);
  NetDeviceContainer d1d2 = p2p.Install(n1n2);
  NetDeviceContainer d1d3 = p2p.Install(n1n3);
  NetDeviceContainer d1d4 = p2p.Install(n1n4);
  NetDeviceContainer d2d5 = p2p.Install(n2n5);
  NetDeviceContainer d3d5 = p2p.Install(n3n5);
  NetDeviceContainer d4d5 = p2p.Install(n4n5);
  NetDeviceContainer d5d6 = p2p.Install(n5n6);

  NS_LOG_INFO("Assign IP addresses");
  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.0.1.0", "255.255.255.0");
  ipv4.Assign(d0d1);
  ipv4.SetBase("10.1.2.0", "255.255.255.0");
  ipv4.Assign(d1d2);
  ipv4.SetBase("10.1.3.0", "255.255.255.0");
  ipv4.Assign(d1d3);
  ipv4.SetBase("10.1.4.0", "255.255.255.0");
  ipv4.Assign(d1d4);
  ipv4.SetBase("10.2.5.0", "255.255.255.0");
  ipv4.Assign(d2d5);
  ipv4.SetBase("10.3.5.0", "255.255.255.0");
  ipv4.Assign(d3d5);
  ipv4.SetBase("10.4.5.0", "255.255.255.0");
  ipv4.Assign(d4d5);
  ipv4.SetBase("10.5.6.0", "255.255.255.0");
  ipv4.Assign(d5d6);

  NS_LOG_INFO("Install Routing tables");
  Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  NS_LOG_INFO("Create Applications");

  //Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(536));
  //Config::SetDefault("ns3::TcpSocket::DelAckCount", UintegerValue(0));

//  // TCP Receiver
//  PacketSinkHelper sinkTCP("ns3::TcpSocketFactory", Address(InetSocketAddress(Ipv4Address::GetAny(), 10)));
//  sinkTCP.Install(c.Get(6));
//
//  //  TCP Sender
//  BulkSendHelper source("ns3::TcpSocketFactory", Address(InetSocketAddress(Ipv4Address("10.5.6.2"), 10)));
//  source.SetAttribute("MaxBytes", UintegerValue(10000000));
//  source.SetAttribute("SendSize", UintegerValue(500));
//  ApplicationContainer sourceApps = source.Install(c.Get(0));
//  sourceApps.Start(Seconds(1.1));
//  sourceApps.Stop(Seconds(5.1));

  // MPTCP SINK
  uint32_t servPort = 5000;
  Ptr<MpTcpPacketSink> sinkSocket = CreateObject<MpTcpPacketSink>();
  sinkSocket->SetAttribute("Local", AddressValue(InetSocketAddress(Ipv4Address::GetAny(), servPort)));
  Ptr<Node> server = c.Get(6);
  server->AddApplication(sinkSocket);
  ApplicationContainer Apps;
  Apps.Add(sinkSocket);
  Apps.Start(Seconds(0.0));
  //Apps.Stop(Seconds(100));

  //  MPTCP SOURCE
  Ptr<MpTcpBulkSendApplication> src = CreateObject<MpTcpBulkSendApplication>();
  src->SetAttribute("Remote", AddressValue(Address(InetSocketAddress(Ipv4Address("10.5.6.2"), servPort))));
  //BulkSendHelper source("ns3::TcpSocketFactory", Address(InetSocketAddress(Ipv4Address("10.5.6.2"), 10)));
  src->SetAttribute("MaxBytes", UintegerValue(10000000));
  src->SetAttribute("SendSize", UintegerValue(5000));
  src->Printer();
  Ptr<Node> client = c.Get(0);
  client->AddApplication(src);
  Apps.Add(src);
  Apps.Start(Seconds(1.1));
  Apps.Stop(Seconds(100));

//  // UDP packet sink
//  PacketSinkHelper sink("ns3::UdpSocketFactory", Address(InetSocketAddress(Ipv4Address::GetAny(), 9)));
//  sink.Install(c.Get(6));
//
//  // UDP packet source
//  OnOffHelper onoff("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address("10.5.6.2"), 9));
//  onoff.SetConstantRate(DataRate("100Kbps"));
//  onoff.SetAttribute("PacketSize", UintegerValue(500));
//  ApplicationContainer apps;
//  for (uint32_t i = 0; i < 1; i++)
//    {
//      apps.Add(onoff.Install(c.Get(0)));
//    }
//  apps.Start(Seconds(1.0));
//  apps.Stop(Seconds(5.0));

  NS_LOG_INFO("Simulation run");
  Simulator::Run();
  Simulator::Destroy();
  NS_LOG_INFO("Simulation End");
}
