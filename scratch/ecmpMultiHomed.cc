/*
 * Author: Morteza Kheirkhah <m.kheirkhah@sussex.ac.uk>
 *
// Network topology:
//           n2
//          /  \
//         /    \
//  n0---n1--n3--n5---n6
//   \     \    /     /
//    \     \  /     /
//     \     n4     /
//      \          /
//      n7---n8---n9
//
// - all links are point-to-point
// - MPTCP has two sub-flows; one from n0-n6 via n1 and the other from n0-n6 via n8.
*/

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

NS_LOG_COMPONENT_DEFINE("ecmpMultiHomed");

int
main(int argc, char *argv[])
{
  // Add some logging
  LogComponentEnable("ecmpMultiHomed", LOG_ALL);
  LogComponentEnable("MpTcpSocketBase", LOG_INFO);
  //LogComponentEnable("MpTcpBulkSendApplication", LOG_ALL);
  //LogComponentEnable("Ipv4GlobalRouting", LOG_DEBUG);

  /* Uncoupled_TCPs, Linked_Increases, RTT_Compensator, Fully_Coupled */
  Config::SetDefault ("ns3::MpTcpSocketBase::CongestionControl", StringValue("RTT_Compensator"));
  Config::SetDefault ("ns3::Ipv4GlobalRouting::FlowEcmpRouting", BooleanValue (true));

  // Topology construction
  NS_LOG_INFO("Create nodes");
  NodeContainer c;
  c.Create(10);

  // Topology construction
  NodeContainer n0n1 = NodeContainer(c.Get(0), c.Get(1));
  NodeContainer n1n2 = NodeContainer(c.Get(1), c.Get(2));
  NodeContainer n1n3 = NodeContainer(c.Get(1), c.Get(3));
  NodeContainer n1n4 = NodeContainer(c.Get(1), c.Get(4));
  NodeContainer n2n5 = NodeContainer(c.Get(2), c.Get(5));
  NodeContainer n3n5 = NodeContainer(c.Get(3), c.Get(5));
  NodeContainer n4n5 = NodeContainer(c.Get(4), c.Get(5));
  NodeContainer n5n6 = NodeContainer(c.Get(5), c.Get(6));
  // Direct point to point
  NodeContainer n0n7 = NodeContainer(c.Get(0), c.Get(7));
  NodeContainer n7n8 = NodeContainer(c.Get(7), c.Get(8));
  NodeContainer n8n9 = NodeContainer(c.Get(8), c.Get(9));
  NodeContainer n9n6 = NodeContainer(c.Get(9), c.Get(6));

  NS_LOG_INFO("Install network stack");
  InternetStackHelper netStack;
  netStack.Install(c);

  NS_LOG_INFO("Create channel");
  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("0.01ms"));
  NetDeviceContainer d0d1 = p2p.Install(n0n1);
  NetDeviceContainer d1d2 = p2p.Install(n1n2);
  NetDeviceContainer d1d3 = p2p.Install(n1n3);
  NetDeviceContainer d1d4 = p2p.Install(n1n4);
  NetDeviceContainer d2d5 = p2p.Install(n2n5);
  NetDeviceContainer d3d5 = p2p.Install(n3n5);
  NetDeviceContainer d4d5 = p2p.Install(n4n5);
  NetDeviceContainer d5d6 = p2p.Install(n5n6);
  // Direct p2p
  NetDeviceContainer d0d7 = p2p.Install(n0n7);
  NetDeviceContainer d7d8 = p2p.Install(n7n8);
  NetDeviceContainer d8d9 = p2p.Install(n8n9);
  NetDeviceContainer d9d6 = p2p.Install(n9n6);

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
  //
  ipv4.SetBase("10.0.7.0", "255.255.255.0");
  ipv4.Assign(d0d7);
  ipv4.SetBase("10.7.8.0", "255.255.255.0");
  ipv4.Assign(d7d8);
  ipv4.SetBase("10.8.9.0", "255.255.255.0");
  ipv4.Assign(d8d9);
  ipv4.SetBase("10.9.6.0", "255.255.255.0");
  ipv4.Assign(d9d6);

  NS_LOG_INFO("Install Routing tables");
  Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  NS_LOG_INFO("Create Applications");
  // MPTCP SINK
  uint32_t servPort = 5000;
  MpTcpPacketSinkHelper sink("ns3::TcpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), servPort));
  ApplicationContainer sinkApps = sink.Install(c.Get(6));
  sinkApps.Start(Seconds(0.0));
  sinkApps.Stop(Seconds(100.0));

  // MPTCP SOURCE
  MpTcpBulkSendHelper source("ns3::TcpSocketFactory", InetSocketAddress(Ipv4Address("10.5.6.2"), servPort));
  ApplicationContainer sourceApps = source.Install(c.Get(0));
  sourceApps.Start(Seconds(0.0));
  sourceApps.Stop(Seconds(100.0));

  NS_LOG_INFO("Simulation run");
  Simulator::Run();
  Simulator::Stop(Seconds(1000));
  Simulator::Destroy();
  NS_LOG_INFO("Simulation End");
}
