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

NS_LOG_COMPONENT_DEFINE("1p2pWithHelper2");

int
main(int argc, char *argv[])
{
  // Add some logging
  LogComponentEnable("1p2pWithHelper2", LOG_ALL);
  //LogComponentEnable("MpTcpSocketBase", LOG_INFO);
  LogComponentEnable("MpTcpBulkSendApplication", LOG_ALL);

  NS_LOG_INFO("Create nodes");
  NodeContainer c;
  c.Create(2);

  // Topology construction
  NodeContainer n0n1 = NodeContainer(c.Get(0), c.Get(1));

  NS_LOG_INFO("Install network stack");
  InternetStackHelper netStack;
  netStack.Install(c);

  NS_LOG_INFO("Create channel");
  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("0.5ms"));
  NetDeviceContainer d0d1 = p2p.Install(n0n1);

  NS_LOG_INFO("Assign IP addresses");
  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.0.1.0", "255.255.255.0");
  ipv4.Assign(d0d1);


  NS_LOG_INFO("Install Routing tables");
  Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  NS_LOG_INFO("Create Applications");

  // MPTCP SINK
  uint32_t servPort = 5000;
  MpTcpPacketSinkHelper sink ("ns3::TcpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), servPort));
  ApplicationContainer sinkApps = sink.Install (c.Get (1));
  sinkApps.Start (Seconds (0.0));
  sinkApps.Stop (Seconds (100.0));

  // MPTCP SOURCE
  MpTcpBulkSendHelper source("ns3::TcpSocketFactory", InetSocketAddress(Ipv4Address("10.0.1.2"), servPort));
  source.SetAttribute("MaxBytes", UintegerValue(10000000));
  source.SetAttribute("SendSize", UintegerValue(100000));
  ApplicationContainer sourceApps = source.Install(c.Get(0));
  sourceApps.Start(Seconds(0.0));
  sourceApps.Stop(Seconds(90.0));

  NS_LOG_INFO("Simulation run");
  Simulator::Run();
  Simulator::Stop(Seconds(100 + 10.0));
  Simulator::Destroy();
  NS_LOG_INFO("Simulation End");
}
