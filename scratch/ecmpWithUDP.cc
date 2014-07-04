// This script illustrates the behavior of equal-cost multipath routing 
// (ECMP) with Ipv4 global routing, across three equal-cost paths
//
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
// - multiple UDP flows from n0 to n6
// - Tracing of queues and packet receptions to file "ecmp-global-routing.tr"
// - pcap traces on nodes n2, n3, and n4

#include <iostream>
#include <fstream>
#include <string>
#include <cassert>

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/internet-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("EcmpGlobalRoutingExample");

int 
main (int argc, char *argv[])
{
  uint32_t ecmpMode = 2;

  LogComponentEnable("Ipv4GlobalRouting", LOG_DEBUG);
  LogComponentEnable("Ipv4GlobalRouting", LOG_ERROR);
  LogComponentEnable("EcmpGlobalRoutingExample", LOG_ALL);


  // Allow the user to override any of the defaults and the above
  // Bind ()s at run-time, via command-line arguments
  CommandLine cmd;
  cmd.AddValue ("EcmpMode", "Ecmp Mode: (0 none, 1 random, 2 flow)", ecmpMode);
  cmd.Parse (argc, argv);

  switch (ecmpMode)
    {
      case 0:
        break;  //no ECMP
      case 1:
        Config::SetDefault ("ns3::Ipv4GlobalRouting::RandomEcmpRouting", BooleanValue (true));
        break;
      case 2:
        Config::SetDefault ("ns3::Ipv4GlobalRouting::FlowEcmpRouting", BooleanValue (true));
        break;  
      default:
        NS_FATAL_ERROR ("Illegal command value for EcmpMode: " << ecmpMode);
        break;
    }

  // Allow the user to override any of the defaults and the above

  NS_LOG_INFO ("Create nodes.");
  NodeContainer c;
  c.Create (7);
  NodeContainer n0n1 = NodeContainer (c.Get (0), c.Get (1));
  NodeContainer n1n2 = NodeContainer (c.Get (1), c.Get (2));
  NodeContainer n1n3 = NodeContainer (c.Get (1), c.Get (3));
  NodeContainer n1n4 = NodeContainer (c.Get (1), c.Get (4));
  NodeContainer n2n5 = NodeContainer (c.Get (2), c.Get (5));
  NodeContainer n3n5 = NodeContainer (c.Get (3), c.Get (5));
  NodeContainer n4n5 = NodeContainer (c.Get (4), c.Get (5));
  NodeContainer n5n6 = NodeContainer (c.Get (5), c.Get (6));

  InternetStackHelper internet;
  internet.Install (c);

  NS_LOG_INFO ("Create channels.");
  PointToPointHelper p2p;
  p2p.SetDeviceAttribute ("DataRate", StringValue ("10Mbps"));
  p2p.SetChannelAttribute ("Delay", StringValue ("1ms"));
  NetDeviceContainer d0d1 = p2p.Install (n0n1);
  NetDeviceContainer d1d2 = p2p.Install (n1n2);
  NetDeviceContainer d1d3 = p2p.Install (n1n3);
  NetDeviceContainer d1d4 = p2p.Install (n1n4);
  NetDeviceContainer d2d5 = p2p.Install (n2n5);
  NetDeviceContainer d3d5 = p2p.Install (n3n5);
  NetDeviceContainer d4d5 = p2p.Install (n4n5);
  NetDeviceContainer d5d6 = p2p.Install (n5n6);

  NS_LOG_INFO ("Assign IP Addresses.");
  Ipv4AddressHelper ipv4;
  ipv4.SetBase ("10.0.1.0", "255.255.255.0");
  ipv4.Assign (d0d1);
  ipv4.SetBase ("10.1.2.0", "255.255.255.0");
  ipv4.Assign (d1d2);
  ipv4.SetBase ("10.1.3.0", "255.255.255.0");
  ipv4.Assign (d1d3);
  ipv4.SetBase ("10.1.4.0", "255.255.255.0");
  ipv4.Assign (d1d4);
  ipv4.SetBase ("10.2.5.0", "255.255.255.0");
  ipv4.Assign (d2d5);
  ipv4.SetBase ("10.3.5.0", "255.255.255.0");
  ipv4.Assign (d3d5);
  ipv4.SetBase ("10.4.5.0", "255.255.255.0");
  ipv4.Assign (d4d5);
  ipv4.SetBase ("10.5.6.0", "255.255.255.0");
  ipv4.Assign (d5d6);

  NS_LOG_INFO ("Populate routing tables.");
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  NS_LOG_INFO ("Create Applications.");
  uint16_t port = 9;   // Discard port (RFC 863)
  OnOffHelper onoff ("ns3::UdpSocketFactory",
                     InetSocketAddress (Ipv4Address ("10.5.6.2"), port));
  onoff.SetConstantRate (DataRate ("100kbps"));
  onoff.SetAttribute ("PacketSize", UintegerValue (500));

  ApplicationContainer apps;
  for (uint32_t i = 0; i < 3; i++)
    {
      apps.Add (onoff.Install (c.Get (0)));
    }
  //apps.Add (onoff.Install (c.Get (1)));
  apps.Start (Seconds (1.0));
  apps.Stop (Seconds (5.0));

  PacketSinkHelper sink ("ns3::UdpSocketFactory",
                         Address (InetSocketAddress (Ipv4Address::GetAny (), port)));
  sink.Install (c.Get (6));

  // Trace the right-most (second) interface on nodes 2, 3, and 4
  p2p.EnablePcap ("ecmp-global-routing", 2, 2);
  p2p.EnablePcap ("ecmp-global-routing", 3, 2);
  p2p.EnablePcap ("ecmp-global-routing", 4, 2);

  NS_LOG_INFO ("Run Simulation.");
  Simulator::Run ();
  Simulator::Destroy ();
  NS_LOG_INFO("Simulation is ended!");
}
