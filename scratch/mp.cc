#define NS_LOG_APPEND_CONTEXT \
  { std::clog << Simulator::Now ().GetSeconds ()<< "  ";}

// Network topology
//
//  n0
//     \ p-p
//      \          (shared csma/cd)
//       n2 -------------------------n3
//      /            |        |
//     / p-p        n4        n5 ---------- n6
//   n1                             p-p
//   |                                      |
//   ----------------------------------------
//                p-p
//
// - at time 1 CBR/UDP flow from n1 to n6's IP address on the n5/n6 link
// - at time 10, start similar flow from n1 to n6's address on the n1/n6 link
//
//  Order of events
//  At pre-simulation time, configure global routes.  Shortest path from
//  n1 to n6 is via the direct point-to-point link
//  At time 1s, start CBR traffic flow from n1 to n6
//  At time 2s, set the n1 point-to-point interface to down.  Packets
//    will be diverted to the n1-n2-n5-n6 path
//  At time 4s, re-enable the n1/n6 interface to up.  n1-n6 route restored.
//  At time 6s, set the n6-n1 point-to-point Ipv4 interface to down (note, this
//    keeps the point-to-point link "up" from n1's perspective).  Traffic will
//    flow through the path n1-n2-n5-n6
//  At time 8s, bring the interface back up.  Path n1-n6 is restored
//  At time 10s, stop the first flow.
//  At time 11s, start a new flow, but to n6's other IP address (the one
//    on the n1/n6 p2p link)
//  At time 12s, bring the n1 interface down between n1 and n6.  Packets
//    will be diverted to the alternate path
//  At time 14s, re-enable the n1/n6 interface to up.  This will change
//    routing back to n1-n6 since the interface up notification will cause
//    a new local interface route, at higher priority than global routing
//  At time 16s, stop the second flow.

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <stdint.h>
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/network-module.h"
#include "ns3/mptcp-module.h"
#include "ns3/csma-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/config-store-module.h"
#include "ns3/stats-module.h"

#include "ns3/flow-classifier.h"
#include "ns3/flow-monitor-module.h"

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("mptcp");

uint32_t LinkRate = 10000000;
uint32_t Delay = 0;
Time cDelay = MilliSeconds(Delay);
int totalSubflow = 2;
double LossRate = 0.0;
int MaxPackets = 100;
static const uint32_t totalTxBytes = 10000000; // 1 Mb
static const uint32_t sendBufSize = 14000; //2000000;
//static const uint32_t recvBufSize = 200000;
static uint32_t currentTxBytes = 0;
static const double simDuration = 1000.0;

Ptr<Node> client;
Ptr<Node> server;

static const uint32_t writeSize = sendBufSize;
uint8_t data[totalTxBytes];
Ptr<MpTcpSocketBase> lSocket;

void
StartFlow(Ptr<MpTcpSocketBase>, Ipv4Address, uint16_t);
void
WriteUntilBufferFull(Ptr<Socket>, unsigned int);
void
connectionSucceeded(Ptr<Socket>);
void
connectionFailed(Ptr<Socket>);
void
HandlePeerClose(Ptr<Socket>);
void
HandlePeerError(Ptr<Socket>);
void
CloseConnection(Ptr<Socket>);
void
SetupSocketParam(Ptr<MpTcpSocketBase>);
void
printIterator(std::map<FlowId, FlowMonitor::FlowStats>::const_iterator iter,
    Ptr<OutputStreamWrapper> output, const Ipv4FlowClassifier::FiveTuple &sFT)
{
  if (sFT.protocol == 17)
    {
      *output->GetStream() << "UDP: ";
    }
  if (sFT.protocol == 6)
    {
      *output->GetStream() << "TCP: ";
    }
  *output->GetStream() << "Flow " << iter->first << " (" << sFT.sourceAddress << " -> "
      << sFT.destinationAddress << ")\n";
  *output->GetStream() << "  Tx Bytes:   " << iter->second.txBytes << "\n";
  *output->GetStream() << "  Rx Bytes:   " << iter->second.rxBytes << "\n";
  *output->GetStream() << "  Packet Lost " << iter->second.lostPackets << "\n";
  *output->GetStream() << "  lastPacketSeen " << iter->second.timeLastRxPacket.GetSeconds() << "\n";
  *output->GetStream() << "  Rx Packets " << iter->second.rxPackets << "\n";
  *output->GetStream() << "  Tx Packets " << iter->second.txPackets << "\n";
  *output->GetStream() << "  Throughput: "
      << iter->second.rxBytes * 8.0
          / (iter->second.timeLastRxPacket.GetSeconds()
              - iter->second.timeFirstTxPacket.GetSeconds()) / 1000 / 1000 << " Mbps\n";
  *output->GetStream() << "  Flow Completion Time: "
      << (iter->second.timeLastRxPacket.GetSeconds() - iter->second.timeFirstTxPacket.GetSeconds())
      << " s\n";
}


int
main(int argc, char *argv[])
{
//  Config::SetDefault("ns3::ConfigStore::Filename", StringValue("MPTCP-attributes.xml"));
//  Config::SetDefault("ns3::ConfigStore::Mode", StringValue("Load"));
//  Config::SetDefault("ns3::ConfigStore::FileFormat", StringValue("Xml"));
//  ConfigStore inputConfig;
//  inputConfig.ConfigureDefaults ();

  Config::SetDefault("ns3::DropTailQueue::MaxPackets", UintegerValue(MaxPackets));
  Config::SetDefault("ns3::MpTcpSocketBase::CongestionControl", StringValue("Uncoupled_TCPs"));
//  Config::SetDefault("ns3::RateErrorModel::ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
//  Config::SetDefault("ns3::RateErrorModel::ErrorRate", StringValue("100"));

  LogComponentEnable("mptcp", LOG_LEVEL_LOGIC);
  LogComponentEnable("MpTcpSocketBase", LOG_INFO);
//  LogComponentEnable("MpTcpSocketBase", LOG_ALL);
//  LogComponentEnable("TcpL4Protocol", LOG_ALL);

  NS_LOG_INFO ("Create nodes.");
  NodeContainer c;
  c.Create(7);
  NodeContainer n0n2 = NodeContainer(c.Get(0), c.Get(2));
  NodeContainer n1n2 = NodeContainer(c.Get(1), c.Get(2));
  NodeContainer n5n6 = NodeContainer(c.Get(5), c.Get(6));
  NodeContainer n1n6 = NodeContainer(c.Get(1), c.Get(6));
  NodeContainer n2345 = NodeContainer(c.Get(2), c.Get(3), c.Get(4), c.Get(5));

  client = n1n2.Get(0);
  server = n5n6.Get(1);


  InternetStackHelper internet;
  internet.Install(c);

  // We create the channels first without any IP addressing information
  NS_LOG_INFO ("Create channels.");
  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("1ms"));
  NetDeviceContainer d0d2 = p2p.Install(n0n2);
  NetDeviceContainer d1d6 = p2p.Install(n1n6);

  NetDeviceContainer d1d2 = p2p.Install(n1n2);

  p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("1ms"));
  NetDeviceContainer d5d6 = p2p.Install(n5n6);

  // We create the channels first without any IP addressing information
  CsmaHelper csma;
  csma.SetChannelAttribute("DataRate", StringValue("10Mbps"));
  csma.SetChannelAttribute("Delay", StringValue("1ms"));
  NetDeviceContainer d2345 = csma.Install(n2345);

  // Later, we add IP addresses.
  NS_LOG_INFO ("Assign IP Addresses.");
  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.1.1.0", "255.255.255.0");
  ipv4.Assign(d0d2);

  ipv4.SetBase("10.1.2.0", "255.255.255.0");
  ipv4.Assign(d1d2);

  ipv4.SetBase("10.1.3.0", "255.255.255.0");
  Ipv4InterfaceContainer i5i6 = ipv4.Assign(d5d6);

  ipv4.SetBase("10.250.1.0", "255.255.255.0");
  ipv4.Assign(d2345);

  ipv4.SetBase("172.16.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i1i6 = ipv4.Assign(d1d6);

  // Create router nodes, initialize routing database and set up the routing
  // tables in the nodes.
  Ipv4GlobalRoutingHelper::PopulateRoutingTables();


//  Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(536));
//
//  // TCP packet sink
//  PacketSinkHelper h_mysink("ns3::TcpSocketFactory", Address(InetSocketAddress(Ipv4Address::GetAny(), 3000)));
//  ApplicationContainer mysinkApps = h_mysink.Install(server);
//  mysinkApps.Start(Seconds(0.0));
//
//  //  TCP Bulk (Flow0)    10.0.0.2 (term0) --> 10.0.2.3 (term4)
//  BulkSendHelper source("ns3::TcpSocketFactory", Address(InetSocketAddress("172.16.1.2", 3000)));
//  source.SetAttribute("MaxBytes", UintegerValue(0)); // Set the amount of data to send in bytes.  Zero is unlimited.
//  source.SetAttribute("SendSize", UintegerValue(536));    // Set Tcp segment size
//
//  ApplicationContainer sourceApps = source.Install(client);
//  sourceApps.Start(Seconds(0.0)); // Source Start time
//  sourceApps.Stop(Seconds(5.0));

  // MpTcp sink (Receiver Side)
  uint32_t servPort = 5000;
  Ptr<MpTcpPacketSink> sinkSocket = CreateObject<MpTcpPacketSink>();
  sinkSocket->SetAttribute("Local", AddressValue(InetSocketAddress(Ipv4Address::GetAny(), servPort)));
  server->AddApplication(sinkSocket);
  ApplicationContainer Apps;
  Apps.Add(sinkSocket);
  Apps.Start(Seconds(0.0));
  Apps.Stop(Seconds(simDuration));

//  /* Receiver side setup with Object Factory Model*/
////  ObjectFactory factory;
////  factory.SetTypeId("ns3::MpTcpPacketSink");
////  factory.Set("Local", AddressValue(InetSocketAddress(Ipv4Address::GetAny(), servPort)));
////  Ptr<Application> SinkApp = factory.Create<Application>();
////  server->AddApplication(SinkApp);
////  ApplicationContainer Apps;
////  Apps.Add(SinkApp);
//  //
//  // Sender side setup
  lSocket = CreateObject<MpTcpSocketBase>(client); //lSocket = new MpTcpSocketBase(client);
  lSocket->Bind();

  SetupSocketParam(lSocket);
  Simulator::ScheduleNow(&StartFlow, lSocket, "172.16.1.2", servPort);

  /* Downcasting object from Socket -> TcpSocketBase */
  //Ptr<TcpSocketBase> TcpsocketBase = localSocket->GetObject<TcpSocketBase>();
  //Ptr<TcpSocketBase> TcpsocketBase = DynamicCast<TcpSocketBase>(localSocket);
  //
  /* Retreive some data*/
  AsciiTraceHelper h_ascii;
//  std::string tr_file_name = "mmptcp.tr";
//  std::ofstream ascii;
//  Ptr<OutputStreamWrapper> ascii_wrap;
//  ascii.open(tr_file_name.c_str());
//  ascii_wrap = new OutputStreamWrapper(tr_file_name.c_str(), std::ios::out);
//  internetStackH.EnableAsciiIpv4All(ascii_wrap);

  /* Output ConfigStore to Xml format */
  Config::SetDefault("ns3::ConfigStore::Filename", StringValue("mmptcp-attributes.xml"));
  Config::SetDefault("ns3::ConfigStore::FileFormat", StringValue("Xml"));
  Config::SetDefault("ns3::ConfigStore::Mode", StringValue("Save"));
  ConfigStore outputConfig2;
  outputConfig2.ConfigureDefaults();
  outputConfig2.ConfigureAttributes();

  // Trace routing tables
  Ipv4GlobalRoutingHelper g;
  Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper>("mp.routes", std::ios::out);
  g.PrintRoutingTableAllAt(Seconds(0.5), routingStream);

  /* Flow Monitor Configuration */
  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll();

  Simulator::Stop(Seconds(simDuration + 10.0));
  Simulator::Run();


  monitor->CheckForLostPackets();

  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
  std::map<FlowId, FlowMonitor::FlowStats>::const_iterator iter;
  Ptr<OutputStreamWrapper> output = h_ascii.CreateFileStream("mptcp.Results");
  for (iter = stats.begin(); iter != stats.end(); ++iter)
    {
      Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(iter->first);
      if ((t.sourceAddress == "172.16.1.1" && t.destinationAddress == "172.16.1.2"))
        {
          printIterator(iter, output, t);
//        printIterator(*iter, output, t);
        }
      if ((t.sourceAddress == "10.1.2.1" && t.destinationAddress == "10.1.3.2"))
              {
                printIterator(iter, output, t);
      //        printIterator(*iter, output, t);
              }
    }
  monitor->SerializeToXmlFile("mptcp.flowmon", false, false);


  Simulator::Destroy();
  NS_LOG_LOGIC("mptcp:: simulation ended");
  return 0;
}

void
StartFlow(Ptr<MpTcpSocketBase> localSocket, Ipv4Address servAddress, uint16_t servPort)
{
  NS_LOG_FUNCTION_NOARGS();

  int connectionState = lSocket->Connect(servAddress, servPort);
  if (connectionState == 0)
    {
      lSocket->SetConnectCallback(MakeCallback(&connectionSucceeded), MakeCallback(&connectionFailed));
      lSocket->SetDataSentCallback(MakeCallback(&WriteUntilBufferFull));
      lSocket->SetCloseCallbacks(MakeCallback(&HandlePeerClose), MakeCallback(&HandlePeerError));
    }
  else
    {
      //localSocket->NotifyConnectionFailed();
      NS_LOG_LOGIC("mptcp:: connection failed");
    }
}

void
SetupSocketParam(Ptr<MpTcpSocketBase> lSocket)
{
//  lSocket->SetCongestionCtrlAlgo(Linked_Increases);
//  lSocket->SetCongestionCtrlAlgo(Fully_Coupled);
//  lSocket->SetCongestionCtrlAlgo(Uncoupled_TCPs);
//  lSocket->SetCongestionCtrlAlgo(RTT_Compensator);
  //lSocket->SetDataDistribAlgo(Round_Robin);
//  lSocket->SetMaxSubFlowNumber(11);
  //lSocket->SetSourceAddress(Ipv4Address("10.1.1.1"));
  lSocket->allocateSendingBuffer(sendBufSize);
  //lSocket->allocateRecvingBuffer(recvBufSize);
  lSocket->mod = 60;
  lSocket->totalBytes = totalTxBytes;
  lSocket->lostRate = LossRate;
  lSocket->LinkCapacity = LinkRate;
  lSocket->RTT = Delay * 2;
  lSocket->TimeScale = -5.0;
  lSocket->MSS = 1400; // Just for plot's info
}

void
connectionSucceeded(Ptr<Socket> localSocket)
{
  NS_LOG_FUNCTION_NOARGS();
  //NS_LOG_INFO("mptcp: Connection requeste succeed");
  Simulator::Schedule(Seconds(0.0), &WriteUntilBufferFull, lSocket, 0);
  Simulator::Schedule(Seconds(simDuration), &CloseConnection, lSocket);
}

void
connectionFailed(Ptr<Socket> localSocket)
{
  NS_LOG_FUNCTION_NOARGS();NS_LOG_INFO("mptcp: Connection requeste failure");
  lSocket->Close();
}

void
HandlePeerClose(Ptr<Socket> localSocket)
{
  NS_LOG_FUNCTION_NOARGS(); //
//  NS_LOG_INFO("mptcp: Connection closed by peer {HandlePeerClose}");
  lSocket->Close();
}

void
HandlePeerError(Ptr<Socket> localSocket)
{
  NS_LOG_FUNCTION_NOARGS();NS_LOG_INFO("mptcp: Connection closed by peer error");
  lSocket->Close();
}

void
CloseConnection(Ptr<Socket> localSocket)
{
  lSocket->Close();
  NS_LOG_LOGIC("mptcp:: currentTxBytes = " << currentTxBytes);         //
  NS_LOG_LOGIC("mptcp:: totalTxBytes   = " << totalTxBytes);           //
  NS_LOG_LOGIC("mptcp:: connection to remote host has been closed");   //
}

void
WriteUntilBufferFull(Ptr<Socket> localSocket, unsigned int txSpace)
{
  //NS_ASSERT(3!=3);
  while (currentTxBytes < totalTxBytes && lSocket->GetTxAvailable() > 0)
    {
      uint32_t left = totalTxBytes - currentTxBytes;
      uint32_t toWrite = std::min(writeSize, lSocket->GetTxAvailable());
      toWrite = std::min(toWrite, left);
      int amountBuffered = lSocket->FillBuffer(&data[currentTxBytes], toWrite);
      currentTxBytes += amountBuffered;
      lSocket->SendBufferedData();
    }
  if (currentTxBytes == totalTxBytes)
    {
      localSocket->Close();
    }
}
