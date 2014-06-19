/*
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
// - multiple TCP flows from n0 to n6 (At most 4 flows in each separate paths)
// - we want to see how load splits as only source port is different in each flow!
*/
#define NS_LOG_APPEND_CONTEXT \
  { std::clog << Simulator::Now ().GetSeconds ()<< "  ";}

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/network-module.h"
#include "ns3/mptcp-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/config-store.h"
#include "ns3/file-config.h"
#include "ns3/gtk-config-store.h"
#include "ns3/flow-classifier.h"
#include "ns3/flow-monitor-module.h"

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("MpTcpNewReno");

uint32_t LinkRate = 100000000;
uint32_t Delay = 0.5;
Time cDelay = MilliSeconds(Delay);
double LossRate = 0.0;
double dtq = 100;
static const uint32_t totalTxBytes = 1000000;
static const uint32_t sendBufSize = 53600;
static uint32_t currentTxBytes = 0;
static const double simDuration = 1000.0;

Ptr<Node> client;
Ptr<Node> server;

static const uint32_t writeSize = sendBufSize;
uint8_t data[totalTxBytes];
Ptr<MpTcpSocketBase> lSocket = 0;

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
SetupDropPacket(Ptr<MpTcpSocketBase>);
void
SetupSocketParam(Ptr<MpTcpSocketBase>);

void
printIterator(std::map<FlowId, FlowMonitor::FlowStats>::const_iterator iter, Ptr<OutputStreamWrapper> output,
    const Ipv4FlowClassifier::FiveTuple &sFT)
{
  if (sFT.protocol == 17)
    {
      *output->GetStream() << "UDP: ";
    }
  if (sFT.protocol == 6)
    {
      *output->GetStream() << "TCP: ";
    }
  *output->GetStream() << "Flow " << iter->first << " (" << sFT.sourceAddress << " -> " << sFT.destinationAddress << ")\n";
  *output->GetStream() << "  Tx Bytes:   " << iter->second.txBytes << "\n";
  *output->GetStream() << "  Rx Bytes:   " << iter->second.rxBytes << "\n";
  *output->GetStream() << "  Packet Lost " << iter->second.lostPackets << "\n";
  *output->GetStream() << "  lastPacketSeen " << iter->second.timeLastRxPacket.GetSeconds() << "\n";
  *output->GetStream() << "  Rx Packets " << iter->second.rxPackets << "\n";
  *output->GetStream() << "  Tx Packets " << iter->second.txPackets << "\n";
  *output->GetStream() << "  Throughput: "
      << iter->second.rxBytes * 8.0 / (iter->second.timeLastRxPacket.GetSeconds() - iter->second.timeFirstTxPacket.GetSeconds()) / 1000 / 1000
      << " Mbps\n";
  *output->GetStream() << "  Flow Completion Time: " << (iter->second.timeLastRxPacket.GetSeconds() - iter->second.timeFirstTxPacket.GetSeconds())
      << " s\n";
}

int
main(int argc, char *argv[])
{
  /* Uncoupled_TCPs, Linked_Increases, RTT_Compensator, Fully_Coupled */
  Config::SetDefault ("ns3::MpTcpSocketBase::CongestionControl", StringValue("Uncoupled_TCPs"));
  Config::SetDefault ("ns3::DropTailQueue::MaxPackets", UintegerValue(dtq));
  Config::SetDefault ("ns3::Ipv4GlobalRouting::FlowEcmpRouting", BooleanValue (true));
  // TCP stuff
  Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(536));
  Config::SetDefault("ns3::TcpSocket::DelAckCount", UintegerValue(0));
  //Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(536));

  LogComponentEnable("MpTcpNewReno", LOG_LEVEL_ALL);
  LogComponentEnable("MpTcpSocketBase", LOG_INFO);
//  LogComponentEnable("Ipv4GlobalRouting", LOG_DEBUG);
//  LogComponentEnable("MpTcpSocketBase", LOG_WARN);
//  LogComponentEnable("MpTcpSocketBase", LOG_ALL);
//  LogComponentEnable("TcpL4Protocol", LOG_WARN);
//  LogComponentEnable("TcpHeader", LOG_ALL);
//  LogComponentEnable("Packet", LOG_ALL);
//  LogComponentEnable("MpTcpTypeDefs", LOG_WARN);

  /* Configuration. */

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

  client = c.Get(0);
  server = c.Get(6);

  //TCP

//  // TCP Receiver
//  PacketSinkHelper sinkTCP("ns3::TcpSocketFactory", Address(InetSocketAddress(Ipv4Address::GetAny(), 5002)));
//  sinkTCP.Install(server);
//
//  //  TCP Sender
//  BulkSendHelper source("ns3::TcpSocketFactory", Address(InetSocketAddress(Ipv4Address("10.5.6.2"), 5002)));
//  source.SetAttribute("MaxBytes", UintegerValue(10000000));
//  source.SetAttribute("SendSize", UintegerValue(500));
//  ApplicationContainer sourceApps = source.Install(client);
//  sourceApps.Start(Seconds(0.0));
//  sourceApps.Stop(Seconds(5.0));

//  // UDP
//  PacketSinkHelper sink = PacketSinkHelper("ns3::UdpSocketFactory", Address(InetSocketAddress(Ipv4Address::GetAny(), 5001)));
//  sink.Install(server);
//
//  OnOffHelper onoff = OnOffHelper("ns3::UdpSocketFactory", InetSocketAddress("10.5.6.2", 5001));
//  onoff.SetConstantRate(DataRate("10000Kbps"));
//  onoff.SetAttribute("PacketSize", UintegerValue(500));
//  onoff.SetAttribute("OffTime",  StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));
//  ApplicationContainer app = onoff.Install(client);
//  app.Start(Seconds(0.0));
//  app.Stop(Seconds(3.0));

  // MPTCP Server
  uint32_t servPort = 5000;
  Ptr<MpTcpPacketSink> sinkSocket = CreateObject<MpTcpPacketSink>();
  sinkSocket->SetAttribute("Local", AddressValue(InetSocketAddress(Ipv4Address::GetAny(), servPort)));
  server->AddApplication(sinkSocket);
  ApplicationContainer Apps;
  Apps.Add(sinkSocket);
  Apps.Start(Seconds(0.0));
  Apps.Stop(Seconds(simDuration));

  // MPTCP Client
  lSocket = CreateObject<MpTcpSocketBase>(client);
  lSocket->Bind();
  lSocket->SetSourceAddress("10.0.1.1");
  SetupSocketParam(lSocket);
  SetupDropPacket(lSocket);

  Simulator::ScheduleNow(&StartFlow, lSocket, "10.5.6.2", servPort);

  /* Output ConfigStore to XML format */
  Config::SetDefault("ns3::ConfigStore::Filename", StringValue("MPTCP-attributes.xml"));
  Config::SetDefault("ns3::ConfigStore::FileFormat", StringValue("Xml"));
  Config::SetDefault("ns3::ConfigStore::Mode", StringValue("Save"));
  ConfigStore outputConfig2;
  outputConfig2.ConfigureDefaults();
  outputConfig2.ConfigureAttributes();

  AsciiTraceHelper h_ascii;
  p2p.EnableAsciiAll(h_ascii.CreateFileStream("DC4.tr"));
  //p2p.EnablePcapAll("DC4", false);

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
      if ((t.sourceAddress == "10.0.0.2" && t.destinationAddress == "10.0.1.2"))
        {
          printIterator(iter, output, t);
        }
      if ((t.sourceAddress == "10.0.7.1" && t.destinationAddress == "10.9.6.2"))
        {
          printIterator(iter, output, t);
        }
      if ((t.sourceAddress == "10.0.2.2" && t.destinationAddress == "10.0.3.2"))
        {
          printIterator(iter, output, t);
        }
      if ((t.sourceAddress == "10.0.1.1" && t.destinationAddress == "10.5.6.2"))
        {
          printIterator(iter, output, t);
        }
    }
  monitor->SerializeToXmlFile("mptcp.flowmon", false, false);

  Simulator::Destroy();
  NS_LOG_LOGIC("MpTcpNewReno:: simulation ended");
  return 0;
}

void
StartFlow(Ptr<MpTcpSocketBase> localSocket, Ipv4Address servAddress, uint16_t servPort)
{
  int connectionState = lSocket->Connect(servAddress, servPort);
  if (connectionState == 0)
    {
      lSocket->SetConnectCallback(MakeCallback(&connectionSucceeded), MakeCallback(&connectionFailed));
      lSocket->SetDataSentCallback(MakeCallback(&WriteUntilBufferFull));
      lSocket->SetCloseCallbacks(MakeCallback(&HandlePeerClose), MakeCallback(&HandlePeerError));
      //Config::ConnectWithoutContext("/NodeList/0/$ns3::MpTcpSocketBase/subflows[0]/CongestionWindow", MakeCallback(&CwndTracer));
    }
  else
    {
      NS_LOG_LOGIC("MpTcpNewReno:: connection failed");
    }
}

void
SetupSocketParam(Ptr<MpTcpSocketBase> lSocket)
{
//  lSocket->SetCongestionCtrlAlgo(Uncoupled_TCPs);
  //lSocket->SetDataDistribAlgo(Round_Robin);
  //lSocket->SetSourceAddress(Ipv4Address("10.1.1.1"));
  //lSocket->SetMaxSubFlowNumber(11);
  //lSocket->allocateSendingBuffer(sendBufSize);
  lSocket->mod = 60;
  lSocket->totalBytes = totalTxBytes;
  lSocket->lostRate = dtq;
  lSocket->LinkCapacity = LinkRate;
  lSocket->RTT = Delay * 2;
  lSocket->TimeScale = -5.0;
  lSocket->MSS = 536; // Just for plot's info
}

void
SetupDropPacket(Ptr<MpTcpSocketBase> lSocket)
{
  // 2 drops
//  lSocket->sampleList.push_back(26);
//  lSocket->sampleList.push_back(47);

  // 4 drops on 3rd RTT. Entire window is lost, this is a demonstration of timeout operation
//  lSocket->sampleList.push_back(11);
//  lSocket->sampleList.push_back(12);
//  lSocket->sampleList.push_back(13);
//  lSocket->sampleList.push_back(14);
}

void
connectionSucceeded(Ptr<Socket> localSocket)
{
  NS_LOG_FUNCTION_NOARGS();  //
  NS_LOG_LOGIC("MpTcpNewReno:: MPTCP Flow will start after all subflows complete their 3WHSs @ " << Simulator::Now ().GetSeconds () + 1.0);
  Simulator::Schedule(Seconds(0.0), &WriteUntilBufferFull, lSocket, 0);
  Simulator::Schedule(Seconds(simDuration), &CloseConnection, lSocket);
}

void
connectionFailed(Ptr<Socket> localSocket)
{
  NS_LOG_FUNCTION_NOARGS();  //
  NS_LOG_INFO("MpTcpNewReno: Connection request has failed");
  lSocket->Close();
}

void
HandlePeerClose(Ptr<Socket> localSocket)
{
  NS_LOG_FUNCTION(localSocket);  //
  //NS_LOG_INFO("mpTopology:Connection closed by peer @ " << Simulator::Now().GetSeconds());
  //lSocket->Close();
}

void
HandlePeerError(Ptr<Socket> localSocket)
{
  NS_LOG_FUNCTION_NOARGS();  //
  NS_LOG_INFO("MpTcpNewReno: Connection closed by peer error");
  lSocket->Close();
}

void
CloseConnection(Ptr<Socket> localSocket)
{
  NS_LOG_FUNCTION_NOARGS();  //
  NS_LOG_LOGIC("MpTcpNewReno::currentTxBytes = " << currentTxBytes);  //
  NS_LOG_LOGIC("MpTcpNewReno::totalTxBytes   = " << totalTxBytes);   //
}

void
WriteUntilBufferFull(Ptr<Socket> localSocket, unsigned int txSpace)
{
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
    localSocket->Close();
}
