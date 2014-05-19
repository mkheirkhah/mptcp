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

#include "ns3/csma-module.h"

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("MpTcpNewReno");

uint32_t LinkRate = 100000000;
uint32_t Delay = 0.5;
Time cDelay = MilliSeconds(Delay);
double LossRate = 0.0;
double dtq = 100;
static const uint32_t totalTxBytes = 10000000;
static const uint32_t sendBufSize = 53600;
static uint32_t currentTxBytes = 0;
static const double simDuration = 1000.0;
static const double simPeriod = 10.0;

Ptr<Node> client;
Ptr<Node> client2;
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
      << iter->second.rxBytes * 8.0 / (iter->second.timeLastRxPacket.GetSeconds() - iter->second.timeFirstTxPacket.GetSeconds())
          / 1000 / 1000 << " Mbps\n";
  *output->GetStream() << "  Flow Completion Time: "
      << (iter->second.timeLastRxPacket.GetSeconds() - iter->second.timeFirstTxPacket.GetSeconds()) << " s\n";
}

static void
MacTxBackoff(Ptr<const Packet> p)
{
  NS_LOG_INFO ("MacTxBackoff at " << Simulator::Now ().GetSeconds ());
}
static void
PhyTxBegin(Ptr<const Packet> p)
{
  //NS_LOG_INFO ("PhyTxBegin at " << Simulator::Now ().GetSeconds ());
}
static void
Sniffer(Ptr<const Packet> p)
{
  //NS_LOG_INFO ("Sniffer at " << Simulator::Now ().GetSeconds ());
}
static void
MacTxDrop(Ptr<const Packet> p)
{
  NS_LOG_INFO ("MacTxDrop (drop before transmision) at " << Simulator::Now ().GetSeconds ());
}
static void
PhyTxDrop(Ptr<const Packet> p)
{
  NS_LOG_INFO ("PhyTxDrop (drop during transmision) at " << Simulator::Now ().GetSeconds ());
}

int
main(int argc, char *argv[])
{
  /* Uncoupled_TCPs, Linked_Increases, RTT_Compensator, Fully_Coupled */
  //Config::SetDefault("ns3::MpTcpSocketBase::CongestionControl", StringValue("Uncoupled_TCPs"));
  Config::SetDefault("ns3::DropTailQueue::Mode", StringValue("QUEUE_MODE_PACKETS"));
  Config::SetDefault("ns3::DropTailQueue::MaxPackets", UintegerValue(100));
  //Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(536));

  LogComponentEnable("MpTcpNewReno", LOG_LEVEL_ALL);
//  LogComponentEnable("MpTcpSocketBase", LOG_INFO);
//  LogComponentEnable("MpTcpSocketBase", LOG_ALL);
//  LogComponentEnable("TcpL4Protocol", LOG_ALL);
//  LogComponentEnable("TcpHeader", LOG_ALL);
//  LogComponentEnable("Packet", LOG_ALL);
//  LogComponentEnable("MpTcpTypeDefs", LOG_WARN);

  /* Configuration. */

  /* Build nodes. */
  NodeContainer term_0;
  term_0.Create(1);
  NodeContainer term_1;
  term_1.Create(1);
  NodeContainer term_2;
  term_2.Create(1);

  /* Build link. */
  //CSMA LINK
  CsmaHelper csma_hub_0;
  csma_hub_0.SetChannelAttribute("DataRate", DataRateValue(10000000));
  csma_hub_0.SetChannelAttribute("Delay", TimeValue(MilliSeconds(0.5)));
  // P2P Link
//  PointToPointHelper p2p_p2p_0;
//  p2p_p2p_0.SetDeviceAttribute("DataRate", DataRateValue(DataRate("10Mbps")));
//  p2p_p2p_0.SetChannelAttribute("Delay", TimeValue(MilliSeconds(1)));

  /* Build link net device container. */
  NodeContainer all_hub_0;
  all_hub_0.Add(term_0);
  all_hub_0.Add(term_1);
  all_hub_0.Add(term_2);
  NetDeviceContainer ndc_hub_0 = csma_hub_0.Install(all_hub_0);
//  NetDeviceContainer ndc_hub_0 = p2p_p2p_0.Install(all_hub_0);

  /* Install the IP stack. */
  InternetStackHelper internetStackH;
  internetStackH.Install(term_0);
  internetStackH.Install(term_1);
  internetStackH.Install(term_2);

  /* IP assign. */
  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.0.0.0", "255.255.255.0");
  Ipv4InterfaceContainer iface_ndc_hub_0 = ipv4.Assign(ndc_hub_0);

  /* Generate Route. */
  Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  client = term_0.Get(0);
  client2 = term_2.Get(0);
  server = term_1.Get(0);

  /* UDP Application. */
  // Create a packet sink on the star "hub" to receive these packets
  uint16_t port = 9;
  Address sinkLocalAddress(InetSocketAddress(Ipv4Address::GetAny(), port));
  PacketSinkHelper sinkHelper("ns3::UdpSocketFactory", sinkLocalAddress);
  ApplicationContainer sinkApp = sinkHelper.Install(server);
  sinkApp.Start(Seconds(0.0));
  sinkApp.Stop(Seconds(simPeriod));

  // Client1
  OnOffHelper clientHelper("ns3::UdpSocketFactory", Address());
  clientHelper.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
  clientHelper.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
  clientHelper.SetAttribute("PacketSize", UintegerValue(1400));
  clientHelper.SetAttribute("MaxBytes", UintegerValue(0));
  clientHelper.SetAttribute("DataRate", DataRateValue(DataRate("10Mbps")));
  //
  ApplicationContainer clientApps;
  AddressValue remoteAddress(InetSocketAddress(iface_ndc_hub_0.GetAddress(1), port));
  clientHelper.SetAttribute("Remote", remoteAddress);
  clientApps.Add(clientHelper.Install(client));
  clientApps.Start(Seconds(0.0));
  clientApps.Stop(Seconds(simPeriod));

  // Client2
  AddressValue remoteAddress2(InetSocketAddress(iface_ndc_hub_0.GetAddress(1), port));
  clientHelper.SetAttribute("Remote", remoteAddress2);
  clientApps.Add(clientHelper.Install(client2));
  clientApps.Start(Seconds(0.0));
  clientApps.Stop(Seconds(simPeriod));

// Create one udpServer applications on node one.
//  uint16_t port = 4000;
//  UdpServerHelper udpserver (port);
//  ApplicationContainer apps = udpserver.Install (server);
//  apps.Start (Seconds (0.0));
//  apps.Stop (Seconds (10.0));

// Create one UdpClient application to send UDP datagrams from node zero to node one.
//  uint32_t MaxPacketSize = 536;
//  Time interPacketInterval = Seconds(0.0);
//  uint32_t maxPacketCount = 500;
//  UdpClientHelper udpclient(iface_ndc_hub_0.GetAddress(1), port);
//  udpclient.SetAttribute("MaxPackets", UintegerValue(maxPacketCount));
//  udpclient.SetAttribute("Interval", TimeValue(interPacketInterval));
//  udpclient.SetAttribute("PacketSize", UintegerValue(MaxPacketSize));
//  apps = udpclient.Install(client);
//  apps.Start(Seconds(1.0));
//  apps.Stop(Seconds(10.0));

  /* TCP Application. */
//  Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(536));
//  Config::SetDefault("ns3::TcpSocket::DelAckCount", UintegerValue(0));
//   // TCP Receiver
//   //PacketSinkHelper h_mysink("ns3::TcpSocketFactory", Address(InetSocketAddress(Ipv4Address::GetAny(), 3000)));
//   ApplicationContainer mysinkApps = h_mysink.Install(server);
//   mysinkApps.Start(Seconds(0.0));
//   //  TCP Sender
//   BulkSendHelper source("ns3::TcpSocketFactory", Address(InetSocketAddress(iface_ndc_hub_0.GetAddress(1), 3000)));
//   source.SetAttribute("MaxBytes", UintegerValue(10000000)); // Set the amount of data to send in bytes.  Zero is unlimited.
//   source.SetAttribute("SendSize", UintegerValue(536));    // Set Tcp segment size
//   ApplicationContainer sourceApps = source.Install(client);
//   sourceApps.Start(Seconds(0.0)); // Source Start time
//   sourceApps.Stop(Seconds(10.0));
  /* MPTCP Application. */
  // MPTCP Server (Receiver)
//  uint32_t servPort = 5000;
//  Ptr<MpTcpPacketSink> sinkSocket = CreateObject<MpTcpPacketSink>();
//  sinkSocket->SetAttribute("Local", AddressValue(InetSocketAddress(Ipv4Address::GetAny(), servPort)));
//  server->AddApplication(sinkSocket);
//  ApplicationContainer Apps;
//  Apps.Add(sinkSocket);
//  Apps.Start(Seconds(0.0));
//  Apps.Stop(Seconds(simDuration));
//  // MPTCP Client (Sender)
//  lSocket = CreateObject<MpTcpSocketBase>(client); //lSocket = new MpTcpSocketBase(client);
//  lSocket->Bind(); //  lSocket->Bind();
//  SetupSocketParam(lSocket);
//  SetupDropPacket(lSocket);
//  Simulator::ScheduleNow(&StartFlow, lSocket, "10.0.0.2", servPort);
  /* Output ConfigStore to Xml format */

  ndc_hub_0.Get(0)->TraceConnectWithoutContext("MaxTxBackoff", MakeCallback(&MacTxBackoff));
  ndc_hub_0.Get(0)->TraceConnectWithoutContext("PhyTxBegin", MakeCallback(&PhyTxBegin));
  ndc_hub_0.Get(0)->TraceConnectWithoutContext("Sniffer", MakeCallback(&Sniffer));
  ndc_hub_0.Get(0)->TraceConnectWithoutContext("MacTxDrop", MakeCallback(&MacTxDrop));
  ndc_hub_0.Get(0)->TraceConnectWithoutContext("PhyTxDrop", MakeCallback(&PhyTxDrop));

  Config::SetDefault("ns3::ConfigStore::Filename", StringValue("MPTCP-attributes.xml"));
  Config::SetDefault("ns3::ConfigStore::FileFormat", StringValue("Xml"));
  Config::SetDefault("ns3::ConfigStore::Mode", StringValue("Save"));
  ConfigStore outputConfig2;
  outputConfig2.ConfigureDefaults();
  outputConfig2.ConfigureAttributes();

  AsciiTraceHelper h_ascii;
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
      if ((t.sourceAddress == "10.0.0.1" && t.destinationAddress == "10.0.0.2"))
        {
          printIterator(iter, output, t);
        }
      if ((t.sourceAddress == "10.0.0.3" && t.destinationAddress == "10.0.0.2"))
        {
          printIterator(iter, output, t);
        }
    }
  monitor->SerializeToXmlFile("mptcp.flowmon", false, false);
  //
  Simulator::Destroy();
  NS_LOG_INFO("Simulation end \n");
  Ptr<PacketSink> sink = DynamicCast<PacketSink>(sinkApp.Get(0));
  NS_LOG_UNCOND("UdpPacketSinkApp -> TotalRx: " << (sink->GetTotalRx()/1000000) << " MB");
  NS_LOG_UNCOND("UdpPacketSinkApp -> TotalThroughput: " << ((sink->GetTotalRx() * 8.0 / simPeriod)/1000000) << " Mbps") ;
  //
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
    }
  else
    {
      NS_LOG_LOGIC("MpTcpNewReno:: connection failed");
    }
}

void
SetupSocketParam(Ptr<MpTcpSocketBase> lSocket)
{
  lSocket->SetMaxSubFlowNumber(11);
  lSocket->allocateSendingBuffer(sendBufSize);
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
  NS_LOG_LOGIC("MpTcpNewReno::totalTxBytes   = " << totalTxBytes);  //
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
