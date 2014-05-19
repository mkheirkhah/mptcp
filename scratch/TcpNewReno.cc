#define NS_LOG_APPEND_CONTEXT \
  { std::clog << Simulator::Now ().GetSeconds ()<< "  ";}

#include <sstream>
#include <string>
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

//       10.1.1.0
//   n1 ------------ n2

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("NewRenoTCP");

uint32_t LinkRate = 10000000;
uint32_t Delay = 1;
Time cDelay = MilliSeconds(Delay);
double dtq = 30;
static const double simDuration = 1000.0;

Ptr<Node> client;
Ptr<Node> server;

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

//static void
//CwndTracer(uint32_t oldval, uint32_t newval)
//{
//  NS_LOG_INFO ("Moving cwnd from " << oldval << " to " << newval);
//}

int
main(int argc, char *argv[])
{
  Config::SetDefault("ns3::DropTailQueue::MaxPackets", UintegerValue(dtq));
  Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1400));
  Config::SetDefault("ns3::TcpSocket::DelAckCount", UintegerValue(0));

  LogComponentEnable("NewRenoTCP", LOG_LEVEL_ALL);
//  LogComponentEnable("MpTcpSocketBase", LOG_INFO);
//    LogComponentEnable("MpTcpSocketBase", LOG_ERROR);
//  LogComponentEnable("TcpL4Protocol", LOG_DEBUG);
//  LogComponentEnable("TcpHeader", LOG_ALL);
//  LogComponentEnable("Packet", LOG_ALL);
  LogComponentEnable("MpTcpTypeDefs", LOG_ERROR);

// Creation of the hosts
  NodeContainer nodes;
  nodes.Create(2);

  client = nodes.Get(0);
  server = nodes.Get(1);

  InternetStackHelper stack;
  stack.Install(nodes);

  PointToPointHelper p2plink;
  p2plink.SetDeviceAttribute("DataRate", DataRateValue(DataRate(LinkRate)));
  p2plink.SetChannelAttribute("Delay", TimeValue(cDelay));

  NetDeviceContainer netDevices;
  netDevices = p2plink.Install(nodes);

// Attribution of the IP addresses
  Ipv4AddressHelper ipv4addr;
  ipv4addr.SetBase("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer interface = ipv4addr.Assign(netDevices);

  vector<Ipv4InterfaceContainer> ipv4Ints;
  ipv4Ints.insert(ipv4Ints.end(), interface);

  /*  Application */

   // TCP packet sink
   PacketSinkHelper h_mysink("ns3::TcpSocketFactory", Address(InetSocketAddress(Ipv4Address::GetAny(), 3000)));
   ApplicationContainer mysinkApps = h_mysink.Install(server);
   mysinkApps.Start(Seconds(0.0));

   //  TCP Bulk
   BulkSendHelper source("ns3::TcpSocketFactory", Address(InetSocketAddress(ipv4Ints[0].GetAddress(1), 3000)));
   source.SetAttribute("MaxBytes", UintegerValue(10000000)); // Set the amount of data to send in bytes.  Zero is unlimited.
   source.SetAttribute("SendSize", UintegerValue(536));    // Set Tcp segment size
   ApplicationContainer sourceApps = source.Install(client);
   sourceApps.Start(Seconds(0.0)); // Source Start time
   sourceApps.Stop(Seconds(10.0));

  /* Output ConfigStore to Xml format */
  Config::SetDefault("ns3::ConfigStore::Filename", StringValue("MPTCP-attributes.xml"));
  Config::SetDefault("ns3::ConfigStore::FileFormat", StringValue("Xml"));
  Config::SetDefault("ns3::ConfigStore::Mode", StringValue("Save"));
  ConfigStore outputConfig2;
  outputConfig2.ConfigureDefaults();
  outputConfig2.ConfigureAttributes();

//  Ptr<ReceiveListErrorModel> em = CreateObject<ReceiveListErrorModel>();
//  std::list < uint32_t > sl;
//  sl.push_back(22);
//  em->SetList(sl);
//  netDevices.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(em));

//  PointerValue pv;
//  netDevices.Get(0)->GetAttribute("TxQueue", pv);
//  Ptr<Queue> dtq = pv.Get<Queue>();
//  dtq->TraceConnectWithoutContext("Drop", MakeCallback(&DropQueue));
//
//  Ptr<NetDevice> netDev = netDevices.Get(0);
//  UintegerValue Uv;
//  netDev->GetAttribute("Mtu", Uv);
//  NS_LOG_ERROR("MTU: " << Uv.Get());

//ErroModel
//  Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
//  em->SetUnit(RateErrorModel::ERROR_UNIT_PACKET);
//  em->SetRate(0.1); //Subflow1
//  netDevices.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(em));

// ListErrorModel
//  std::list< uint32_t> list;
//  list.push_back(50);
//  Ptr<ListErrorModel> em = CreateObject<ListErrorModel>();
//  em->SetList(list);
//  Ptr<NetDevice> _server = server->GetDevice(1);
//  _server->SetAttribute("ReceiveErrorModel", PointerValue(em));
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
      if ((t.sourceAddress == "10.1.1.1" && t.destinationAddress == "10.1.1.2"))
        {
          printIterator(iter, output, t);
        }
    }
  monitor->SerializeToXmlFile("mptcp.flowmon", false, false);

  Simulator::Destroy();
  NS_LOG_LOGIC("NewRenoTCP:: simulation ended");
  return 0;
}
