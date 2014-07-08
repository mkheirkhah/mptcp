// Network topology
//
//           10Mb/s, 10ms
//       n0-----------------n1
//
// - Tracing of queues and packet receptions to file 
//   "tcp-large-transfer.tr"
// - pcap traces also generated in the following files
//   "tcp-large-transfer-$n-$i.pcap" where n and i represent node and interface
// numbers respectively
//  Usage (e.g.): ./waf --run tcp-large-transfer
#include <ctype.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cassert>

#include "ns3/core-module.h"
#include "ns3/applications-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/flow-classifier.h"
#include "ns3/flow-monitor-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TcpLargeTransfer");

uint32_t LinkRate = 100000000; // 10Mbps
uint32_t Delay = 1; // RTT: 2ms
Time cDelay = MilliSeconds(Delay);
double dtq = 65;
uint32_t segSize = 536;
static const uint32_t totalTxBytes = 10000000;
static uint32_t currentTxBytes = 0;
// Perform series of 1040 byte writes (this is a multiple of 26 since
// we want to detect data splicing in the output stream)
static const uint32_t writeSize = 1040;
uint8_t data[writeSize];

// These are for starting the writing process, and handling the sending 
// socket's notification upcalls (events).  These two together more or less
// implement a sending "Application", although not a proper ns3::Application
// subclass.
void
connectionFailed(Ptr<Socket> lSocket);
void
connectionSucceeded(Ptr<Socket>);
void
StartFlow(Ptr<Socket>, Ipv4Address, uint16_t);
void
WriteUntilBufferFull(Ptr<Socket>, uint32_t);
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
//CwndTracer (uint32_t oldval, uint32_t newval)
//{
//  NS_LOG_INFO ("Moving cwnd from " << oldval << " to " << newval);
//}

int
main(int argc, char *argv[])
{
  Config::SetDefault("ns3::DropTailQueue::MaxPackets", UintegerValue(dtq));
  Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(segSize));
  Config::SetDefault("ns3::TcpSocket::DelAckCount", UintegerValue(0));

// Users may find it convenient to turn on explicit debugging
// for selected modules; the below lines suggest how to do this
//  LogComponentEnable("TcpL4Protocol", LOG_LEVEL_ALL);
  LogComponentEnable("TcpSocketBase", LOG_DEBUG);
  LogComponentEnable("TcpLargeTransfer", LOG_LEVEL_ALL);
  //  LogComponentEnable("PacketSink", LOG_LEVEL_ALL);
  //LogComponentEnable("TcpLargeTransfer", LOG_LEVEL_ALL);
//  LogComponentEnable("TcpL4Protocol", LOG_LEVEL_ALL);
//  LogComponentEnable("Ipv4EndPointDemux", LOG_LEVEL_ALL);
//  LogComponentEnable("PacketSink", LOG_LEVEL_ALL);

  CommandLine cmd;
  cmd.Parse(argc, argv);

  // initialize the tx buffer.
  for (uint32_t i = 0; i < writeSize; ++i)
    {
      char m = toascii(97 + i % 26);
      data[i] = m;
    }

  // Here, we will explicitly create three nodes.  The first container contains
  // nodes 0 and 1 from the diagram above, and the second one contains nodes
  // 1 and 2.  This reflects the channel connectivity, and will be used to
  // install the network interfaces and connect them with a channel.
  NodeContainer n0n1;
  n0n1.Create(2);

//  NodeContainer n1n2;
//  n1n2.Add (n0n1.Get (1));
//  n1n2.Create (1);

  // We create the channels first without any IP addressing information
  // First make and configure the helper, so that it will put the appropriate
  // attributes on the network interfaces and channels we are about to install.
  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", DataRateValue(DataRate(LinkRate)));
  p2p.SetChannelAttribute("Delay", TimeValue(cDelay));

  // And then install devices and channels connecting our topology.
  NetDeviceContainer dev0 = p2p.Install(n0n1);
//  NetDeviceContainer dev1 = p2p.Install (n1n2);

  // Now add ip/tcp stack to all nodes.
  InternetStackHelper internet;
  internet.InstallAll();

  // Later, we add IP addresses.
  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.1.3.0", "255.255.255.0");
  Ipv4InterfaceContainer ipInterfs = ipv4.Assign(dev0);
//  ipv4.SetBase ("10.1.2.0", "255.255.255.0");
//  Ipv4InterfaceContainer ipInterfs = ipv4.Assign (dev1);

  // and setup ip routing tables to get total ip-level connectivity.
  Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  //
  // Error model
  //
//  Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
//  em->SetUnit(RateErrorModel::ERROR_UNIT_PACKET);
//  em->SetAttribute("ErrorRate", DoubleValue(0.1));
//  dev0.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(em));

//  Ptr<ReceiveListErrorModel> em = CreateObject<ReceiveListErrorModel>();
//  std::list < uint32_t > sl;
//  sl.push_back(21);
//  sl.push_back(22);
//  sl.push_back(23);
//  sl.push_back(25);
//  sl.push_back(30);
//  sl.push_back(36);
//  sl.push_back(46);
//  sl.push_back(56);
//  sl.push_back(58);
//  sl.push_back(60);
//  sl.push_back(62);
//  sl.push_back(75);
  //sampleList.push_back(1);
//  em->SetList(sl);
//  dev0.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(em));

  ///////////////////////////////////////////////////////////////////////////
  // Simulation 1
  //
  // Send 2000000 bytes over a connection to server port 50000 at time 0
  // Should observe SYN exchange, a lot of data segments and ACKS, and FIN 
  // exchange.  FIN exchange isn't quite compliant with TCP spec (see release
  // notes for more info)
  //
  ///////////////////////////////////////////////////////////////////////////

  uint16_t servPort = 50000;

  // Create a packet sink to receive these packets on n2...
  PacketSinkHelper sink("ns3::TcpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), servPort));

  ApplicationContainer apps = sink.Install(n0n1.Get(1));
  apps.Start(Seconds(0.0));
  apps.Stop(Seconds(10000.0));

  // Create a source to send packets from n0.  Instead of a full Application
  // and the helper APIs you might see in other example files, this example
  // will use sockets directly and register some socket callbacks as a sending
  // "Application".

  //Config::SetDefault("ns3::TcpSocket::DelAckCount", UintegerValue(0));
  // Create and bind the socket...
  Ptr<Socket> localSocket = Socket::CreateSocket(n0n1.Get(0), TcpSocketFactory::GetTypeId());
  localSocket->Bind();

  // Downcasting
  //Ptr<TcpSocketBase> TcpsocketBase = localSocket->GetObject<TcpSocketBase>();
  Ptr<TcpSocketBase> TcpsocketBase = DynamicCast<TcpSocketBase>(localSocket);
  TcpsocketBase->dtq_TCP = dtq;
  TcpsocketBase->lCapacity = LinkRate;
  TcpsocketBase->RTT_TCP = 2 * cDelay.GetMilliSeconds();
  TcpsocketBase->totalBytes_TCP = totalTxBytes;



  //NS_LOG_INFO("Initial SequenceNb: "<<TcpsocketBase->initialSeqNb);

  // Trace changes to the congestion window
  //Config::ConnectWithoutContext ("/NodeList/0/$ns3::TcpL4Protocol/SocketList/0/CongestionWindow", MakeCallback (&CwndTracer));

  // ...and schedule the sending "Application"; This is similar to what an 
  // ns3::Application subclass would do internally.
  //Simulator::ScheduleNow(&StartFlow, localSocket, ipInterfs.GetAddress(1), servPort);
  Simulator::Schedule(Seconds(0.0), &StartFlow, localSocket, ipInterfs.GetAddress(1), servPort);
  // One can toggle the comment for the following line on or off to see the
  // effects of finite send buffer modelling.  One can also change the size of
  // said buffer.

  //localSocket->SetAttribute("SndBufSize", UintegerValue(4096));

  //Ask for ASCII and pcap traces of network traffic
  AsciiTraceHelper ascii;
  p2p.EnableAsciiAll(ascii.CreateFileStream("tcp-large-transfer.tr"));
  p2p.EnablePcapAll("tcp-large-transfer");

  /* Flow Monitor Configuration */
  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll();

  // Finally, set up the simulator to run.  The 1000 second hard limit is a
  // failsafe in case some change above causes the simulation to never end
  Simulator::Stop(Seconds(1000));
  Simulator::Run();

  monitor->CheckForLostPackets();
  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
  std::map<FlowId, FlowMonitor::FlowStats>::const_iterator iter;
  Ptr<OutputStreamWrapper> output = ascii.CreateFileStream("tcp.Results");
  for (iter = stats.begin(); iter != stats.end(); ++iter)
    {
      Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(iter->first);
      if ((t.sourceAddress == "10.1.3.1" && t.destinationAddress == "10.1.3.2"))
        {
          printIterator(iter, output, t);
        }
    }
  monitor->SerializeToXmlFile("tcp.flowmon", false, false);

  Simulator::Destroy();
  NS_LOG_WARN("Simulation has Finished");
}
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//begin implementation of sending "Application"
void
StartFlow(Ptr<Socket> localSocket, Ipv4Address servAddress, uint16_t servPort)
{
  NS_LOG_FUNCTION_NOARGS();NS_LOG_WARN("Simulation Start");  //
  NS_LOG_LOGIC ("Starting flow at time " << Simulator::Now ().GetSeconds ());
  localSocket->Connect(InetSocketAddress(servAddress, servPort)); //connect

  // tell the tcp implementation to call WriteUntilBufferFull again
  // if we blocked and new tx buffer space becomes available
  localSocket->SetSendCallback(MakeCallback(&WriteUntilBufferFull));
  localSocket->SetConnectCallback(MakeCallback(&connectionSucceeded), MakeCallback(&connectionFailed));
  //WriteUntilBufferFull(localSocket, localSocket->GetTxAvailable());

}
void
connectionSucceeded(Ptr<Socket> lSocket)
{
  NS_LOG_FUNCTION_NOARGS();  //
  NS_LOG_LOGIC("TCP Flow will start after all subflows complete their 3WHSs @ " << Simulator::Now ().GetSeconds ());
  Simulator::ScheduleNow(&WriteUntilBufferFull, lSocket, 0);
  //Simulator::Schedule(Seconds(simDuration), &CloseConnection, lSocket);
}
void
connectionFailed(Ptr<Socket> lSocket)
{
  NS_LOG_FUNCTION_NOARGS();  //
  NS_LOG_INFO("Connection request has failed");
  //lSocket->Close();
}
void
WriteUntilBufferFull(Ptr<Socket> localSocket, uint32_t txSpace)
{
  //NS_LOG_FUNCTION_NOARGS();
  while (currentTxBytes < totalTxBytes && localSocket->GetTxAvailable() > 0)
    {
      uint32_t left = totalTxBytes - currentTxBytes;
      uint32_t dataOffset = currentTxBytes % writeSize;
      uint32_t toWrite = writeSize - dataOffset;
      toWrite = std::min(toWrite, left);
      toWrite = std::min(toWrite, localSocket->GetTxAvailable());
      int amountSent = localSocket->Send(&data[dataOffset], toWrite, 0);
      if (amountSent < 0)
        {
          // we will be called again when new tx space becomes available.
          return;
        }
      currentTxBytes += amountSent;
    }
  if (currentTxBytes == totalTxBytes)
    localSocket->Close();
}
