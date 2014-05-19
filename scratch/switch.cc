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
#include "ns3/core-module.h"
#include "ns3/global-route-manager.h"
#include "ns3/bridge-module.h"
#include "ns3/csma-helper.h"

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("mptcp");

uint32_t LinkRate = 1000000;
uint32_t Delay = 1;
Time cDelay = MilliSeconds(Delay);
int totalSubflow = 2;
double LossRate = 0.0;
static const uint32_t totalTxBytes = 4000000;
static const uint32_t sendBufSize = 200000; //2000000;
//static const uint32_t recvBufSize = 200000;
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
SetupSocketParam(Ptr<MpTcpSocketBase>);


int
main(int argc, char *argv[])
{
//  Config::SetDefault("ns3::DropTailQueue::MaxPackets", UintegerValue(30));
  ;
//  Config::SetDefault("ns3::DropTailQueue::Mode", StringValue("QUEUE_MODE_BYTES"));
//  Config::SetDefault("ns3::DropTailQueue::MaxBytes", UintegerValue(1400000));

//  Config::SetDefault("ns3::RateErrorModel::ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
//  Config::SetDefault("ns3::RateErrorModel::ErrorRate", StringValue("100"));

  LogComponentEnable("mptcp", LOG_LEVEL_LOGIC);
//  LogComponentEnable("MpTcpSocketBase", LOG_INFO);
//    LogComponentEnable("RttEstimator", LOG_ALL);
  //LogComponentEnable("TcpSocketBase", LOG_INFO);

  /* Build nodes. */
   NodeContainer term_0;
   term_0.Create (1);
   NodeContainer term_1;
   term_1.Create (1);
   NodeContainer bridge_0;
   bridge_0.Create (1);
   NodeContainer bridge_1;
   bridge_1.Create (1);

   client = term_0.Get(0);
   server = term_1.Get(0);

   /* Build link. */
   CsmaHelper csma_bridge_0;
   csma_bridge_0.SetChannelAttribute ("DataRate", DataRateValue (DataRate(LinkRate)));
   csma_bridge_0.SetChannelAttribute ("Delay",  TimeValue ((cDelay)));
   CsmaHelper csma_bridge_1;
   csma_bridge_1.SetChannelAttribute ("DataRate", DataRateValue (DataRate(LinkRate)));
   csma_bridge_1.SetChannelAttribute ("Delay",  TimeValue (cDelay));

   /* Build link net device container. */
   NodeContainer all_bridge_0;
   all_bridge_0.Add (term_0);
   all_bridge_0.Add (term_1);
   NetDeviceContainer terminalDevices_bridge_0;
   NetDeviceContainer BridgeDevices_bridge_0;
   for (int i = 0; i < 2; i++)
   {
    NetDeviceContainer link = csma_bridge_0.Install(NodeContainer(all_bridge_0.Get(i), bridge_0));
    terminalDevices_bridge_0.Add (link.Get(0));
    BridgeDevices_bridge_0.Add (link.Get(1));
   }
   BridgeHelper bridge_bridge_0;
   bridge_bridge_0.Install (bridge_0.Get(0), BridgeDevices_bridge_0);
   NetDeviceContainer ndc_bridge_0 = terminalDevices_bridge_0;
   NodeContainer all_bridge_1;
   all_bridge_1.Add (term_0);
   all_bridge_1.Add (term_1);
   NetDeviceContainer terminalDevices_bridge_1;
   NetDeviceContainer BridgeDevices_bridge_1;
   for (int i = 0; i < 2; i++)
   {
    NetDeviceContainer link = csma_bridge_1.Install(NodeContainer(all_bridge_1.Get(i), bridge_1));
    terminalDevices_bridge_1.Add (link.Get(0));
    BridgeDevices_bridge_1.Add (link.Get(1));
   }
   BridgeHelper bridge_bridge_1;
   bridge_bridge_1.Install (bridge_1.Get(0), BridgeDevices_bridge_1);
   NetDeviceContainer ndc_bridge_1 = terminalDevices_bridge_1;

   /* Install the IP stack. */
   InternetStackHelper internetStackH;
   internetStackH.Install (term_0);
   internetStackH.Install (term_1);

   /* IP assign. */
   Ipv4AddressHelper ipv4;
   ipv4.SetBase ("10.0.0.0", "255.255.255.0");
   Ipv4InterfaceContainer iface_ndc_bridge_0 = ipv4.Assign (ndc_bridge_0);
   ipv4.SetBase ("10.0.1.0", "255.255.255.0");
   Ipv4InterfaceContainer iface_ndc_bridge_1 = ipv4.Assign (ndc_bridge_1);

   /* Generate Route. */
   Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

   Config::SetDefault ("ns3::TcpSocket::SegmentSize", UintegerValue (1400));
////  // TCP packet sink
  PacketSinkHelper h_mysink("ns3::TcpSocketFactory", Address(InetSocketAddress("0.0.0.0", 3000)));
  ApplicationContainer mysinkApps = h_mysink.Install(server);
  mysinkApps.Start(Seconds(0.0));

  //  TCP Bulk (Flow0)    10.0.0.2 (term0) --> 10.0.2.3 (term4)
  BulkSendHelper source("ns3::TcpSocketFactory", Address(InetSocketAddress("10.0.0.2", 3000)));
  source.SetAttribute("MaxBytes", UintegerValue(0)); // Set the amount of data to send in bytes.  Zero is unlimited.
  source.SetAttribute("SendSize", UintegerValue(8000));    // Set Tcp segment size

  ApplicationContainer sourceApps = source.Install(client);
  sourceApps.Start(Seconds(1.0)); // Source Start time
  sourceApps.Stop(Seconds(30.0));

  // Configuration of the Client/Server application
//  uint32_t servPort = 5000;
//  ObjectFactory m_sf;
//  m_sf.SetTypeId("ns3::MpTcpPacketSink");
//  m_sf.Set("Local", AddressValue(InetSocketAddress(Ipv4Address::GetAny(), servPort)));
//  Ptr<Application> sapp = m_sf.Create<Application>();
//  server->AddApplication(sapp);
//  ApplicationContainer Apps;
//  Apps.Add(sapp);
//
//  Apps.Start(Seconds(0.0));
//  Apps.Stop(Seconds(simDuration));
//
//  lSocket = new MpTcpSocketBase(client);
//  lSocket->SetCongestionCtrlAlgo(Uncoupled_TCPs);
//  lSocket->SetDataDistribAlgo(Round_Robin);
//  lSocket->Bind();
//
//  SetupSocketParam(lSocket);
//
//  Simulator::ScheduleNow(&StartFlow, lSocket, "10.0.0.2", servPort);

  /* Output ConfigStore to Xml format */
  Config::SetDefault("ns3::ConfigStore::Filename", StringValue("MPTCP-att.xml"));
  Config::SetDefault("ns3::ConfigStore::FileFormat", StringValue("Xml"));
  Config::SetDefault("ns3::ConfigStore::Mode", StringValue("Save"));
  ConfigStore outputConfig2;
  outputConfig2.ConfigureDefaults();
  outputConfig2.ConfigureAttributes();

  Simulator::Stop(Seconds(simDuration + 10.0));
  Simulator::Run();
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
    lSocket->SetCongestionCtrlAlgo(RTT_Compensator);
  lSocket->SetDataDistribAlgo(Round_Robin);
  lSocket->SetMaxSubFlowNumber(11);
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
  Simulator::Schedule(Seconds(1.0), &WriteUntilBufferFull, lSocket, 0);
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
