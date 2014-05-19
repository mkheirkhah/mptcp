#define NS_LOG_APPEND_CONTEXT \
  { std::clog << Simulator::Now ().GetSeconds ()<< "  ";}

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

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("mptcp");

uint32_t LinkRate = 100000000;
uint32_t Delay = 50;
Time cDelay = MilliSeconds(Delay);
int totalSubflow = 2;
double LossRate = 0.0;
int MaxPackets = 30;
static const uint32_t totalTxBytes = 1000000;
static const uint32_t sendBufSize = 200000; //2000000;
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

int
main(int argc, char *argv[])
{
//  Config::SetDefault("ns3::ConfigStore::Filename", StringValue("MPTCP-attributes.xml"));
//  Config::SetDefault("ns3::ConfigStore::Mode", StringValue("Load"));
//  Config::SetDefault("ns3::ConfigStore::FileFormat", StringValue("Xml"));
//  ConfigStore inputConfig;
//  inputConfig.ConfigureDefaults ();

  Config::SetDefault("ns3::DropTailQueue::MaxPackets", UintegerValue(MaxPackets));
  Config::SetDefault("ns3::MpTcpSocketBase::CongestionControl", StringValue("RTT_Compensator"));
//  Config::SetDefault("ns3::RateErrorModel::ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
//  Config::SetDefault("ns3::RateErrorModel::ErrorRate", StringValue("100"));

  LogComponentEnable("mptcp", LOG_LEVEL_LOGIC);
//  LogComponentEnable("MpTcpSocketBase", LOG_ALL);
    LogComponentEnable("MpTcpSocketBase", LOG_INFO);
//  LogComponentEnable("TcpL4Protocol", LOG_INFO);

  /* Build nodes. */
  NodeContainer router_0;
  router_0.Create(1);
  NodeContainer term_0;
  term_0.Create(1);
  NodeContainer term_1;
  term_1.Create(1);
  NodeContainer term_2;
  term_2.Create(1);

  client = term_0.Get(0);
  server = term_1.Get(0);

  /* Build link. */
  CsmaHelper csma_hub_0;
  csma_hub_0.SetChannelAttribute("DataRate", DataRateValue(DataRate(LinkRate)));
  csma_hub_0.SetChannelAttribute("Delay", TimeValue(cDelay));
  CsmaHelper csma_hub_1;
  csma_hub_1.SetChannelAttribute("DataRate", DataRateValue(DataRate(LinkRate)));
  csma_hub_1.SetChannelAttribute("Delay", TimeValue(cDelay));
  CsmaHelper csma_hub_2;
  csma_hub_2.SetChannelAttribute("DataRate", DataRateValue(DataRate(LinkRate)));
  csma_hub_2.SetChannelAttribute("Delay", TimeValue(cDelay));
  CsmaHelper csma_hub_3;
  csma_hub_3.SetChannelAttribute("DataRate", DataRateValue(DataRate(LinkRate)));
  csma_hub_3.SetChannelAttribute("Delay", TimeValue(cDelay));

  /* Build link net device container. */
  NodeContainer all_hub_0;
  all_hub_0.Add(router_0);
  all_hub_0.Add(term_2);
  NetDeviceContainer ndc_hub_0 = csma_hub_0.Install(all_hub_0);
  NodeContainer all_hub_1;
  all_hub_1.Add(router_0);
  all_hub_1.Add(term_1);
  NetDeviceContainer ndc_hub_1 = csma_hub_1.Install(all_hub_1);
  NodeContainer all_hub_2;
  all_hub_2.Add(router_0);
  all_hub_2.Add(term_0);
  NetDeviceContainer ndc_hub_2 = csma_hub_2.Install(all_hub_2);
  NodeContainer all_hub_3;
  all_hub_3.Add(term_0);
  all_hub_3.Add(term_1);
  NetDeviceContainer ndc_hub_3 = csma_hub_3.Install(all_hub_3);

  //----------------------------------------------------------------
  // Pointer-Base access to TxQueue (DropTailQueue)
//  Ptr<NetDevice> nic = ndc_hub_0.Get(0); // Get a pointer to NetDevice from an elememnt in NetdeviceContainer.
//  PointerValue pv;
//  nic->GetAttribute("TxQueue", pv);
//  Ptr<Object> txQueue = pv.GetObject();
//  Ptr<DropTailQueue> dtq = txQueue->GetObject<DropTailQueue>();
//  UintegerValue MaxPkts;
//  dtq->GetAttribute("MaxPackets", MaxPkts);
//  dtq->SetAttribute("MaxPackets", UintegerValue(MaxPackets));
//  // NameSpace-Base access to TxQueue (DropTailQueue)
//  Config::Set("/NodeList/0/DeviceList/0/TxQueue/MaxPackets", UintegerValue(MaxPackets));
//  Names::Add("router_0", router_0.Get(0));
//  Names::Add("eth_3", router_0.Get(0)->GetDevice(2));
//  Config::Set("/Names/router_0/eth_1/MaxPackets", UintegerValue(MaxPackets));
  //-----------------------------------------------------------------

  /* Install the IP stack. */
  InternetStackHelper internetStackH;
  internetStackH.Install(router_0);
  internetStackH.Install(term_0);
  internetStackH.Install(term_1);
  internetStackH.Install(term_2);

//  MpInternetStackHelper stack;
//  stack.Install(nodes);

  /* IP assign. */
  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.0.0.0", "255.255.255.0");
  Ipv4InterfaceContainer iface_ndc_hub_0 = ipv4.Assign(ndc_hub_0);
  ipv4.SetBase("10.0.1.0", "255.255.255.0");
  Ipv4InterfaceContainer iface_ndc_hub_1 = ipv4.Assign(ndc_hub_1);
  ipv4.SetBase("10.0.2.0", "255.255.255.0");
  Ipv4InterfaceContainer iface_ndc_hub_2 = ipv4.Assign(ndc_hub_2);
  ipv4.SetBase("10.0.3.0", "255.255.255.0");
  Ipv4InterfaceContainer iface_ndc_hub_3 = ipv4.Assign(ndc_hub_3);

  /* Generate Route. */
  Ipv4GlobalRoutingHelper::PopulateRoutingTables();

//  Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1400));
//
//  // TCP packet sink
//  PacketSinkHelper h_mysink("ns3::TcpSocketFactory", Address(InetSocketAddress("0.0.0.0", 3000)));
//  ApplicationContainer mysinkApps = h_mysink.Install(term_2.Get(0));
//  mysinkApps.Start(Seconds(0.0));
//
//  //  TCP Bulk (Flow0)    10.0.0.2 (term0) --> 10.0.2.3 (term4)
//  BulkSendHelper source("ns3::TcpSocketFactory", Address(InetSocketAddress("10.0.0.2", 3000)));
//  source.SetAttribute("MaxBytes", UintegerValue(0)); // Set the amount of data to send in bytes.  Zero is unlimited.
//  source.SetAttribute("SendSize", UintegerValue(1400));    // Set Tcp segment size
//
//  ApplicationContainer sourceApps = source.Install(client);
//  sourceApps.Start(Seconds(0.0)); // Source Start time
//  sourceApps.Stop(Seconds(15.0));

  // MpTcp sink (Receiver Side)
  uint32_t servPort = 5000;
  Ptr<MpTcpPacketSink> sinkSocket = CreateObject<MpTcpPacketSink>();
  sinkSocket->SetAttribute("Local", AddressValue(InetSocketAddress(Ipv4Address::GetAny(), servPort)));
  server->AddApplication(sinkSocket);
  ApplicationContainer Apps;
  Apps.Add(sinkSocket);
  Apps.Start(Seconds(0.0));
  Apps.Stop(Seconds(simDuration));

  /* Receiver side setup with Object Factory Model*/
//  ObjectFactory factory;
//  factory.SetTypeId("ns3::MpTcpPacketSink");
//  factory.Set("Local", AddressValue(InetSocketAddress(Ipv4Address::GetAny(), servPort)));
//  Ptr<Application> SinkApp = factory.Create<Application>();
//  server->AddApplication(SinkApp);
//  ApplicationContainer Apps;
//  Apps.Add(SinkApp);
  //
  // Sender side setup
  lSocket = CreateObject<MpTcpSocketBase>(client); //lSocket = new MpTcpSocketBase(client);
  lSocket->Bind();

  SetupSocketParam(lSocket);
  Simulator::ScheduleNow(&StartFlow, lSocket, iface_ndc_hub_3.GetAddress(1), servPort);

  /* Downcasting object from Socket -> TcpSocketBase */
  //Ptr<TcpSocketBase> TcpsocketBase = localSocket->GetObject<TcpSocketBase>();
  //Ptr<TcpSocketBase> TcpsocketBase = DynamicCast<TcpSocketBase>(localSocket);
  //
  /* Retreive some data*/
  std::string tr_file_name = "mmptcp.tr";
  std::ofstream ascii;
  Ptr<OutputStreamWrapper> ascii_wrap;
  ascii.open(tr_file_name.c_str());
  ascii_wrap = new OutputStreamWrapper(tr_file_name.c_str(), std::ios::out);
  internetStackH.EnableAsciiIpv4All(ascii_wrap);

  /* Output ConfigStore to Xml format */
  Config::SetDefault("ns3::ConfigStore::Filename", StringValue("mmptcp-attributes.xml"));
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
