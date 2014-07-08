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

//       10.1.1.0
//   n1 ------------ n2

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("MpTcpNewReno");

uint32_t LinkRate = 1000000;
uint32_t Delay = 100;
Time cDelay = MilliSeconds(Delay);
double LossRate = 0.0;
static const uint32_t totalTxBytes = 200000;
static const uint32_t sendBufSize = 2000000;
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

static void
CwndTracer(double oldval, double newval)
{
  NS_LOG_INFO ("Moving cwnd from " << oldval << " to " << newval);
}

//static MpTcpHeader header;
static TcpHeader header;

int
main(int argc, char *argv[])
{
  Config::SetDefault("ns3::DropTailQueue::MaxPackets", UintegerValue(25));

  LogComponentEnable("MpTcpNewReno", LOG_LEVEL_ALL);
//  LogComponentEnable("MpTcpSocketBase", LOG_INFO);
  LogComponentEnable("MpTcpTypeDefs", LOG_WARN);

// Creation of the hosts
  NodeContainer nodes;
  nodes.Create(2);

  client = nodes.Get(0);
  server = nodes.Get(1);

  InternetStackHelper stack;
  //stack.SetTcp("ns3::MpTcpL4Protocol");
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

  // Configuration of the Client/Server application
  uint32_t servPort = 5000;
  ObjectFactory m_sf;
  m_sf.SetTypeId("ns3::MpTcpPacketSink");
  m_sf.Set("Local", AddressValue(InetSocketAddress(Ipv4Address::GetAny(), servPort)));

  Ptr<Application> sapp = m_sf.Create<Application>();
  server->AddApplication(sapp);
  ApplicationContainer Apps;
  Apps.Add(sapp);

  Apps.Start(Seconds(0.0));
  Apps.Stop(Seconds(simDuration - 10));

  lSocket = new MpTcpSocketBase(client);
  lSocket->Bind();

  SetupSocketParam(lSocket);
  SetupDropPacket(lSocket);

  Simulator::ScheduleNow(&StartFlow, lSocket, ipv4Ints[0].GetAddress(1), servPort);

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

  Simulator::Stop(Seconds(simDuration + 10.0));
  Simulator::Run();
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
      Config::ConnectWithoutContext("/NodeList/0/$ns3::MpTcpSocketBase/subflows[0]/CongestionWindow", MakeCallback(&CwndTracer));
    }
  else
    {
      NS_LOG_LOGIC("MpTcpNewReno:: connection failed");
    }
}

void
SetupSocketParam(Ptr<MpTcpSocketBase> lSocket)
{
  lSocket->SetCongestionCtrlAlgo(Uncoupled_TCPs);
  //lSocket->SetDataDistribAlgo(Round_Robin);
  lSocket->SetMaxSubFlowNumber(11);
  //lSocket->SetSourceAddress(Ipv4Address("10.1.1.1"));
  lSocket->allocateSendingBuffer(sendBufSize);
  lSocket->mod = 60;
  lSocket->totalBytes = totalTxBytes;
  lSocket->lostRate = LossRate;
  lSocket->LinkCapacity = LinkRate;
  lSocket->RTT = Delay * 2;
  lSocket->TimeScale = -5.0;
  lSocket->MSS = 1400; // Just for plot's info
}

void
SetupDropPacket(Ptr<MpTcpSocketBase> lSocket)
{
  // 2 drops
  lSocket->sampleList.push_back(26);
  lSocket->sampleList.push_back(47);

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
  Simulator::Schedule(Seconds(1.0), &WriteUntilBufferFull, lSocket, 0);
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
