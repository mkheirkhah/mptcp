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
/* Multipath Network Topology
 lan 10.1.1.0
 ___________
 /           \
   n1             n2
 \___________/
 lan 10.1.2.0
 */
using namespace ns3;
NS_LOG_COMPONENT_DEFINE("mptcp");

uint32_t LinkRate = 100000000;
uint32_t Delay = 10;
Time cDelay = MilliSeconds(Delay);
int totalSubflow = 4;
double LossRate = 0.0;
static const uint32_t totalTxBytes = 10000000;
static const uint32_t sendBufSize =  200000; //2000000;
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
  Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1400));
//  Config::SetDefault("ns3::DropTailQueue::MaxPackets", UintegerValue(15));
//  Config::SetDefault("ns3::RateErrorModel::ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
//  Config::SetDefault("ns3::RateErrorModel::ErrorRate", StringValue("100"));

  LogComponentEnable("mptcp", LOG_LEVEL_LOGIC);
//  LogComponentEnable("MpTcpSocketBase", LOG_INFO);
//  LogComponentEnable("MpTcpTypeDefs", LOG_FUNCTION);
//  LogComponentEnable("MpTcpSocketBase", LOG_DEBUG);
//  LogComponentEnable("MpTcpSocketBase", LOG_LOGIC);
//  LogComponentEnable("MpTcpL4Protocol", LOG_INFO);
//  LogComponentEnable("Ipv4EndPointDemux", LOG_LEVEL_ALL);
//  LogComponentEnable("MpTcpSocketBase", LOG_LEVEL_ALL);
//  LogComponentEnable("MpTcpPacketSink", LOG_LEVEL_ALL);
//  LogComponentEnable("MpTcpSubfLow", LOG_FUNCTION);

  // Creation of the hosts
  NodeContainer nodes;
  nodes.Create(2);

  client = nodes.Get(0);
  server = nodes.Get(1);

  InternetStackHelper stack;
  //stack.SetTcp("ns3::MpTcpL4Prtocol");
  stack.Install(nodes);

  vector<Ipv4InterfaceContainer> ipv4Ints;

  for (int i = 0; i < totalSubflow; i++)
    { // Creation of the point to point link between hosts
      PointToPointHelper p2plink;
      p2plink.SetDeviceAttribute("DataRate", DataRateValue(DataRate(LinkRate)));
      p2plink.SetChannelAttribute("Delay", TimeValue(cDelay));

      NetDeviceContainer netDevices;
      netDevices = p2plink.Install(nodes);

      std::stringstream netAddr;
      netAddr << "10.1." << (i + 1) << ".0";
      string str = netAddr.str();

      Ipv4AddressHelper ipv4addr;
      ipv4addr.SetBase(str.c_str(), "255.255.255.0");
      Ipv4InterfaceContainer interface = ipv4addr.Assign(netDevices);
      ipv4Ints.insert(ipv4Ints.end(), interface);
    }

  // Configuration of the Client/Server application
  uint32_t servPort = 5000;
  ObjectFactory m_sf;
  m_sf.SetTypeId("ns3::MpTcpPacketSink");
//  m_sf.Set("Protocol", StringValue("ns3::TcpSocketFactory"));
//  m_sf.Set("Local", AddressValue(InetSocketAddress(ipv4Ints[0].GetAddress(1), servPort)));
  m_sf.Set("Local", AddressValue(InetSocketAddress(Ipv4Address::GetAny(), servPort)));
  Ptr<Application> sapp = m_sf.Create<Application>();
  server->AddApplication(sapp);
  ApplicationContainer Apps;
  Apps.Add(sapp);

  Apps.Start(Seconds(0.0));
  Apps.Stop(Seconds(simDuration));

  //lSocket = new MpTcpSocketBase(client);
  lSocket = CreateObject<MpTcpSocketBase>(client); //lSocket = new MpTcpSocketBase(client);
  lSocket->SetCongestionCtrlAlgo(Uncoupled_TCPs);
  lSocket->SetDataDistribAlgo(Round_Robin);
  lSocket->Bind();

  SetupSocketParam(lSocket);

  Simulator::ScheduleNow(&StartFlow, lSocket, ipv4Ints[0].GetAddress(1), servPort);

  /* Output ConfigStore to Xml format */
  Config::SetDefault("ns3::ConfigStore::Filename", StringValue("MPTCP-attributes.xml"));
  Config::SetDefault("ns3::ConfigStore::FileFormat", StringValue("Xml"));
  Config::SetDefault("ns3::ConfigStore::Mode", StringValue("Save"));
  ConfigStore outputConfig2;
  outputConfig2.ConfigureDefaults();
  outputConfig2.ConfigureAttributes();

//  Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
//  em->SetUnit(RateErrorModel::ERROR_UNIT_PACKET);
//  em->SetRate(0.1); //Subflow1
//  Ptr<NetDevice> server_2 = server->GetDevice(2);
//  server_2->SetAttribute("ReceiveErrorModel", PointerValue(em));

  // List ErrorModel
//  std::list< uint32_t> list;
//  list.push_back(50);
//
//  Ptr<ListErrorModel> em = CreateObject<ListErrorModel>();
//  em->SetList(list);
//  Ptr<NetDevice> _server = server->GetDevice(1);
//  _server->SetAttribute("ReceiveErrorModel", PointerValue(em));

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
  lSocket->SetCongestionCtrlAlgo(Uncoupled_TCPs);
  //lSocket->SetDataDistribAlgo(Round_Robin);
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
