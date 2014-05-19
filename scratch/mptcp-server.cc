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
NS_LOG_COMPONENT_DEFINE("FirstMultipathToplogy");

uint32_t LinkRate = 100000000;
uint32_t Delay = 10;
Time cDelay = MilliSeconds(Delay);
static const uint32_t totalTxBytes = 100000;
static const uint32_t sendBufSize = 536 * 100; //2000000;
static const uint32_t recvBufSize = 536 * 100; //2000000;
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
//static void
//CwndTracer(uint32_t oldVal, uint32_t newVal){
//  NS_LOG_UNCOND("Subflow cWindow:  " << oldVal << " -> " << newVal);
//}
int
main(int argc, char *argv[])
{
  Config::SetDefault("ns3::DropTailQueue::MaxPackets", UintegerValue(50));
//  Config::SetDefault("ns3::DropTailQueue::MaxBytes", UintegerValue(300000));
//  Config::SetDefault("ns3::RateErrorModel::ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
//  Config::SetDefault("ns3::RateErrorModel::ErrorRate", StringValue("100"));

  LogComponentEnable("FirstMultipathToplogy", LOG_LEVEL_LOGIC);
//  LogComponentEnable("MpTcpSocketBase", LOG_WARN);
//  LogComponentEnable("TcpL4Protocol", LOG_DEBUG);
//  LogComponentEnable("Ipv4EndPointDemux", LOG_LEVEL_ALL);
//  LogComponentEnable("MpTcpSocketBase", LOG_ALL);
  LogComponentEnable("MpTcpSocketBase", LOG_INFO);
//  LogComponentEnable("MpTcpPacketSink", LOG_LEVEL_ALL);

  // Creation of the hosts
  NodeContainer nodes;
  nodes.Create(2);

  client = nodes.Get(0);
  server = nodes.Get(1);

  InternetStackHelper stack;
  //stack.SetTcp("MpTcpL4Protocol");
  stack.Install(nodes);

  vector<Ipv4InterfaceContainer> ipv4Ints;

  int subflow = 2;
  for (int i = 0; i < subflow; i++)
    { // Creation of the point to point link between hosts
      PointToPointHelper p2plink;
      p2plink.SetDeviceAttribute("DataRate", DataRateValue(DataRate(LinkRate)));
      p2plink.SetChannelAttribute("Delay", TimeValue(cDelay));

      NetDeviceContainer netDevices;
      netDevices = p2plink.Install(nodes);

      // Attribution of the IP addresses
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
  NS_LOG_INFO ("address " << ipv4Ints[0].GetAddress (1));
  ObjectFactory m_sf;
  m_sf.SetTypeId("ns3::MpTcpPacketSink");
  //m_sf.Set("Protocol", StringValue("ns3::TcpSocketFactory"));
  m_sf.Set("Local", AddressValue(InetSocketAddress(ipv4Ints[0].GetAddress(1), servPort)));
//  m_sf.Set("Local", AddressValue(InetSocketAddress(Ipv4Address::GetAny(), servPort)));
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

//  Ptr<MpTcpSocketBase> lSocket1 = new MpTcpSocketBase(client);
//  lSocket1->Bind();
//  lSocket1->allocateSendingBuffer(14000);
//  lSocket1->allocateRecvingBuffer(14000);
//  lSocket1->SetMaxSubFlowNumber(11);
//  lSocket1->SetSourceAddress(Ipv4Address("10.1.1.1"));
//  NS_LOG_INFO("FirstSocket"<< lSocket1->Connect(ipv4Ints[0].GetAddress(1), servPort));
//  lSocket1->Close();

  NS_LOG_INFO("SecondSocket start");
  //Ptr<MpTcpSocketBase> lSocket2 = new MpTcpSocketBase(client);
  Ptr<MpTcpSocketBase> lSocket2 = CreateObject<MpTcpSocketBase>(client);
  lSocket2->Bind();
  lSocket2->allocateSendingBuffer(14000);
  lSocket2->allocateRecvingBuffer(14000);
  lSocket2->SetMaxSubFlowNumber(11);
  lSocket2->SetSourceAddress(Ipv4Address("10.1.1.1"));
  NS_LOG_INFO("Second socket"  << lSocket2->Connect(ipv4Ints[0].GetAddress(2), servPort));
  lSocket2->Close();
  NS_LOG_INFO("SecondSocket End");


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
  NS_LOG_LOGIC("mpTopology:: simulation ended");
  return 0;
}
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
void
StartFlow(Ptr<MpTcpSocketBase> localSocket, Ipv4Address servAddress, uint16_t servPort)
{
  //NS_LOG_LOGIC("Starting flow at time " << Simulator::Now ().GetSeconds ());
  lSocket->SetMaxSubFlowNumber(11);
  //lSocket->SetMinSubFlowNumber(1);
  lSocket->SetSourceAddress(Ipv4Address("10.1.1.1"));
  lSocket->allocateSendingBuffer(sendBufSize);
  lSocket->allocateRecvingBuffer(recvBufSize);
  lSocket->SetunOrdBufMaxSize(50);
  lSocket->LossProbablity = 20;
  lSocket->mod = 150;
  lSocket->totalBytes = totalTxBytes;
  lSocket->lostRate = 0.09;
  lSocket->LinkCapacity = LinkRate;
  lSocket->RTT = Delay * 2;
  lSocket->TimeScale = -5.0;

  int connectionState = lSocket->Connect(servAddress, servPort);
  if (connectionState == 0)
    {
      lSocket->SetConnectCallback(MakeCallback(&connectionSucceeded), MakeCallback(&connectionFailed));
      lSocket->SetDataSentCallback(MakeCallback(&WriteUntilBufferFull));
      lSocket->SetCloseCallbacks(MakeCallback(&HandlePeerClose), MakeCallback(&HandlePeerError));
      //Config::ConnectWithoutContext ("/NodeList/*/$ns3::TcpL4Protocol/SocketList/*/Subflows/*/cWindow", MakeCallback (&CwndTracer));
    }
  else
    {
      //localSocket->NotifyConnectionFailed();
      NS_LOG_LOGIC("mpTopology:: connection failed");
    }
}

void
connectionSucceeded(Ptr<Socket> localSocket)
{
  NS_LOG_INFO("mpTopology: Connection requeste succeed");
  Simulator::Schedule(Seconds(1.0), &WriteUntilBufferFull, lSocket, 0);
  Simulator::Schedule(Seconds(simDuration), &CloseConnection, lSocket);
}

void
connectionFailed(Ptr<Socket> localSocket)
{
  NS_LOG_FUNCTION_NOARGS();NS_LOG_INFO("mpTopology: Connection requeste failure");
  //lSocket->Close();
}

void
HandlePeerClose(Ptr<Socket> localSocket)
{
  NS_LOG_FUNCTION_NOARGS(); //
  NS_LOG_INFO("mpTopology: Connection closed by peer {HandlePeerClose}");
  //lSocket->Close();
}

void
HandlePeerError(Ptr<Socket> localSocket)
{
  NS_LOG_FUNCTION_NOARGS();NS_LOG_INFO("mpTopology: Connection closed by peer error");
  //lSocket->Close();
}

void
CloseConnection(Ptr<Socket> localSocket)
{
  //lSocket->Close();
  NS_LOG_LOGIC("mpTopology:: currentTxBytes = " << currentTxBytes);         //
  NS_LOG_LOGIC("mpTopology:: totalTxBytes   = " << totalTxBytes);           //
  NS_LOG_LOGIC("mpTopology:: connection to remote host has been closed");   //
}

void
variateDelay(Ptr<Node> node)
{
  Ptr<Ipv4L3Protocol> ipv4 = node->GetObject<Ipv4L3Protocol>();
  TimeValue delay;
  for (uint32_t i = 0; i < ipv4->GetNInterfaces(); i++)
    {
      //Ptr<NetDevice> device = m_node->GetDevice(i);
      Ptr<Ipv4Interface> interface = ipv4->GetInterface(i);
      Ipv4InterfaceAddress interfaceAddr = interface->GetAddress(0);
      // do not consider loopback addresses
      if (interfaceAddr.GetLocal() == Ipv4Address::GetLoopback())
        {   // loopback interface has identifier equal to zero
          continue;
        }
      Ptr<NetDevice> netDev = interface->GetDevice();
      Ptr<Channel> P2Plink = netDev->GetChannel();
      P2Plink->GetAttribute(string("Delay"), delay);
      double oldDelay = delay.Get().GetSeconds();
      std::stringstream strDelay;
      double newDelay = (rand() % 100) * 0.01;
      double err = newDelay - oldDelay;
      strDelay << (0.95 * oldDelay + 0.05 * err) << "s";
      P2Plink->SetAttribute(string("Delay"), StringValue(strDelay.str()));
      //P2Plink->GetAttribute(string("Delay"), delay);
//      NS_LOG_INFO ("variateDelay -> new delay == " << delay.Get().GetSeconds());
    }
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
//      if (Simulator::Now().GetSeconds() > 2 && Simulator::Now().GetSeconds() < 4)
//      variateDelay(client);
      lSocket->SendBufferedData();
    }
  if (currentTxBytes == totalTxBytes)
    localSocket->Close();
}
