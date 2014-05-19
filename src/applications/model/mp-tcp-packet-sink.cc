#include "ns3/address.h"
#include "ns3/address-utils.h"
#include "ns3/log.h"
#include "ns3/inet-socket-address.h"
#include "ns3/node.h"
#include "ns3/socket.h"
#include "ns3/udp-socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/mp-tcp-packet-sink.h"

using namespace std;

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("MpTcpPacketSink");
NS_OBJECT_ENSURE_REGISTERED(MpTcpPacketSink);

TypeId
MpTcpPacketSink::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::MpTcpPacketSink")
      .SetParent<Application>()
      .AddConstructor<MpTcpPacketSink>()
      .AddAttribute("Local", "The Address on which to Bind the rx socket.",
          AddressValue(),
          MakeAddressAccessor(&MpTcpPacketSink::m_local),
          MakeAddressChecker())
//    .AddAttribute ("Protocol", "The type id of the protocol to use for the rx socket.",
//                   TypeIdValue (TcpSocketFactory::GetTypeId ()),
//                   MakeTypeIdAccessor (&MpTcpPacketSink::m_tid),
//                   MakeTypeIdChecker ())
//    .AddAttribute ("algopr", "The used algorithm to handle pakcet reordering.",
//                   UintegerValue(0),
//                   MakeUintegerAccessor(&MpTcpPacketSink::algopr),
//                   MakeUintegerChecker<uint32_t>())
//    .AddTraceSource ("Rx", "A packet has been received",
//                     MakeTraceSourceAccessor (&MpTcpPacketSink::m_rxTrace))
      ;
  return tid;
}

MpTcpPacketSink::MpTcpPacketSink()
{
  NS_LOG_FUNCTION (this);
  m_socket = 0;
  m_totalRx = 0;
}

MpTcpPacketSink::~MpTcpPacketSink()
{
  NS_LOG_FUNCTION (this);
}

uint32_t
MpTcpPacketSink::GetTotalRx() const
{
  return m_totalRx;
}

void
MpTcpPacketSink::DoDispose(void)
{
  NS_LOG_FUNCTION (this);
  m_socket = 0;

  // chain up
  Application::DoDispose();
}

// Application Methods
void
MpTcpPacketSink::StartApplication()    // Called at time specified by Start
{
  NS_LOG_FUNCTION (this);
  // Create the socket if not already
  if (!m_socket)
    {
      size = 2000;
      buf = new uint8_t[size];
      //m_socket = new MpTcpSocketBase(GetNode());
      m_socket = CreateObject<MpTcpSocketBase>(GetNode()); //m_socket = Socket::CreateSocket (GetNode(), m_tid);
      m_socket->Bind(m_local);
      m_socket->Listen();
      NS_LOG_LOGIC("StartApplication -> MptcpPacketSink got an listening socket " << m_socket << " binded to addrs:port  " << InetSocketAddress::ConvertFrom(m_local).GetIpv4() << ":" << InetSocketAddress::ConvertFrom(m_local).GetPort());
    }
  //We ca also allocate sendingBuffer here...
  //m_socket->allocateRecvingBuffer(14000);
  //m_socket->allocateSendingBuffer(14000);
  //m_socket->SetunOrdBufMaxSize(2000); // unused function call...
  m_socket->SetRecvCallback(MakeCallback(&MpTcpPacketSink::HandleRead, this));
  m_socket->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address &>(),
      MakeCallback(&MpTcpPacketSink::HandleAccept, this));
  m_socket->SetCloseCallbacks(MakeCallback(&MpTcpPacketSink::HandlePeerClose, this),
      MakeCallback(&MpTcpPacketSink::HandlePeerError, this));
}

void
MpTcpPacketSink::StopApplication()     // Called at time specified by Stop
{
  NS_LOG_FUNCTION (this);     //
  NS_LOG_WARN (Simulator::Now().GetSeconds() << " MpTcpPacketSink -> Total received bytes " << m_totalRx);
  while (!m_socketList.empty()) //these are accepted sockets, close them
    {
      Ptr<Socket> acceptedSocket = m_socketList.front();
      m_socketList.pop_front();
      NS_LOG_INFO("MpTcpPacketSink -> Drop this accepted socket ,"<<acceptedSocket << ", and call Close on it ");
      acceptedSocket->Close();
      NS_LOG_INFO("MpTcpPacketSink -> Now SocketListSize is " << m_socketList.size());
    }

  if (m_socket)
    {
      NS_LOG_INFO("MpTcpPacketSink -> FINALY closing the listening socket, " << m_socket);
      m_socket->Close();
      m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket> >());
    }
}

void
MpTcpPacketSink::HandleRead(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << m_socket);

  uint32_t dataAmount = m_socket->Recv(buf, size);
  m_totalRx += dataAmount;
  NS_LOG_INFO ("MpTcpPacketSink:HandleRead() -> Received " << dataAmount << " bytes total Rx " << m_totalRx);
}

void
MpTcpPacketSink::HandlePeerClose(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
  //NS_LOG_INFO("MpTcpPacketSink, peerClose " << socket);
}

void
MpTcpPacketSink::HandlePeerError(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
  //NS_LOG_INFO("MpTcpPktSink, peerError");
}

void
MpTcpPacketSink::HandleAccept(Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback(MakeCallback(&MpTcpPacketSink::HandleRead, this));
  m_socketList.push_back(s);
  NS_LOG_INFO("MptcpPacketSink got an new connection. SocketList: " << m_socketList.size());
}

Ptr<MpTcpSocketBase>
MpTcpPacketSink::getMpTcpSocket()
{
  return m_socket;
}

/*
 NS_LOG_COMPONENT_DEFINE ("MpTcpPacketSource");
 NS_OBJECT_ENSURE_REGISTERED (MpTcpPacketSource);

 TypeId
 MpTcpPacketSource::GetTypeId (void)
 {
 static TypeId tid = TypeId("ns3::MpTcpPacketSource")
 .SetParent<Application>()
 .AddConstructor<MpTcpPacketSource>()
 .AddAttribute ("Protocol", "The type id of the protocol to use for the tx socket",
 TypeIdValue (TcpSocketFactory::GetTypeId()),
 MakeTypeIdAccessor (&MpTcpPacketSource::m_tid),
 MakeTypeIdChecker ())
 .AddAttribute ("ServerAddr", "The addres of the server",
 AddressValue(),
 MakeAddressAccessor (&MpTcpPacketSource::m_servAddr),
 MakeAddressChecker())
 ;
 return tid;
 }
 MpTcpPacketSource::MpTcpPacketSource()
 {
 NS_LOG_FUNCTION (this);
 }
 MpTcpPacketSource::~MpTcpPacketSource()
 {
 NS_LOG_FUNCTION (this);
 }
 void
 MpTcpPacketSource::SetServPort(uint32_t port)
 {
 NS_LOG_FUNCTION (this << port);
 m_servPort = port;
 }
 uint32_t
 MpTcpPacketSource::GetServPort(void)
 {
 return m_servPort;
 }
 void
 MpTcpPacketSource::StartApplication ()
 {
 NS_LOG_FUNCTION (this);
 m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
 m_socket->Bind();

 }
 */
} // Namespace ns3
