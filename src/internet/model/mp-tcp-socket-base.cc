/*
 * MultiPath-TCP (MPTCP) implementation.
 * Programmed by Morteza Kheirkhah from University of Sussex.
 * Some codes here are modeled from ns3::TCPNewReno implementation.
 * Email: m.kheirkhah@sussex.ac.uk
 */
#define NS_LOG_APPEND_CONTEXT \
  if (m_node) { std::clog << Simulator::Now ().GetSeconds () << " [node " << m_node->GetId () << "] "; }

#include <algorithm>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include "ns3/abort.h"
#include "ns3/log.h"
#include "ns3/string.h"
#include "ns3/mp-tcp-socket-base.h"
#include "ns3/tcp-l4-protocol.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/error-model.h"
#include "ns3/point-to-point-channel.h"
#include "ns3/point-to-point-net-device.h"
#include "ns3/pointer.h"
#include "ns3/drop-tail-queue.h"
#include "ns3/object-vector.h"

NS_LOG_COMPONENT_DEFINE("MpTcpSocketBase");
using namespace std;
namespace ns3
{
NS_OBJECT_ENSURE_REGISTERED(MpTcpSocketBase);

TypeId
MpTcpSocketBase::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::MpTcpSocketBase")
      .SetParent<TcpSocketBase>()
      .AddConstructor<MpTcpSocketBase>()
      .AddAttribute("CongestionControl","Congestion control algorithm",
          EnumValue(Uncoupled_TCPs),
          MakeEnumAccessor(&MpTcpSocketBase::SetCongestionCtrlAlgo),
          MakeEnumChecker(Uncoupled_TCPs, "Uncoupled_TCPs",Fully_Coupled, "Fully_Coupled", RTT_Compensator, "RTT_Compensator", Linked_Increases,"Linked_Increases"))
      .AddAttribute("SchedulingAlgorithm", "Algorithm for data distribution between subflows", EnumValue(Round_Robin),
          MakeEnumAccessor(&MpTcpSocketBase::SetDataDistribAlgo),
          MakeEnumChecker(Round_Robin, "Round_Robin"))
      .AddAttribute("MaxSubflows","Maximum number of subflows per each mptcp connection",
          UintegerValue(255),
          MakeUintegerAccessor(&MpTcpSocketBase::maxSubflows),
          MakeUintegerChecker<uint8_t>())
      .AddAttribute("Subflows", "The list of subflows associated to this protocol.",
          ObjectVectorValue(),
          MakeObjectVectorAccessor(&MpTcpSocketBase::subflows),
          MakeObjectVectorChecker<MpTcpSocketBase>());
  return tid;
}

MpTcpSocketBase::MpTcpSocketBase()
{
  NS_LOG_FUNCTION(this);
}

MpTcpSocketBase::MpTcpSocketBase(Ptr<Node> node) :
    subflows(0), localAddrs(0), remoteAddrs(0)
//:
//    m_node(node), m_mptcp(node->GetObject<TcpL4Protocol>()), mpState(MP_NONE), mpSendState(MP_NONE), mpRecvState(MP_NONE), mpEnabled(false), addrAdvertised(
//        false), mpTokenRegister(false), subflows(0), localAddrs(0), remoteAddrs(0), lastUsedsFlowIdx(0), totalCwnd(0), localToken(0), remoteToken(0), client(
//        false), server(false), remoteRecvWnd(1), segmentSize(0), nextTxSequence(1), nextRxSequence(1)
{
  NS_LOG_FUNCTION(this);
  m_node = node;
  m_mptcp = node->GetObject<TcpL4Protocol>();
  mpSendState = MP_NONE;
  mpRecvState = MP_NONE;
  mpEnabled = false;
  addrAdvertised = false;
  mpTokenRegister = false;
  lastUsedsFlowIdx = 0;
  totalCwnd = 0;
  localToken = 0;
  remoteToken = 0;
  client = false;
  server = false;
  remoteRecvWnd = 1;
  segmentSize = 0;
  nextTxSequence = 1;
  nextRxSequence = 1;
  gnu.SetOutFile("allPlots.pdf");
  pAck = 0;
  mod = 60;
  Callback<void, Ptr<Socket> > vPS = MakeNullCallback<void, Ptr<Socket> >();
  Callback<void, Ptr<Socket>, const Address &> vPSA = MakeNullCallback<void, Ptr<Socket>, const Address &>();
  Callback<void, Ptr<Socket>, uint32_t> vPSUI = MakeNullCallback<void, Ptr<Socket>, uint32_t>();
  SetConnectCallback(vPS, vPS);
  SetDataSentCallback(vPSUI);
  SetSendCallback(vPSUI);
  SetRecvCallback(vPS);
}

MpTcpSocketBase::~MpTcpSocketBase(void)
{
  NS_LOG_FUNCTION(this);
  m_node = 0;
  /*
   * Upon Bind, an Ipv4Endpoint is allocated and set to m_endPoint, and
   * DestroyCallback is set to TcpSocketBase::Destroy. If we called
   * m_tcp->DeAllocate, it will destroy its Ipv4EndpointDemux::DeAllocate,
   * which in turn destroys my m_endPoint, and in turn invokes
   * TcpSocketBase::Destroy to nullify m_node, m_endPoint, and m_tcp.
   */
  if (m_endPoint != 0)
    {
      NS_ASSERT(m_mptcp != 0);
      m_mptcp->DeAllocate(m_endPoint);
      NS_ASSERT(m_endPoint == 0);
    }
  m_mptcp = 0;
  CancelAllSubflowTimers();
  NS_LOG_INFO(Simulator::Now().GetSeconds() << " ["<< this << "] ~MpTcpSocketBase -> m_node: " << m_node << " m_mptcp: " << m_mptcp << " m_endPoint: " << m_endPoint);
}

/** Configure the endpoint to a local address. Called by Connect() if Bind() didn't specify one. */
int
MpTcpSocketBase::SetupEndpoint()
{
  NS_LOG_FUNCTION (this);
  Ptr<Ipv4> ipv4 = m_node->GetObject<Ipv4>();
  NS_ASSERT(ipv4 != 0);
  if (ipv4->GetRoutingProtocol() == 0)
    {
      NS_FATAL_ERROR("No Ipv4RoutingProtocol in the node");
    }

  // Create a dummy packet, then ask the routing function for the best output interface's address
  Ipv4Header header;
  header.SetDestination(m_endPoint->GetPeerAddress());
  Socket::SocketErrno errno_;
  Ptr<Ipv4Route> route;
  Ptr<NetDevice> oif = m_boundnetdevice; // m_boundnetdevice is allocated to 0 by the default constructor of ns3::Socket.
  route = ipv4->GetRoutingProtocol()->RouteOutput(Ptr<Packet>(), header, oif, errno_);
  if (route == 0)
    {
      NS_LOG_LOGIC ("Route to " << m_endPoint->GetPeerAddress () << " does not exist");NS_LOG_ERROR (errno_);
      m_errno = errno_;
      return -1;
    }NS_LOG_LOGIC ("Route exists");

  // Setup local address for this endpoint
  m_endPoint->SetLocalAddress(route->GetSource());
  return 0;
}

void
MpTcpSocketBase::EstimateRtt(const TcpHeader& TcpHeader)
{
  NS_LOG_FUNCTION_NOARGS();
}

/** Called by ForwardUp() to estimate RTT */
void
MpTcpSocketBase::EstimateRtt(uint8_t sFlowIdx, const TcpHeader& mptcpHeader)
{
  NS_LOG_FUNCTION(this << (int)sFlowIdx);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  sFlow->lastMeasuredRtt = sFlow->rtt->AckSeq(mptcpHeader.GetAckNumber());
  sFlow->measuredRTT.insert(sFlow->measuredRTT.end(), sFlow->rtt->GetCurrentEstimate().GetSeconds());

  // plotting
  sFlow->_RTT.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->lastMeasuredRtt.GetMilliSeconds()));
  sFlow->_AvgRTT.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->rtt->GetCurrentEstimate().GetMilliSeconds()));
  sFlow->_RTO.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->rtt->RetransmitTimeout().GetMilliSeconds()));
}

// Read options from incoming packets
bool
MpTcpSocketBase::ReadOptions(Ptr<Packet> pkt, const TcpHeader& mptcpHeader)
{
  NS_LOG_FUNCTION(this << mptcpHeader);
  NS_ASSERT(remoteToken == 0 && mpEnabled == false);
  vector<TcpOptions*> mp_options = mptcpHeader.GetOptions();
  uint8_t flags = mptcpHeader.GetFlags();
  TcpOptions *opt;
  bool hasSyn = flags & TcpHeader::SYN;
  for (uint32_t j = 0; j < mp_options.size(); j++)
    {
      opt = mp_options[j];
      if ((opt->optName == OPT_MPC) && hasSyn && (mpRecvState == MP_NONE))
        { // SYN+ACK would be send later on by ProcessSynRcvd(...)
          mpRecvState = MP_MPC;
          mpEnabled = true;
          remoteToken = ((OptMultipathCapable *) opt)->senderToken;
        }
      else
        NS_FATAL_ERROR("Unexpected option has received ... This could be a bug please report it to our GitHub page");
    }
  return true; // This should return true otherwise Forwardup() would retrun too.
}

// Read options from incoming packets
bool
MpTcpSocketBase::ReadOptions(uint8_t sFlowIdx, Ptr<Packet> pkt, const TcpHeader& mptcpHeader)
{
  NS_LOG_FUNCTION(this << (int)sFlowIdx << mptcpHeader);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  vector<TcpOptions*> options = mptcpHeader.GetOptions();
  uint8_t flags = mptcpHeader.GetFlags();
  TcpOptions *opt;
  bool hasSyn = flags & TcpHeader::SYN;
  bool TxAddr = false;
  for (uint32_t j = 0; j < options.size(); j++)
    {
      opt = options[j];
      if ((opt->optName == OPT_MPC) && hasSyn && (mpRecvState == MP_NONE))
        { // SYN+ACK would be send later on by ProcessSynRcvd(...)
          mpRecvState = MP_MPC;
          mpEnabled = true;
          remoteToken = ((OptMultipathCapable *) opt)->senderToken;
          NS_ASSERT(client);
        }
      else if ((opt->optName == OPT_JOIN) && hasSyn)
        {
          OptJoinConnection * optJoin = (OptJoinConnection *) opt;
          if ((mpSendState == MP_ADDR) && (localToken == optJoin->receiverToken))
            { // SYN+ACK would be send later on by ProcessSynRcvd(...)
              // Join option is sent over the path (couple of addresses) not already in use
            }
        }
      else if ((opt->optName == OPT_ADDR) && (mpRecvState == MP_MPC))
        {
          // Receiver store sender's addresses information and send back its addresses.
          // If there are several addresses to advertise then multiple OPT_ADDR would be attached to the TCP Options.
          MpTcpAddressInfo * addrInfo = new MpTcpAddressInfo();
          addrInfo->addrID = ((OptAddAddress *) opt)->addrID;
          addrInfo->ipv4Addr = ((OptAddAddress *) opt)->addr;
          remoteAddrs.insert(remoteAddrs.end(), addrInfo);
          TxAddr = true;
        }
      else if (opt->optName == OPT_REMADR)
        { // not implemented yet
          NS_LOG_WARN(this << "ReadOption-> OPT_REMADR is not implemented yet");
        }
      else if (opt->optName == OPT_DSN)
        { // not implemented yet
          NS_LOG_LOGIC(this << " ReadOption-> OPT_DSN -> we'll deal with it later on");
        }
    }
  if (TxAddr == true)
    {
      mpRecvState = MP_ADDR;
      // If addresses did not send yet then advertise them...
      if (mpSendState != MP_ADDR)
        {
          NS_LOG_DEBUG(Simulator::Now().GetSeconds()<< "---------------------- AdvertiseAvailableAddresses By Server ---------------------");
          AdvertiseAvailableAddresses(); // this is what the receiver has to do
          return false;
        }
      // If addresses already sent then initiate subflows...
      else if (mpSendState == MP_ADDR)
        {
          InitiateSubflows();  // this is what the initiator has to do
          return false;
        }
    }
  return true;
}

/** Received a packet upon ESTABLISHED state. This function is mimicking the
 role of tcp_rcv_established() in tcp_input.c in Linux kernel. */
void
MpTcpSocketBase::ProcessEstablished(uint8_t sFlowIdx, Ptr<Packet> packet, const TcpHeader& mptcpHeader)
{
  NS_LOG_FUNCTION (this << mptcpHeader);

  // Extract the flags. PSH and URG are not honoured.
  uint8_t tcpflags = mptcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG);

  // Different flags are different events
  if (tcpflags == TcpHeader::ACK)
    {
      ReceivedAck(sFlowIdx, packet, mptcpHeader);
    }
  else if (tcpflags == TcpHeader::SYN)
    { // Received SYN, old NS-3 behaviour is to set state to SYN_RCVD and
// respond with a SYN+ACK. But it is not a legal state transition as of
// RFC793. Thus this is ignored.
    }
  else if (tcpflags == (TcpHeader::SYN | TcpHeader::ACK))
    { // No action for received SYN+ACK, it is probably a duplicated packet
    }
  else if (tcpflags == TcpHeader::FIN || tcpflags == (TcpHeader::FIN | TcpHeader::ACK))
    { // Received FIN or FIN+ACK, bring down this socket nicely
      PeerClose(sFlowIdx, packet, mptcpHeader);
    }
  else if (tcpflags == 0)
    { // No flags means there is only data
      ReceivedData(sFlowIdx, packet, mptcpHeader);
//      if (m_rxBuffer.Finished ())
//        {
//          PeerClose (packet, mptcpHeader);
//        }
    }
  else
    { // Received RST or the TCP flags is invalid, in either case, terminate this socket
      if (tcpflags != TcpHeader::RST)
        { // this must be an invalid flag, send reset
          NS_LOG_LOGIC ("Illegal flag " << tcpflags << " received. Reset packet is sent.");
          SendRST(sFlowIdx);
        }
      CloseAndNotify(sFlowIdx);
    }
}

void
MpTcpSocketBase::ProcessListen(Ptr<Packet> packet, const TcpHeader& mptcpHeader, const Address& fromAddress, const Address& toAddress)
{
  NS_LOG_FUNCTION (this << mptcpHeader);

  // Extract the flags. PSH and URG are not honoured.
  uint8_t tcpflags = mptcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG);

  // Fork a socket if received a SYN. Do nothing otherwise.
  // C.f.: the LISTEN part in tcp_v4_do_rcv() in tcp_ipv4.c in Linux kernel
  if (tcpflags != TcpHeader::SYN)
    {
      return;
    }

  // Clone the socket, simulate fork
  Ptr<MpTcpSocketBase> newSock = CopyObject<MpTcpSocketBase>(this);
  NS_LOG_DEBUG ("Clone new MpTcpSocketBase new connection. ListenerSocket " << this << " AcceptedSocket "<< newSock);
  Simulator::ScheduleNow(&MpTcpSocketBase::CompleteFork, newSock, packet, mptcpHeader, fromAddress, toAddress);
}

void
MpTcpSocketBase::CompleteFork(Ptr<Packet> p, const TcpHeader& mptcpHeader, const Address& fromAddress, const Address& toAddress)
{
  NS_LOG_FUNCTION(this);
  server = true;

  // Get port and address from peer (connecting host)
  if (InetSocketAddress::IsMatchingType(toAddress))
    {
      m_endPoint = m_mptcp->Allocate(InetSocketAddress::ConvertFrom(toAddress).GetIpv4(), InetSocketAddress::ConvertFrom(toAddress).GetPort(),
          InetSocketAddress::ConvertFrom(fromAddress).GetIpv4(), InetSocketAddress::ConvertFrom(fromAddress).GetPort());
    }
  NS_ASSERT(InetSocketAddress::ConvertFrom(toAddress).GetIpv4() == m_localAddress);
  NS_ASSERT(InetSocketAddress::ConvertFrom(toAddress).GetPort() == m_localPort);
  NS_ASSERT(InetSocketAddress::ConvertFrom(fromAddress).GetIpv4() == m_remoteAddress);
  NS_ASSERT(InetSocketAddress::ConvertFrom(fromAddress).GetPort() == m_remotePort);

  // We only setup destroy callback for MPTCP connection's endPoints, not on subflows endpoints.
  SetupCallback();
  m_mptcp->m_sockets.push_back(this);

  // Create new master subflow (master subsock) and assign its endpoint to the connection endpoint
  Ptr<MpTcpSubFlow> sFlow = CreateObject<MpTcpSubFlow>();
  sFlow->routeId = (subflows.size() == 0 ? 0 : subflows[subflows.size() - 1]->routeId + 1);
  sFlow->sAddr = m_localAddress; //m_endPoint->GetLocalAddress();
  sFlow->sPort = m_localPort;    //m_endPoint->GetLocalPort();
  sFlow->dAddr = m_remoteAddress;
  sFlow->dPort = m_remotePort;
  sFlow->MSS = segmentSize;
  sFlow->state = SYN_RCVD;
  sFlow->cnCount = sFlow->cnRetries;
  sFlow->m_endPoint = m_endPoint; // This is master subsock, its endpoint is the same as connection endpoint.
  NS_LOG_INFO ("("<< (int)sFlow->routeId<<") LISTEN -> SYN_RCVD");
  subflows.insert(subflows.end(), sFlow);
  sFlow->RxSeqNumber = (mptcpHeader.GetSequenceNumber()).GetValue() + 1; //Set the subflow sequence number and send SYN+ACK
  NS_LOG_DEBUG("CompleteFork -> RxSeqNb: " << sFlow->RxSeqNumber << " highestAck: " << sFlow->highestAck);
  SendEmptyPacket(sFlow->routeId, TcpHeader::SYN | TcpHeader::ACK);

  // Update currentSubflow in case close just after 3WHS.
  currentSublow = sFlow->routeId;
  NS_LOG_UNCOND("CompleteFork -> receivingBufferSize: " << recvingBuffer->bufMaxSize);NS_LOG_INFO(this << "  MPTCP connection is initiated (Receiver): " << sFlow->sAddr << ":" << sFlow->sPort << " -> " << sFlow->dAddr << ":" << sFlow->dPort);
}

/** Received a packet upon LISTEN state. */
void
MpTcpSocketBase::ProcessListen(uint8_t sFlowIdx, Ptr<Packet> packet, const TcpHeader& mptcpHeader, const Address& fromAddress,
    const Address& toAddress)
{
  NS_LOG_FUNCTION (m_node->GetId() << mptcpHeader);
  uint8_t tcpflags = mptcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  /*
   * Here the SYN is only flag that is expected to receives in normal operation.
   * But, it might also be possible to get SYN with data piggyback when MPTCP has already an ESTABLISHED master subflow.
   */
  if (tcpflags == TcpHeader::SYN)
    { // Receiver got new SYN...Sends SYN+ACK.
      // This is a valid condition when receiver got SYN with MP_JOIN from sender and create new subflow with LISTEN state.
      NS_LOG_INFO(" (" << sFlow->routeId << ") " << TcpStateName[sFlow->state] << " -> SYN_RCVD");
      sFlow->state = SYN_RCVD;
      sFlow->RxSeqNumber = (mptcpHeader.GetSequenceNumber()).GetValue() + 1;
      NS_ASSERT(sFlow->highestAck == mptcpHeader.GetAckNumber().GetValue());
      SendEmptyPacket(sFlowIdx, TcpHeader::SYN | TcpHeader::ACK);
    }
  else if (tcpflags == TcpHeader::ACK)
    {
      NS_FATAL_ERROR("Subflow state is LISTEN, how come it receives ACK flag...");
    }

  if (tcpflags == 0 && subflows.size() > 1)
    {// Slave subflows can receive SYN flag piggyback data packet.
      ReceivedData(sFlowIdx, packet, mptcpHeader);
    }
}

/** Received a packet upon SYN_SENT */
void
MpTcpSocketBase::ProcessSynSent(uint8_t sFlowIdx, Ptr<Packet> packet, const TcpHeader& mptcpHeader)
{
  NS_LOG_FUNCTION (this << mptcpHeader);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];

  // Extract the flags. PSH and URG are not honoured.
  uint8_t tcpflags = mptcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG);

  // Execute a action based on tcpflags
  if (tcpflags == 0)
    { // Bare data, accept it and move to ESTABLISHED state. This is not a normal behaviour. Remove this?
      NS_ASSERT(tcpflags != 0);
    }
  else if (tcpflags == TcpHeader::ACK)
    {
      NS_ASSERT(tcpflags != TcpHeader::ACK);
    }
  else if (tcpflags == TcpHeader::SYN)
    {
      NS_ASSERT(tcpflags != TcpHeader::SYN);
    }
  else if (tcpflags == (TcpHeader::SYN | TcpHeader::ACK))
    { // Handshake completed for sender... Send final ACK
      NS_LOG_WARN("---------------------- HandShake is Completed in ClientSide ----------------------" << subflows.size());
      if (!m_connected)
        { // This function only excute for initial subflow since when it has established then MPTCP connection is already established!!
          m_connected = true;
          m_endPoint->SetPeer(m_remoteAddress, m_remotePort);
        }NS_LOG_INFO("(" << sFlow->routeId << ") "<< TcpStateName[sFlow->state] << " -> ESTABLISHED");
      sFlow->state = ESTABLISHED;
      sFlow->retxEvent.Cancel();
      sFlow->StartTracing("cWindow");
      sFlow->rtt->Init(mptcpHeader.GetAckNumber());
      sFlow->initialSequnceNumber = (mptcpHeader.GetAckNumber().GetValue());
      NS_LOG_INFO("(" <<sFlow->routeId << ") InitialSeqNb of data packet should be --->>> " << sFlow->initialSequnceNumber);
      sFlow->RxSeqNumber = (mptcpHeader.GetSequenceNumber()).GetValue() + 1;
      sFlow->highestAck = std::max(sFlow->highestAck, mptcpHeader.GetAckNumber().GetValue() - 1);
      sFlow->TxSeqNumber = mptcpHeader.GetAckNumber().GetValue();
      sFlow->maxSeqNb = sFlow->TxSeqNumber - 1;

      Time estimate;
      estimate = Seconds(1.5);
      sFlow->rtt->SetCurrentEstimate(estimate);

      SendEmptyPacket(sFlowIdx, TcpHeader::ACK);

      // Advertise available addresses...
      if (addrAdvertised == false)
        {
          NS_LOG_WARN("---------------------- AdvertiseAvailableAddresses By Client ---------------------");
          AdvertiseAvailableAddresses();
          addrAdvertised = true;
        }
      if (m_state != ESTABLISHED)
        {
          m_state = ESTABLISHED;
          NotifyConnectionSucceeded();
        }NS_LOG_UNCOND("ProcessSynSent -> SubflowsSize: " << subflows.size());
    }
  else
    { // Other in-sequence input
      NS_ASSERT(3 != 3);
    }
}

/** Received a packet upon SYN_RCVD */
void
MpTcpSocketBase::ProcessSynRcvd(uint8_t sFlowIdx, Ptr<Packet> packet, const TcpHeader& mptcpHeader, const Address& fromAddress,
    const Address& toAddress)
{
  NS_LOG_FUNCTION (this << mptcpHeader);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  uint8_t tcpflags = mptcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG);

  if ((tcpflags == TcpHeader::ACK))
    { // handshake is completed nicely in the receiver.
      NS_LOG_INFO (" ("<< sFlow->routeId << ") " << TcpStateName[sFlow->state]<<" -> ESTABLISHED");
      sFlow->state = ESTABLISHED; // Subflow state is ESTABLISHED
      m_state = ESTABLISHED; // NEED TO CONSIDER IT AGAIN....
      sFlow->connected = true;    // This means subflow is established
      sFlow->retxEvent.Cancel();  // This would cancel ReTxTimer where it being setup when SYN is sent.
      NS_ASSERT(sFlow->RxSeqNumber == mptcpHeader.GetSequenceNumber().GetValue());
      sFlow->TxSeqNumber++;
      sFlow->maxSeqNb = sFlow->TxSeqNumber - 1;
      NS_ASSERT(sFlow->TxSeqNumber == mptcpHeader.GetAckNumber().GetValue());

      // Check MPTCP Connection status. If it is not yet ESTABLISHED then change it to true to indicate that.
      if (m_connected != true)
        {
          m_connected = true;
          NotifyNewConnectionCreated(this, m_remoteAddress);
        }NS_LOG_DEBUG ("---------------------- HandShake is Completed in ServerSide ----------------------" << subflows.size());
    }
  else if (tcpflags == TcpHeader::SYN)
    { // SYN/ACK sent might be lost, send SYN/ACK again.
      NS_LOG_INFO ("("<< sFlow->routeId << ") " << "SYN_RCVD -> SYN_RCVD");
      sFlow->RxSeqNumber = (mptcpHeader.GetSequenceNumber()).GetValue() + 1;
      SendEmptyPacket(sFlowIdx, TcpHeader::SYN | TcpHeader::ACK);
    }
  else if (tcpflags == (TcpHeader::FIN | TcpHeader::ACK))
    {
    }
}

/** Received a packet upon CLOSE_WAIT, FIN_WAIT_1, or FIN_WAIT_2 states */
void
MpTcpSocketBase::ProcessWait(uint8_t sFlowIdx, Ptr<Packet> packet, const TcpHeader& mptcpHeader)
{
  NS_LOG_FUNCTION (this << sFlowIdx <<packet <<mptcpHeader); //
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  // Extract the flags. PSH and URG are not honoured.
  uint8_t tcpflags = mptcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG);

  if (packet->GetSize() > 0 && tcpflags != TcpHeader::ACK)
    { // Bare data, accept it
      ReceivedData(sFlowIdx, packet, mptcpHeader);
    }
  else if (tcpflags == TcpHeader::ACK)
    { // Process the ACK, and if in FIN_WAIT_1, conditionally move to FIN_WAIT_2
      ReceivedAck(sFlowIdx, packet, mptcpHeader);
    }
  else if (tcpflags == TcpHeader::FIN || tcpflags == (TcpHeader::FIN | TcpHeader::ACK))
    { // Got FIN, respond with ACK and move to next state
      NS_LOG_INFO( "("<<(int) sFlow->routeId << ") ProcessWait -> " << mptcpHeader);
      if (tcpflags & TcpHeader::ACK)
        { // Process the ACK first
          NS_LOG_INFO( "("<<(int)sFlow->routeId << ") ProcessWait -> ReceviedAck() sFlow->state: " << TcpStateName[sFlow->state]);
          ReceivedAck(sFlowIdx, packet, mptcpHeader);
        }
      sFlow->SetFinSequence(mptcpHeader.GetSequenceNumber());
      NS_LOG_INFO ("("<<(int)sFlow->routeId<<") Accepted FIN at seq " << mptcpHeader.GetSequenceNumber () + SequenceNumber32 (packet->GetSize ()) << ", PktSize: " << packet->GetSize() << " {ProcessWait}");
    }
  else if (tcpflags == TcpHeader::SYN || tcpflags == (TcpHeader::SYN | TcpHeader::ACK))
    { // Duplicated SYN or SYN+ACK, possibly due to spurious retransmission
      NS_LOG_INFO("ProcessWait -> got SYN or SYN/ACK  " << mptcpHeader);
      return;
    }
  else
    { // This is a RST or bad flags
      NS_LOG_INFO("ProcessWait -> got RST or bad flags  " << mptcpHeader);
      if (tcpflags != TcpHeader::RST)
        {
          NS_LOG_LOGIC ("Illegal flag " << tcpflags << " received. Reset packet is sent.");
          SendRST(sFlowIdx);
        }
      CloseAndNotify(sFlowIdx);
      return;
    }
  // Check if the close responder sent an in-sequence FIN, if so, respond ACK
  if ((sFlow->state == FIN_WAIT_1 || sFlow->state == FIN_WAIT_2) && sFlow->Finished())
    {
      if (sFlow->state == FIN_WAIT_1)
        {
          NS_LOG_INFO ("("<< (int) sFlowIdx <<") FIN_WAIT_1 -> CLOSING {ProcessWait}");
          sFlow->state = CLOSING;
          if (sendingBuffer->Empty() && sFlow->mapDSN.size() == 0 && mptcpHeader.GetAckNumber().GetValue() == sFlow->highestAck + 1)
            {// This ACK corresponds to the FIN sent
              TimeWait(sFlowIdx);
            }
        }
      else if (sFlow->state == FIN_WAIT_2)
        {
          TimeWait(sFlowIdx);
        }
      SendEmptyPacket(sFlowIdx, TcpHeader::ACK);
    }
}

/** Move TCP to Time_Wait state and schedule a transition to Closed state */
void
MpTcpSocketBase::TimeWait(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION((int) sFlowIdx);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  NS_LOG_INFO ("("<< (int) sFlow->routeId << ") "<<TcpStateName[sFlow->state] << " -> TIME_WAIT {TimeWait}");
  sFlow->state = TIME_WAIT;
  CancelAllTimers(sFlowIdx);

  // Move from TIME_WAIT to CLOSED after 2*MSL. Max segment lifetime is 2 min according to RFC793, p.28
  sFlow->m_timewaitEvent = Simulator::Schedule(Seconds(2 * 120), &MpTcpSocketBase::CloseMultipathConnection, this);
}

void
MpTcpSocketBase::CancelAllTimers(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION((int) sFlowIdx);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  sFlow->retxEvent.Cancel();
  sFlow->m_lastAckEvent.Cancel();
  sFlow->m_timewaitEvent.Cancel();
  NS_LOG_LOGIC( "(" << (int)sFlow->routeId<<")" << "CancelAllTimers");
}

void
MpTcpSocketBase::CancelAllSubflowTimers(void)
{
  NS_LOG_FUNCTION_NOARGS();
  for (uint32_t i = 0; i < subflows.size(); i++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[i];
      if (sFlow->state != CLOSED)
        {
          sFlow->retxEvent.Cancel();
          sFlow->m_lastAckEvent.Cancel();
          sFlow->m_timewaitEvent.Cancel();
          NS_LOG_INFO("CancelAllSubflowTimers() -> Subflow:" << sFlow->routeId);
        }
    }
}

void
MpTcpSocketBase::ProcessLastAck(uint8_t sFlowIdx, Ptr<Packet> packet, const TcpHeader& mptcpHeader)
{
  NS_LOG_FUNCTION (this << mptcpHeader);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  NS_LOG_INFO("("<< (int)sFlowIdx << ") ProcessLastAck -> HeaderSeqNb: " << mptcpHeader.GetSequenceNumber() << " == sFlow->RxSeqNb: " << sFlow->RxSeqNumber);

  // Extract the flags. PSH and URG are not honoured.
  uint8_t tcpflags = mptcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG);

  if (tcpflags == 0)
    {
      ReceivedData(sFlowIdx, packet, mptcpHeader);
    }
  else if (tcpflags == TcpHeader::ACK)
    {
      if (mptcpHeader.GetSequenceNumber() == SequenceNumber32(sFlow->RxSeqNumber))
        { // This ACK corresponds to the FIN sent. This socket closed peacefully.
          NS_LOG_INFO("("<<(int) sFlow->routeId << ") ProcessLastAck -> This ACK corresponds to the FIN sent -> CloseAndNotify (" << (int)sFlowIdx << ")");
          CloseAndNotify(sFlowIdx);

        }
    }
  else if (tcpflags == TcpHeader::FIN)
    { // Received FIN again, the peer probably lost the FIN+ACK
      SendEmptyPacket(sFlowIdx, TcpHeader::FIN | TcpHeader::ACK);
    }
  else if (tcpflags == (TcpHeader::FIN | TcpHeader::ACK) || tcpflags == TcpHeader::RST)
    {
      CloseAndNotify(sFlowIdx);
    }
  else
    { // Received a SYN or SYN+ACK or bad flags
      NS_LOG_INFO ("Illegal flag " << tcpflags << " received. Reset packet is sent.");
      SendRST(sFlowIdx);
      CloseAndNotify(sFlowIdx);
    }
}

// Receipt of new packet, put into Rx buffer
void
MpTcpSocketBase::ReceivedData(uint8_t sFlowIdx, Ptr<Packet> p, const TcpHeader& mptcpHeader)
{
  NS_LOG_FUNCTION (this << mptcpHeader);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  uint32_t expectedSeq = sFlow->RxSeqNumber;
  vector<TcpOptions*> options = mptcpHeader.GetOptions();
  TcpOptions* opt;
  bool stored = true;
  for (uint32_t i = 0; i < options.size(); i++)
    {
      opt = options[i];
      if (opt->optName == OPT_DSN)
        {
          OptDataSeqMapping* optDSN = (OptDataSeqMapping*) opt;
          if (optDSN->subflowSeqNumber == sFlow->RxSeqNumber)
            {
              if (optDSN->dataSeqNumber == nextRxSequence)
                {
                  NS_LOG_WARN("In-order DataPacket Received! SubflowSeqNb: " << optDSN->subflowSeqNumber);
                  uint32_t amountRead = recvingBuffer->ReadPacket(p, optDSN->dataLevelLength);
                  if (amountRead == 0)
                    {
                      NS_ASSERT(3!=3);
                      NS_LOG_WARN(this << "data has failed to be added in receiveBuffer!");
                      return;
                    }
                  NS_ASSERT(amountRead == optDSN->dataLevelLength && optDSN->dataLevelLength == p->GetSize());
                  sFlow->RxSeqNumber += amountRead;
                  // Do we need to increment highest ACK??
                  //sFlow->highestAck = std::max(sFlow->highestAck, (mptcpHeader.GetAckNumber()).GetValue() - 1);
                  nextRxSequence += amountRead;
                  ReadUnOrderedData();
                  if (expectedSeq < sFlow->RxSeqNumber)
                    {
                      NotifyDataRecv();
                    }
                  SendEmptyPacket(sFlowIdx, TcpHeader::ACK);
                  // If we received FIN before and now completed all "holes" in rx buffer, invoke peer close
                  if (sFlow->Finished() && (mptcpHeader.GetFlags() & TcpHeader::FIN) == 0)
                    {
                      NS_LOG_INFO("("<< (int) sFlowIdx <<") Last data packet received, now received FIN is in sequence!");
                      DoPeerClose(sFlowIdx);
                      return;
                    }
                }
              else if (optDSN->dataSeqNumber > nextRxSequence) // there is a gap in dataSeqNumber
                {
                  NS_LOG_WARN("optDSN->dataSeqNumber > nextRxSequence");
                  stored = StoreUnOrderedData(
                      new DSNMapping(sFlowIdx, optDSN->dataSeqNumber, optDSN->dataLevelLength, optDSN->subflowSeqNumber,
                          mptcpHeader.GetAckNumber().GetValue(), p));
                  // I think subflowSeqNumber should be advanced here as it is in-sequence even though dataSeqNum is unordered!
                  // So if we don't send ACK here then sender can't send anymore data until it receives ACK or its timeout run-out.
                  if (stored)
                    {
                      sFlow->RxSeqNumber += optDSN->dataLevelLength;
                      sFlow->highestAck = std::max(sFlow->highestAck, (mptcpHeader.GetAckNumber()).GetValue() - 1);
                    }
                  SendEmptyPacket(sFlowIdx, TcpHeader::ACK);
                }
              else
                {
                  NS_ASSERT(3!=3);
                  NS_LOG_WARN(this << "Data received is duplicated in DataSeq Lavel so it has been rejected!");
                  SendEmptyPacket(sFlowIdx, TcpHeader::ACK);
                }
            }
          else if (optDSN->subflowSeqNumber > sFlow->RxSeqNumber)
            { // There is a gap in subflowSeqNumber
              // This condition might occures when a packet get drop...
              stored = StoreUnOrderedData(
                  new DSNMapping(sFlowIdx, optDSN->dataSeqNumber, optDSN->dataLevelLength, optDSN->subflowSeqNumber,
                      mptcpHeader.GetAckNumber().GetValue(), p));
              if (stored)
                {
                  SendEmptyPacket(sFlowIdx, TcpHeader::ACK); // Since there is a gap in subflow level then we ask for it!
                }
              else
                {
                  NS_LOG_ERROR("Data failed to be stored in unOrderedBuffer SegNb: " << optDSN->subflowSeqNumber);
                  SendEmptyPacket(sFlowIdx, TcpHeader::ACK);
                }
            }
          else if (optDSN->subflowSeqNumber < sFlow->RxSeqNumber)
            { // Received subflowSeqNumer is smaller than subflow expected RxSeqNumber
              NS_LOG_INFO("Data received is duplicated in Subflow Layer so it has been rejected! subflowSeq: " << optDSN->subflowSeqNumber << " dataSeq: " << optDSN->dataSeqNumber);
              SendEmptyPacket(sFlowIdx, TcpHeader::ACK);  // Ask for expected subflow sequnce number.
            }
          else
            NS_ASSERT(3!=3);
        }
    }
}

/** Process the newly received ACK */
void
MpTcpSocketBase::ReceivedAck(uint8_t sFlowIdx, Ptr<Packet> packet, const TcpHeader& mptcpHeader)
{
  NS_LOG_FUNCTION (this << sFlowIdx << mptcpHeader);

  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  uint32_t ack = (mptcpHeader.GetAckNumber()).GetValue();

  uint32_t tmp = ((ack - sFlow->initialSequnceNumber) / sFlow->MSS) % mod;
  sFlow->ACK.push_back(make_pair(Simulator::Now().GetSeconds(), tmp));

  // Stop execution if TCPheader is not ACK at all.
  if (0 == (mptcpHeader.GetFlags() & TcpHeader::ACK))
    { // Ignore if no ACK flag
      NS_ASSERT(3!=3);
    }
  // Received ACK. Compare the ACK number against highest unacked seqno.
  else if (ack <= sFlow->highestAck + 1)
    {
      NS_LOG_LOGIC ("This acknowlegment" << mptcpHeader.GetAckNumber () << "do not ack the latest data in subflow level");
      list<DSNMapping *>::iterator current = sFlow->mapDSN.begin();
      list<DSNMapping *>::iterator next = sFlow->mapDSN.begin();
      while (current != sFlow->mapDSN.end())
        {
          ++next;
          DSNMapping *ptrDSN = *current;
          // All segments before ackSeqNum should be removed from the mapDSN list.
          if (ptrDSN->subflowSeqNumber + ptrDSN->dataLevelLength <= ack)
            { // Optional task ...
              //next = sFlow->mapDSN.erase(current);
              //delete ptrDSN;
            }
          // There is a sent segment with subflowSN equal to ack but the ack is smaller than already receveid acked!
          else if ((ptrDSN->subflowSeqNumber == ack) && (ack < sFlow->highestAck + 1))
            { // Case 1: Old ACK, ignored.
              NS_LOG_WARN ("Ignored ack of " << mptcpHeader.GetAckNumber());
              NS_ASSERT(3!=3);
              break;
            }
          // There is a sent segment with requested SequenceNumber and ack is for first unacked byte!!
          else if ((ptrDSN->subflowSeqNumber == ack) && (ack == sFlow->highestAck + 1))
            { // Case 2: Potentially a duplicated ACK, so ack should be smaller than nextExpectedSN to send.
              if (ack < sFlow->TxSeqNumber)
                {
                  //NS_LOG_ERROR(Simulator::Now().GetSeconds()<< " [" << m_node->GetId()<< "] Duplicated ack received for SeqgNb: " << ack << " DUPACKs: " << sFlow->m_dupAckCount + 1);
                  DupAck(sFlowIdx, ptrDSN);
                  break;
                }
              // otherwise, the ACK is precisely equal to the nextTxSequence
              NS_ASSERT(ack <= sFlow->TxSeqNumber);
              break;
            }
          current = next;
        }
    }
  else if (ack > sFlow->highestAck + 1)
    { // Case 3: New ACK, reset m_dupAckCount and update m_txBuffer (DSNMapping List)
      NS_LOG_WARN ("New ack of " << mptcpHeader.GetAckNumber ());
      NewAckNewReno(sFlowIdx, mptcpHeader, 0);
      sFlow->m_dupAckCount = 0;
    }
  // If there is any data piggybacked, store it into m_rxBuffer
  if (packet->GetSize() > 0)
    {
      NS_ASSERT(3!=3);
      NS_LOG_WARN(this << " ReceivedAck -> There is data piggybacked, deal with it...");
      ReceivedData(sFlowIdx, packet, mptcpHeader);
    }
}

void
MpTcpSocketBase::SetSegSize(uint32_t size)
{
  segmentSize = size;
  NS_ABORT_MSG_UNLESS(m_state == CLOSED, "Cannot change segment size dynamically.");
}

uint32_t
MpTcpSocketBase::GetSegSize(void) const
{
  return segmentSize;
}

uint32_t
MpTcpSocketBase::SendDataPacket(uint8_t sFlowIdx, uint32_t size, bool withAck)
{

  NS_LOG_FUNCTION (this << (uint32_t)sFlowIdx << size << withAck);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  Ptr<Packet> p = 0;
  DSNMapping * ptrDSN = 0;
  uint32_t packetSize = size;
  bool guard = false;
  /*
   * If timeout happens then TxSeqNumber would be shifted down to the seqNb after highestAck,
   * but maxSeqNb would be still related to maxSeqNb ever sent.
   * Thus we can conclude that when maxSeqNb is bigger than TxSeqNumber -1, we are in timeout has occurred.
   * So we have to send packet from subflowBuffer (mapDSN) instead of connection buffer (sendingBuffer),
   * In other situations maxSeqNb should be equal to TxSeqNumber -1.
   * Boolean 'guard' become true if timeOut is occurred!!
   */
  if (sFlow->maxSeqNb > sFlow->TxSeqNumber)
    {
      uint32_t cunt = 0;
      for (list<DSNMapping *>::iterator it = sFlow->mapDSN.begin(); it != sFlow->mapDSN.end(); ++it)
        {
          cunt++;
          DSNMapping * ptr = *it;
          if (ptr->subflowSeqNumber == sFlow->TxSeqNumber)
            {
              ptrDSN = ptr;
              p = Create<Packet>(ptrDSN->packet, ptrDSN->dataLevelLength);
              packetSize = ptrDSN->dataLevelLength;
              guard = true;
              NS_LOG_ERROR(Simulator::Now().GetSeconds() <<" Oooops- maxSeqNb: " << sFlow->maxSeqNb << " TxSeqNb: " << sFlow->TxSeqNumber << " FastRecovery: " << sFlow->m_inFastRec << " SegNb: " << ptrDSN->subflowSeqNumber);NS_LOG_WARN("Ooops continue packetSize: " << packetSize << " this is from stored sent segment of number: " << cunt);
              break;
            }
        }
    }
  else
    NS_ASSERT_MSG(sFlow->maxSeqNb == sFlow->TxSeqNumber -1, " maxSN: " << sFlow->maxSeqNb << " TxSeqNb-1" << sFlow->TxSeqNumber -1);
  /*
   * If no packet has made yet and maxSeqNb is equal to TxSeqNumber -1,
   * then we can safely create a packet from connection buffer (sendingBuffer).
   */
  if (p == 0 && ptrDSN == 0)
    {
      NS_ASSERT(!guard);
      NS_ASSERT(sFlow->maxSeqNb == sFlow->TxSeqNumber -1);
      p = sendingBuffer->CreatePacket(size);
      if (p == 0)
        { // When this condition might occurs?
          NS_ASSERT(3!=3);
          NS_LOG_WARN("No data is available in SendingBuffer to create a pkt from it!");
          return 0;
        }
    }
  NS_ASSERT(packetSize <= size);
  NS_ASSERT(packetSize == p->GetSize());

  // This is data packet, so its TCP_Flag should be 0
  uint8_t flags = withAck ? TcpHeader::ACK : 0;

  // Add FIN to the last data packet...Change subflow state to FIN_WAIT_1, receiver side is not needed for us though!
  // uint32_t remainingData = m_txBuffer.SizeFromSequence (seq + SequenceNumber32 (sz));
  /*
   * Only one subflow can triggered active close, i.e., attaching the FIN to the last data packet from SendingBuffer
   */

//  uint32_t remainingData = sendingBuffer->PendingData();
//  if (m_closeOnEmpty && (remainingData == 0) && !guard) // add guard temporarily
//    {
//      flags |= TcpHeader::FIN; // Add FIN to the flag
//      if (sFlow->state == ESTABLISHED)
//        { // On active close: I am the first one to send FIN
//          NS_LOG_INFO ("(" << (int)sFlow->routeId<< ") ESTABLISHED -> FIN_WAIT_1 {SendPendingData} -> FIN is peggyback to last data Packet! MapDSN: " << sFlow->mapDSN.size() << ", pSize: " << p->GetSize());
//          sFlow->state = FIN_WAIT_1;
//        }
//      /*
//       * When receiver got FIN from peer (sender) and now its app sent all of its pending data,
//       * so server now can attaches FIN to its last data packet. This condition is not expected to occured now,
//       * but we keep it here for future version our implementation that support bidirection communication.
//       */
//      else if (sFlow->state == CLOSE_WAIT)
//        { // On passive close: Peer sent me FIN already
//          NS_LOG_INFO ("CLOSE_WAIT -> LAST_ACK (SendPendingData)");
//          sFlow->state = LAST_ACK;
//          NS_FATAL_ERROR("This is not expected to occured in our unidirectional MPTCP imeplmetation.");
//        }
//    }
//
// Add MPTCP header to the packet
  TcpHeader header;
  header.SetFlags(flags);
  header.SetSequenceNumber(SequenceNumber32(sFlow->TxSeqNumber));
  header.SetAckNumber(SequenceNumber32(sFlow->RxSeqNumber));
  header.SetSourcePort(sFlow->sPort);
  header.SetDestinationPort(sFlow->dPort);
  header.SetWindowSize(AdvertisedWindowSize());
  if (!guard)
    { // If packet is made from sendingBuffer, then we got to add the packet and its info to subflow's mapDSN.
      sFlow->AddDSNMapping(sFlowIdx, nextTxSequence, packetSize, sFlow->TxSeqNumber, sFlow->RxSeqNumber, p->Copy());
    }
  if (!guard)
    { // if packet is made from sendingBuffer, then we use nextTxSequence to OptDSN
      header.AddOptDSN(OPT_DSN, nextTxSequence, packetSize, sFlow->TxSeqNumber);
    }
  else
    { // if packet is made from subflow's Buffer (already sent packets), that packet's dataSeqNumber should be added here!
      header.AddOptDSN(OPT_DSN, ptrDSN->dataSeqNumber, (uint16_t) packetSize, sFlow->TxSeqNumber);
      NS_ASSERT(packetSize == ptrDSN->dataLevelLength);
    }

  uint8_t hlen = 5;   // 5 --> 32-bit words = 20 Bytes == TcpHeader Size with out any option
  uint8_t olen = 15;  // 15 because packet size is 2 bytes in size. 1 + 8 + 2+ 4 = 15
  uint8_t plen = 0;
  plen = (4 - (olen % 4)) % 4; // (4 - (15 % 4)) 4 => 1
  olen = (olen + plen) / 4;    // (15 + 1) / 4 = 4
  hlen += olen;
  header.SetLength(hlen);
  header.SetOptionsLength(olen);
  header.SetPaddingLength(plen);

  NS_LOG_ERROR("hLen: " << (int)hlen << " oLen: " << (int)olen << " pLen: " << (int)plen);

  // Check RTO, if expired then reschedule it again.
  SetReTxTimeout(sFlowIdx);
  NS_LOG_LOGIC ("Send packet via TcpL4Protocol with flags 0x" << std::hex << static_cast<uint32_t> (flags) << std::dec);

  // simulating loss of acknoledgement in the sender side
  calculateTotalCWND();
  // This time, we'll explicitly create the error model we want
  Ptr<ListErrorModel> rem = CreateObject<ListErrorModel>();
  rem->SetList(sampleList);
  getQueuePkt(sFlow->sAddr);
  if (rem->IsCorrupt(p))
    { // {ranVar < rate => Packet drop...}
      PacketDrop.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd.Get()));
      uint32_t tmp = (((sFlow->TxSeqNumber + packetSize) - sFlow->initialSequnceNumber) / sFlow->MSS) % mod;
      sFlow->DROP.push_back(make_pair(Simulator::Now().GetSeconds(), tmp));
    }
  else
    {
      Ptr<NetDevice> netDevice = FindOutputNetDevice(sFlow->sAddr);
      m_mptcp->SendPacket(p, header, sFlow->sAddr, sFlow->dAddr, netDevice);
      if (!guard)
        sFlow->PktCount++;
      uint32_t tmp = (((sFlow->TxSeqNumber + packetSize) - sFlow->initialSequnceNumber) / sFlow->MSS) % mod;
      sFlow->DATA.push_back(make_pair(Simulator::Now().GetSeconds(), tmp));
    }NS_LOG_WARN(Simulator::Now().GetSeconds() << " ["<< m_node->GetId()<< "] SendDataPacket->  " << header <<" dSize: " << packetSize<< " sFlow: " << sFlow->routeId);

  // Do some updates.....
  sFlow->rtt->SentSeq(SequenceNumber32(sFlow->TxSeqNumber), packetSize); // Notify the RTT of a data packet sent
  sFlow->TxSeqNumber += packetSize; // Update subflow's nextSeqNum to send.
  sFlow->maxSeqNb = std::max(sFlow->maxSeqNb, sFlow->TxSeqNumber - 1);
  if (!guard)
    {
      nextTxSequence += packetSize;  // Update connection sequence number
    }

  NS_LOG_INFO( "("<< (int) sFlowIdx<< ") DataPacket -----> " << header << "  " << m_localAddress << ":" << m_localPort<< "->" << m_remoteAddress << ":" << m_remotePort);
  if (guard)
    return 0;
  else
    return packetSize;
}

void
MpTcpSocketBase::DoRetransmit(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION (this);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];

  // Retransmit SYN packet
  if (sFlow->state == SYN_SENT)
    {
//      if (sFlow->cnCount > 0)
//        {
      //SendEmptyPacket(sFlowIdx, TcpHeader::SYN);
//        }
//      else
//        {
//          NotifyConnectionFailed();
//        }
      return;
    }

  // Retransmit non-data packet: Only if in FIN_WAIT_1 or CLOSING state
  if (sendingBuffer->Empty() && sFlow->mapDSN.size() == 0)
    {
      if (sFlow->state == FIN_WAIT_1 || sFlow->state == CLOSING)
        { // Must have lost FIN, re-send
          NS_LOG_INFO("DoRetransmit -> Resent FIN... TxSeqNumber: " << sFlow->TxSeqNumber);
          SendEmptyPacket(sFlowIdx, TcpHeader::FIN);
        }
      return;
    }

  DSNMapping* ptrDSN = sFlow->GetunAckPkt();
  if (ptrDSN == 0)
    {
      NS_LOG_INFO ("Retransmit -> no Unacked data !! mapDSN size is "<< sFlow->mapDSN.size() << " max Ack seq n�� "<< sFlow->highestAck << " (" << (int)sFlowIdx<< ")");
      NS_ASSERT(3!=3);
      return;
    }

  NS_ASSERT(ptrDSN->subflowSeqNumber == sFlow->highestAck +1);

  // we retransmit only one lost pkt
  Ptr<Packet> pkt = Create<Packet>(ptrDSN->packet, ptrDSN->dataLevelLength);
  TcpHeader header;
  header.SetSourcePort(sFlow->sPort);
  header.SetDestinationPort(sFlow->dPort);
  header.SetFlags(TcpHeader::NONE);  // Change to NONE Flag
  header.SetSequenceNumber(SequenceNumber32(ptrDSN->subflowSeqNumber));
  header.SetAckNumber(SequenceNumber32(sFlow->RxSeqNumber));  // for the acknowledgment, we ACK the sFlow last received data
  header.SetWindowSize(AdvertisedWindowSize());

  header.AddOptDSN(OPT_DSN, ptrDSN->dataSeqNumber, ptrDSN->dataLevelLength, ptrDSN->subflowSeqNumber);

  uint8_t hlen = 5;
  uint8_t olen = 15;
  uint8_t plen = 0;
  plen = (4 - (olen % 4)) % 4;
  olen = (olen + plen) / 4;
  hlen += olen;
  header.SetLength(hlen);
  header.SetOptionsLength(olen);
  header.SetPaddingLength(plen);

  m_mptcp->SendPacket(pkt, header, sFlow->sAddr, sFlow->dAddr, FindOutputNetDevice(sFlow->sAddr));

  //reset RTO
  SetReTxTimeout(sFlowIdx);

  uint32_t tmp = (((ptrDSN->subflowSeqNumber + ptrDSN->dataLevelLength) - sFlow->initialSequnceNumber) / sFlow->MSS) % mod;
  sFlow->RETRANSMIT.push_back(make_pair(Simulator::Now().GetSeconds(), tmp));

  if (sFlow->m_inFastRec)
    NS_LOG_LOGIC(Simulator::Now().GetSeconds() << " PartialAck ReTx-> SeqNb: " << ptrDSN->subflowSeqNumber);
  else
    {
      timeOutTrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd));
    }

  // Update Rtt
  sFlow->rtt->SentSeq(SequenceNumber32(ptrDSN->subflowSeqNumber), ptrDSN->dataLevelLength);

  // In case of RTO, advance m_nextTxSequence
  sFlow->TxSeqNumber = std::max(sFlow->TxSeqNumber, ptrDSN->subflowSeqNumber + ptrDSN->dataLevelLength);
  sFlow->maxSeqNb = std::max(sFlow->maxSeqNb, sFlow->TxSeqNumber - 1);
}

void
MpTcpSocketBase::DoRetransmit(uint8_t sFlowIdx, DSNMapping* ptrDSN)
{
  NS_LOG_FUNCTION(this);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];

  // This retransmit segment should be the lost segment.
  NS_ASSERT(ptrDSN->subflowSeqNumber >= sFlow->highestAck +1);

  SetReTxTimeout(sFlowIdx); // reset RTO

  // we retransmit only one lost pkt
  Ptr<Packet> pkt = Create<Packet>(ptrDSN->packet, ptrDSN->dataLevelLength);
  if (pkt == 0)
    NS_ASSERT(3!=3);

  TcpHeader header;
  header.SetSourcePort(sFlow->sPort);
  header.SetDestinationPort(sFlow->dPort);
  header.SetFlags(TcpHeader::NONE);  // Change to NONE Flag
  header.SetSequenceNumber(SequenceNumber32(ptrDSN->subflowSeqNumber));
  header.SetAckNumber(SequenceNumber32(sFlow->RxSeqNumber));
  header.SetWindowSize(AdvertisedWindowSize());
  // Make sure info here comes from ptrDSN...
  header.AddOptDSN(OPT_DSN, ptrDSN->dataSeqNumber, ptrDSN->dataLevelLength, ptrDSN->subflowSeqNumber);

  NS_LOG_WARN (Simulator::Now().GetSeconds() <<" RetransmitSegment -> "<< " localToken "<< localToken<<" Subflow "<<(int) sFlowIdx<<" DataSeq "<< ptrDSN->dataSeqNumber <<" SubflowSeq " << ptrDSN->subflowSeqNumber <<" dataLength " << ptrDSN->dataLevelLength << " packet size " << pkt->GetSize() << " 3DupACK");
  uint8_t hlen = 5;
  uint8_t olen = 15;
  uint8_t plen = 0;
  plen = (4 - (olen % 4)) % 4;
  olen = (olen + plen) / 4;
  hlen += olen;
  header.SetLength(hlen);
  header.SetOptionsLength(olen);
  header.SetPaddingLength(plen);

  // Send Segment to lower layer
  m_mptcp->SendPacket(pkt, header, sFlow->sAddr, sFlow->dAddr, FindOutputNetDevice(sFlow->sAddr));
  uint32_t tmp = (((ptrDSN->subflowSeqNumber + ptrDSN->dataLevelLength) - sFlow->initialSequnceNumber) / sFlow->MSS) % mod;
  sFlow->RETRANSMIT.push_back(make_pair(Simulator::Now().GetSeconds(), tmp));

  // Notify RTT
  sFlow->rtt->SentSeq(SequenceNumber32(ptrDSN->subflowSeqNumber), ptrDSN->dataLevelLength);

  // In case of RTO, advance m_nextTxSequence
  sFlow->TxSeqNumber = std::max(sFlow->TxSeqNumber, ptrDSN->subflowSeqNumber + ptrDSN->dataLevelLength);

  // highest sent sequence number should be updated!
  sFlow->maxSeqNb = std::max(sFlow->maxSeqNb, sFlow->TxSeqNumber - 1);

  NS_LOG_INFO("("<<(int) sFlowIdx << ") DoRetransmit -> " << header);
}
void
MpTcpSocketBase::DiscardUpTo(uint8_t sFlowIdx, uint32_t ack)
{
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  list<DSNMapping *>::iterator current = sFlow->mapDSN.begin();
  list<DSNMapping *>::iterator next = sFlow->mapDSN.begin();
  while (current != sFlow->mapDSN.end())
    {
      ++next;
      DSNMapping *ptrDSN = *current;
      // All segments before ackSeqNum should be removed from the mapDSN list. Maybe equal part never run due to if condition above.
      if (ptrDSN->subflowSeqNumber + ptrDSN->dataLevelLength <= ack)
        {
          NS_LOG_WARN("DiscardUp-> SeqNb: " << ptrDSN->subflowSeqNumber << " DSNMappingSize: " << sFlow->mapDSN.size() - 1 << " Subflow(" << (int)sFlow->routeId << ")");
          next = sFlow->mapDSN.erase(current);
          delete ptrDSN;
        }
      current = next;
    }
}
// .....................................................................................................
uint8_t
MpTcpSocketBase::GetMaxSubFlowNumber()
{
  return maxSubflows;
}

void
MpTcpSocketBase::SetMaxSubFlowNumber(uint8_t num)
{
  maxSubflows = num;
}
//...........................................................................................
// Following implementation has derived from tcp-reno implementation
//...........................................................................................
void
MpTcpSocketBase::SetSSThresh(uint32_t threshold)
{
  m_ssThresh = threshold;
}

uint32_t
MpTcpSocketBase::GetSSThresh(void) const
{
  return m_ssThresh;
}

void
MpTcpSocketBase::SetInitialCwnd(uint32_t cwnd)
{
  NS_ABORT_MSG_UNLESS(m_state == CLOSED, "MpTcpsocketBase::SetInitialCwnd() cannot change initial cwnd after connection started.");
  m_initialCWnd = cwnd;
}

uint32_t
MpTcpSocketBase::GetInitialCwnd(void) const
{
  return m_initialCWnd;
}

Ptr<TcpSocketBase>
MpTcpSocketBase::Fork(void)
{
  return CopyObject<MpTcpSocketBase>(this);
}

/** Cut cwnd and enter fast recovery mode upon triple dupack */
void
MpTcpSocketBase::DupAck(const TcpHeader& t, uint32_t count)
{
  NS_LOG_FUNCTION_NOARGS();
}
//...........................................................................................

int
MpTcpSocketBase::Listen(void)
{
  NS_LOG_FUNCTION(this);

  if (m_state != CLOSED)
    {
      m_errno = ERROR_INVAL;
      return -1;
    }

  // MPTCP connection state is LISTEN
  m_state = LISTEN;
  return 0;
}

int
MpTcpSocketBase::Connect(Ipv4Address servAddr, uint16_t servPort)
{
  NS_LOG_FUNCTION(this << servAddr << servPort);  //
  Ptr<MpTcpSubFlow> sFlow = CreateObject<MpTcpSubFlow>();
  sFlow->routeId = (subflows.size() == 0 ? 0 : subflows[subflows.size() - 1]->routeId + 1);
  sFlow->dAddr = servAddr;    // Assigned subflow destination address
  sFlow->dPort = servPort;    // Assigned subflow destination port
  m_remoteAddress = servAddr; // MPTCP Connection's remote address
  m_remotePort = servPort;    // MPTCP Connection's remote port

  if (m_endPoint == 0)
    {
      if (Bind() == -1) // Bind(), if there is no endpoint for this socket
        {
          NS_ASSERT(m_endPoint == 0);
          return -1; // Bind() failed.
        }
      // Make sure endpoint is created.
      NS_ASSERT(m_endPoint != 0);
    }
  // Set up remote addr:port for this endpoint as we knew it from Connect's parameters
  m_endPoint->SetPeer(servAddr, servPort);

  if (m_endPoint->GetLocalAddress() == "0.0.0.0")
    {
      // Find approapriate local address from the routing protocol for this endpoint.
      if (SetupEndpoint() != 0)
        { // Route to destination does not exist.
          return -1;
        }
    }
  else
    { // Make sure there is an route from source to destination. Source might be set wrongly.
      if ((IsThereRoute(m_endPoint->GetLocalAddress(), servAddr)) == false)
        {
          NS_LOG_INFO("Connect -> There is no route from " << m_endPoint->GetLocalAddress() << " to " << m_endPoint->GetPeerAddress());
          //m_mptcp->DeAllocate(m_endPoint); // this would fire up destroy function...
          return -1;
        }
    }

  // Set up subflow local addrs:port from endpoint
  sFlow->sAddr = m_endPoint->GetLocalAddress();
  sFlow->sPort = m_endPoint->GetLocalPort();
  sFlow->MSS = segmentSize;
  sFlow->cwnd = sFlow->MSS;
  NS_LOG_INFO("Connect -> SegmentSize: " << sFlow->MSS << " tcpSegmentSize: " << m_segmentSize << " segmentSize: " << segmentSize) ;//
  NS_LOG_UNCOND("Connect -> SendingBufferSize: " << sendingBuffer->bufMaxSize);

  // This is master subsocket (master subflow) then its endpoint is the same as connection endpoint.
  sFlow->m_endPoint = m_endPoint;
  subflows.insert(subflows.end(), sFlow);
  m_mptcp->m_sockets.push_back(this);

  //sFlow->rtt->Reset();
  sFlow->cnCount = sFlow->cnRetries;

//  if (sFlow->state == CLOSED || sFlow->state == LISTEN || sFlow->state == SYN_SENT || sFlow->state == LAST_ACK || sFlow->state == CLOSE_WAIT)
//    { // send a SYN packet and change state into SYN_SENT
  NS_LOG_INFO ("("<< (int)sFlow->routeId << ") "<< TcpStateName[sFlow->state] << " -> SYN_SENT");
  m_state = SYN_SENT;
  sFlow->state = SYN_SENT;  // Subflow state should be change first then SendEmptyPacket...
  SendEmptyPacket(sFlow->routeId, TcpHeader::SYN);
  currentSublow = sFlow->routeId; // update currentSubflow in case close just after 3WHS.
  NS_LOG_INFO(this << "  MPTCP connection is initiated (Sender): " << sFlow->sAddr << ":" << sFlow->sPort << " -> " << sFlow->dAddr << ":" << sFlow->dPort << " m_state: " << TcpStateName[m_state]);
//    }
//  else if (sFlow->state != TIME_WAIT)
//    { // In states SYN_RCVD, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, and CLOSING, an connection
//      // exists. We send RST, tear down everything, and close this socket.
//      NS_LOG_WARN(" Connect-> Can't open another connection as connection is exist -> RST need to be sent. Not yet implemented");
//    SendRST ();
//      CloseAndNotify ();
//    }
  return 0;
}

int
MpTcpSocketBase::Connect(Address &address)
{
  NS_LOG_FUNCTION ( this << address );
  InetSocketAddress transport = InetSocketAddress::ConvertFrom(address);
  m_remoteAddress = transport.GetIpv4(); // MPTCP Connection remoteAddress
  m_remotePort = transport.GetPort(); // MPTCP Connection remotePort
  return Connect(m_remoteAddress, m_remotePort);
}

/** Inhereted from Socket class: Bind socket to an end-point in MpTcpL4Protocol */
int
MpTcpSocketBase::Bind()
{
  NS_LOG_FUNCTION (this);
  client = true;
  m_endPoint = m_mptcp->Allocate();  // Create endPoint with ephemeralPort.
  if (0 == m_endPoint)
    {
      m_errno = ERROR_ADDRNOTAVAIL;
      return -1;
    }
  //m_mptcp->m_sockets.push_back(this); // We don't need it for now
  return SetupCallback();
}

/** Clean up after Bind operation. Set up callback function in the end-point */
int
MpTcpSocketBase::SetupCallback()
{
  NS_LOG_FUNCTION(this);
  if (m_endPoint == 0)
    {
      return -1;
    }
  // set the call backs method
  m_endPoint->SetRxCallback(MakeCallback(&MpTcpSocketBase::ForwardUp, Ptr<MpTcpSocketBase>(this)));
  m_endPoint->SetDestroyCallback(MakeCallback(&MpTcpSocketBase::Destroy, Ptr<MpTcpSocketBase>(this)));

  // Setup local add:port of this mptcp endpoint.
  m_localAddress = m_endPoint->GetLocalAddress();
  m_localPort = m_endPoint->GetLocalPort();

  return 0;
}

/** Inherit from socket class: Bind socket (with specific address) to an end-point in TcpL4Protocol */
int
MpTcpSocketBase::Bind(const Address &address)
{
  NS_LOG_FUNCTION (this<<address);
  server = true;
  if (!InetSocketAddress::IsMatchingType(address))
    {
      m_errno = ERROR_INVAL;
      return -1;
    }

  InetSocketAddress transport = InetSocketAddress::ConvertFrom(address);
  Ipv4Address ipv4 = transport.GetIpv4();
  uint16_t port = transport.GetPort();

  if (ipv4 == Ipv4Address::GetAny() && port == 0)
    {
      m_endPoint = m_mptcp->Allocate();
    }
  else if (ipv4 == Ipv4Address::GetAny() && port != 0)
    { // Allocate with specific port
      m_endPoint = m_mptcp->Allocate(port);
    }
  else if (ipv4 != Ipv4Address::GetAny() && port == 0)
    { // Allocate with specific ipv4 address
      m_endPoint = m_mptcp->Allocate(ipv4);
    }
  else if (ipv4 != Ipv4Address::GetAny() && port != 0)
    { // Allocate with specific Ipv4 add:port
      m_endPoint = m_mptcp->Allocate(ipv4, port);
    }
  else
    NS_LOG_ERROR("Bind to specific add:port has failed!");

  //m_mptcp->m_sockets.push_back(this); // we don't need it for now
  NS_LOG_LOGIC("MpTcpSocketBase:Bind(addr) " << this << " got an endpoint " << m_endPoint << " localAddr " << m_endPoint->GetLocalAddress() << ":" << m_endPoint->GetLocalPort() << " RemoteAddr " << m_endPoint->GetPeerAddress() << ":"<< m_endPoint->GetPeerPort());
  return SetupCallback();
}

bool
MpTcpSocketBase::SendBufferedData()
{
  return SendPendingData();
}

int
MpTcpSocketBase::FillBuffer(uint8_t* buf, uint32_t size)
{
  NS_LOG_FUNCTION( this << size );
  return sendingBuffer->Add(buf, size);
}

/**
 * Sending data via subflows with available window size. It sends data only to ESTABLISHED subflows.
 * It sends data by calling SendDataPacket() function.
 * Called by functions: SendBufferedData, ReceveidAck, NewAck
 */
bool
MpTcpSocketBase::SendPendingData(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION(this);
  if (sendingBuffer->Empty())
    {
      Ptr<MpTcpSubFlow> sF = subflows[sFlowIdx];
      NS_LOG_WARN("(" << (int) sFlowIdx << ") SendingBuffer is EMPTY and SubflowBuffer: " << sF->mapDSN.size());
      if (sF->state == ESTABLISHED && sF->mapDSN.size() > 0 && sF->maxSeqNb > sF->TxSeqNumber)
        {
          uint32_t window = std::min(AvailableWindow(sFlowIdx), sF->MSS);
          NS_LOG_ERROR("SendingBuffer Empty!, Sublfow (" << (int)sFlowIdx << ") AvailableWindow" << window);
          while (window != 0 && window >= sF->MSS)
            {
              if (SendDataPacket(sF->routeId, window, false) == 0)
                return false;
              window = std::min(AvailableWindow(sFlowIdx), sF->MSS);
            }
        }
      else
        {
          NS_LOG_WARN ("MpTcpSocketBase::SendPendingData: SendingBuffer is empty");
          return false; // Nothing to send
        }
    }

  // No endPoint -> Can't send any data
  if (m_endPoint == 0)
    {
      NS_LOG_ERROR ("MpTcpSocketBase::SendPendingData: No endpoint");
      NS_ASSERT_MSG(m_endPoint == 0, " No endpoint");
      return false; // Is this the right way to handle this condition?
    }

  uint32_t nOctetsSent = 0;
  Ptr<MpTcpSubFlow> sFlow;

  // Send data as much as possible (it depends on subflows AvailableWindow and data in sending buffer)
  while (!sendingBuffer->Empty())
    {
      uint8_t count = 0;
      uint32_t window = 0;
      // Search for a subflow with available windows
      while (count < subflows.size())
        {
          count++;
          window = std::min(AvailableWindow(lastUsedsFlowIdx), sendingBuffer->PendingData()); // Get available window size

          if (window == 0)
            {  // No more available window in the current subflow, try with another one
              NS_LOG_WARN("SendPendingData-> No window available on (" << (int)lastUsedsFlowIdx << ")");
              lastUsedsFlowIdx = getSubflowToUse();
            }
          else
            {
              NS_LOG_LOGIC ("MpTcpSocketBase::SendPendingData -> PendingData (" << sendingBuffer->PendingData() << ") Available window ("<<AvailableWindow (lastUsedsFlowIdx)<<")");
              break;
            }
        }
      // No available window for transmission in all subflows, abort sending
      if (count == subflows.size() && window == 0)
        break;

      // Take a pointer to the subflow with available window.
      sFlow = subflows[lastUsedsFlowIdx];

      // By this condition only connection initiator can send data need to be change though!
      if (sFlow->state == ESTABLISHED)
        {
          currentSublow = sFlow->routeId;
          uint32_t s = std::min(window, sFlow->MSS);  // Send no more than window
          if (sFlow->maxSeqNb > sFlow->TxSeqNumber && sendingBuffer->PendingData() <= sFlow->MSS)
            s = sFlow->MSS;
          uint32_t amountSent = SendDataPacket(sFlow->routeId, s, false);
          nOctetsSent += amountSent;  // Count total bytes sent in this loop
        } // end of if statement
      lastUsedsFlowIdx = getSubflowToUse();
    } // end of main while loop
  NS_LOG_LOGIC ("SendPendingData -> amount data sent = " << nOctetsSent << "... Notify application.");
  NotifyDataSent(GetTxAvailable());
  return (nOctetsSent > 0);
}

uint8_t
MpTcpSocketBase::getSubflowToUse()
{
  uint8_t nextSubFlow = 0;
  switch (distribAlgo)
    {
  case Round_Robin:
    nextSubFlow = (lastUsedsFlowIdx + 1) % subflows.size();
    break;
  default:
    break;
    }
  return nextSubFlow;
}

/**
 TCP: Upon RTO:
 1) ssthresh is set to half of flight size
 2) cwnd is set to 1*MSS
 3) retransmit the lost packet
 4) Tcp back to slow start
 */

void
MpTcpSocketBase::ReTxTimeout(uint8_t sFlowIdx)
{ // Retransmit timeout
  NS_LOG_FUNCTION (this);
  NS_ASSERT_MSG(client, "ReTxTimeout is not implemented for server side yet");
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];

  NS_LOG_INFO ("Subflow ("<<(int)sFlowIdx<<") ReTxTimeout Expired at time "<<Simulator::Now ().GetSeconds()<< " unacked packets count is "<<sFlow->mapDSN.size() << " sFlow->state: " << TcpStateName[sFlow->state]); //
  //NS_LOG_INFO("TxSeqNb: " << sFlow->TxSeqNumber << " HighestAck: " << sFlow->highestAck);
  // If erroneous timeout in closed/timed-wait state, just return
  if (sFlow->state == CLOSED || sFlow->state == TIME_WAIT)
    {
      NS_LOG_INFO("RETURN");
      NS_ASSERT(3!=3);
      return;
    }
  // If all data are received (non-closing socket and nothing to send), just return
  // if (m_state <= ESTABLISHED && m_txBuffer.HeadSequence() >= m_highTxMark)
  if (sFlow->state <= ESTABLISHED && sFlow->mapDSN.size() == 0)
    {
      NS_LOG_INFO("RETURN");
      NS_ASSERT(3!=3);
      return;
    }
  Retransmit(sFlowIdx); // Retransmit the packet
}

void
MpTcpSocketBase::ReduceCWND(uint8_t sFlowIdx, DSNMapping* ptrDSN)
{
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  uint32_t segmentSize = sFlow->MSS;
  int cwnd_tmp = 0;
  calculateTotalCWND();

  switch (AlgoCC)
    {
  case Uncoupled_TCPs:
    sFlow->ssthresh = std::max(2 * segmentSize, BytesInFlight(sFlowIdx) / 2);
    sFlow->cwnd = sFlow->ssthresh + 3 * segmentSize;
    break;
  case Linked_Increases:
    sFlow->ssthresh = std::max(2 * segmentSize, BytesInFlight(sFlowIdx) / 2);
    sFlow->cwnd = sFlow->ssthresh + 3 * segmentSize;
    break;
  case RTT_Compensator:
    sFlow->ssthresh = std::max(2 * segmentSize, BytesInFlight(sFlowIdx) / 2);
    sFlow->cwnd = sFlow->ssthresh + 3 * segmentSize;
    break;
  case Fully_Coupled:
    cwnd_tmp = sFlow->cwnd - totalCwnd / 2;
    if (cwnd_tmp < 0)
      cwnd_tmp = 0;
    sFlow->ssthresh = std::max((uint32_t) cwnd_tmp, 2 * segmentSize);
    sFlow->cwnd = sFlow->ssthresh + 3 * segmentSize;
    break;
  default:
    NS_ASSERT(3!=3);
    break;
    }
  // update
  sFlow->m_recover = SequenceNumber32(sFlow->maxSeqNb + 1);
  sFlow->m_inFastRec = true;

  // Retrasnmit a specific packet (lost segment)
  DoRetransmit(sFlowIdx, ptrDSN);

  // plotting
  reTxTrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd));
  sFlow->ssthreshtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->ssthresh));
}

/** Retransmit timeout */
void
MpTcpSocketBase::Retransmit(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION (this);  //
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  // Exit From Fast Recovery
  sFlow->m_inFastRec = false;
  // According to RFC2581 sec.3.1, upon RTO, ssthresh is set to half of flight
  // size and cwnd is set to 1*MSS, then the lost packet is retransmitted and
  // TCP back to slow start
  sFlow->ssthresh = std::max(2 * sFlow->MSS, BytesInFlight(sFlowIdx) / 2);
  sFlow->cwnd = sFlow->MSS; //  sFlow->cwnd = 1.0;
  sFlow->TxSeqNumber = sFlow->highestAck + 1; // m_nextTxSequence = m_txBuffer.HeadSequence(); // Restart from highest Ack
  sFlow->rtt->IncreaseMultiplier();  // Double the next RTO
  DoRetransmit(sFlowIdx);  // Retransmit the packet
  // plotting
  sFlow->_TimeOut.push_back(make_pair(Simulator::Now().GetSeconds(), TimeScale));
  // rfc 3782 - Recovering from timeOut
  //sFlow->m_recover = SequenceNumber32(sFlow->maxSeqNb + 1);
}

void
MpTcpSocketBase::SetReTxTimeout(uint8_t sFlowIdx)
{
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  if (sFlow->retxEvent.IsExpired())
    {
      Time rto = sFlow->rtt->RetransmitTimeout();
      sFlow->retxEvent = Simulator::Schedule(rto, &MpTcpSocketBase::ReTxTimeout, this, sFlowIdx);
    }
}

DSNMapping*
MpTcpSocketBase::getAckedSegment(uint8_t sFlowIdx, uint32_t ack)
{
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  DSNMapping* ptrDSN = 0;
  for (list<DSNMapping *>::iterator it = sFlow->mapDSN.begin(); it != sFlow->mapDSN.end(); ++it)
    {
      DSNMapping* dsn = *it;
      if (dsn->subflowSeqNumber + dsn->dataLevelLength == ack)
        {
          ptrDSN = dsn;
          break;
        }
    }
  return ptrDSN;
}

DSNMapping*
MpTcpSocketBase::getSegmentOfACK(uint8_t sFlowIdx, uint32_t ack)
{
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  DSNMapping* ptrDSN = 0;
  for (list<DSNMapping *>::iterator it = sFlow->mapDSN.begin(); it != sFlow->mapDSN.end(); ++it)
    {
      DSNMapping* dsn = *it;
      if (dsn->subflowSeqNumber == ack)
        {
          ptrDSN = dsn;
          break;
        }
    }
  return ptrDSN;
}
void
MpTcpSocketBase::NewAckNewReno(uint8_t sFlowIdx, const TcpHeader& mptcpHeader, TcpOptions* opt)
{
  NS_LOG_FUNCTION (this << (int)sFlowIdx);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  SequenceNumber32 ack = mptcpHeader.GetAckNumber();
  uint32_t ackedBytes = ack.GetValue() - (sFlow->highestAck + 1);

  NS_LOG_LOGIC ("TcpNewReno receieved ACK for seq " << ack <<" cwnd " << sFlow->cwnd <<" ssthresh " << sFlow->ssthresh);
  // Check for exit condition of fast recovery
  if (sFlow->m_inFastRec && ack < sFlow->m_recover)
    { // Partial ACK, partial window deflation (RFC2582 sec.3 bullet #5 paragraph 3)
      NS_LOG_WARN("NewAckNewReno -> ");
      sFlow->cwnd -= ack.GetValue() - (sFlow->highestAck + 1); // data bytes where acked
      // RFC3782 sec.5, partialAck condition for inflating.
      sFlow->cwnd += sFlow->MSS; // increase cwnd

      // Plotting
      NS_LOG_LOGIC ("Partial ACK in fast recovery: cwnd set to " << sFlow->cwnd.Get());
      PartialAck.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd.Get()));
      sFlow->ssthreshtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->ssthresh));
      sFlow->_FR_PA.push_back(make_pair(Simulator::Now().GetSeconds(), TimeScale));

      DiscardUpTo(sFlowIdx, ack.GetValue());
      DSNMapping* ptrDSN = getSegmentOfACK(sFlowIdx, ack.GetValue());
      NS_ASSERT(ptrDSN != 0);
      DoRetransmit(sFlowIdx, ptrDSN);

      MpTcpSocketBase::NewACK(sFlowIdx, mptcpHeader, opt); // update m_nextTxSequence and send new data if allowed by window
      //DoRetransmit(sFlowIdx); // Assume the next seq is lost. Retransmit lost packet
      pAck++;
      return;
    }
  else if (sFlow->m_inFastRec && ack >= sFlow->m_recover)
    { // Full ACK (RFC2582 sec.3 bullet #5 paragraph 2, option 1)
      NS_LOG_WARN("NewAckNewReno -> FullAck");
      sFlow->cwnd = std::min(sFlow->ssthresh, BytesInFlight(sFlowIdx) + sFlow->MSS);

      // Exit from Fast recovery
      sFlow->m_inFastRec = false;

      // Plotting
      FullAck.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd.Get()));
      sFlow->ssthreshtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->ssthresh));
      sFlow->_FR_FA.push_back(make_pair(Simulator::Now().GetSeconds(), TimeScale));
    }

  // MPTCP various congestion control algorithms...
  OpenCWND(sFlowIdx, ackedBytes);

// Complete newAck processing
  MpTcpSocketBase::NewACK(sFlowIdx, mptcpHeader, opt);      // update m_nextTxSequence and send new data if allowed by window
}

void
MpTcpSocketBase::NewACK(uint8_t sFlowIdx, const TcpHeader& mptcpHeader, TcpOptions* opt)
{
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  uint32_t ack = (mptcpHeader.GetAckNumber()).GetValue();
  NS_LOG_LOGIC ("[" << m_node->GetId()<< "]" << " Cancelled ReTxTimeout event which was set to expire at " << (Simulator::Now () + Simulator::GetDelayLeft (sFlow->retxEvent)).GetSeconds ());

  // On recieving a "New" ack we restart retransmission timer .. RFC 2988
  sFlow->retxEvent.Cancel();
  Time rto = sFlow->rtt->RetransmitTimeout();
  NS_LOG_LOGIC (this << " Schedule ReTxTimeout at time> " <<Simulator::Now ().GetSeconds () << " to expire at time " <<(Simulator::Now () + rto).GetSeconds ());
  sFlow->retxEvent = Simulator::Schedule(rto, &MpTcpSocketBase::ReTxTimeout, this, sFlowIdx);

  // Note the highest ACK and tell app to send more
  DiscardUpTo(sFlowIdx, ack);

  if (GetTxAvailable() > 0)
    { // Notify app about free space available in TxBuffer
      NotifyDataSent(GetTxAvailable()); // NotifySend(GetTxAvailable());
    }
  if (ack > sFlow->TxSeqNumber)
    {
      NS_LOG_WARN("NewAck-> ReceivedAck is bigger than TxSeqNumber => Advance TxSeqNumber from " << sFlow->TxSeqNumber << " To " << ack);
      sFlow->TxSeqNumber = ack; // If advanced
    }

  if (sendingBuffer->Empty() && sFlow->mapDSN.size() == 0 && sFlow->state != FIN_WAIT_1 && sFlow->state != CLOSING)
    { // No retransmit timer if no data to retransmit
      NS_LOG_INFO ("("<< (int)sFlow->routeId << ") NewAck -> Cancelled ReTxTimeout event which was set to expire at " << (Simulator::Now () + Simulator::GetDelayLeft (sFlow->retxEvent)).GetSeconds () << ", DSNmap: " << sFlow->mapDSN.size());
      sFlow->retxEvent.Cancel();
    }

  sFlow->highestAck = std::max(sFlow->highestAck, ack - 1);
  NS_LOG_WARN("NewACK-> sFlow->highestAck: " << sFlow->highestAck);

  currentSublow = sFlow->routeId;
  SendPendingData(sFlow->routeId);
}

void
MpTcpSocketBase::SendEmptyPacket(uint8_t sFlowIdx, uint8_t flags)
{
  NS_LOG_FUNCTION (this << (int)sFlowIdx);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  Ptr<Packet> p = Create<Packet>();

  SequenceNumber32 s = SequenceNumber32(sFlow->TxSeqNumber);

  if (sFlow->m_endPoint == 0)
    {
      NS_FATAL_ERROR("Failed to send empty packet due to null subflow's endpoint");
      NS_LOG_WARN ("Failed to send empty packet due to null subflow's endpoint");
      return;
    }
  if (flags & TcpHeader::FIN)
    {
      //flags |= TcpHeader::ACK;
      if (sFlow->maxSeqNb != sFlow->TxSeqNumber - 1 && client)
        s = sFlow->maxSeqNb + 1;
    }
  else if (m_state == FIN_WAIT_1 || m_state == LAST_ACK || m_state == CLOSING)
    {
      ++s;
    }

  TcpHeader header;
  uint8_t hlen = 0;
  uint8_t olen = 0;

  header.SetSourcePort(sFlow->sPort);
  header.SetDestinationPort(sFlow->dPort);
  header.SetFlags(flags);
  header.SetSequenceNumber(s);
  header.SetAckNumber(SequenceNumber32(sFlow->RxSeqNumber));
  header.SetWindowSize(AdvertisedWindowSize());

  bool hasSyn = flags & TcpHeader::SYN;
  bool hasFin = flags & TcpHeader::FIN;
  bool isAck = flags == TcpHeader::ACK;

  Time RTO = sFlow->rtt->RetransmitTimeout();
  if (hasSyn)
    {
      if (sFlow->cnCount == 0)
        { // No more connection retries, give up
          NS_LOG_INFO ("Connection failed.");
          CloseAndNotify(sFlow->routeId);
          return;
        }
      else
        { // Exponential backoff of connection time out
          int backoffCount = 0x1 << (sFlow->cnRetries - sFlow->cnCount);
          RTO = Seconds(sFlow->cnTimeout.GetSeconds() * backoffCount);
          sFlow->cnCount = sFlow->cnCount - 1;
          NS_LOG_UNCOND("("<< (int)sFlow->routeId<< ") SendEmptyPacket -> backoffCount: " << backoffCount << " RTO: " << RTO.GetSeconds() << " cnTimeout: " << sFlow->cnTimeout.GetSeconds() <<" cnCount: "<< sFlow->cnCount);
        }
    }
  if (((sFlow->state == SYN_SENT) || (sFlow->state == SYN_RCVD && mpEnabled == true)) && mpSendState == MP_NONE)
    {
      mpSendState = MP_MPC;                  // This state means MP_MPC is sent
      localToken = rand() % 1000 + 1;        // Random Local Token
      header.AddOptMPC(OPT_MPC, localToken); // Adding MP_CAPABLE & Token to TCP option (5 Bytes)
      olen += 5;
      m_mptcp->m_TokenMap[localToken] = m_endPoint;       //m_mptcp->m_TokenMap.insert(std::make_pair(localToken, m_endPoint))
      NS_LOG_INFO("("<< (int)sFlow->routeId<< ") SendEmptyPacket -> LOCALTOKEN is mapped to connection endpoint -> " << localToken << " -> " << m_endPoint << " TokenMapsSize: "<< m_mptcp->m_TokenMap.size());
    }
  else if (sFlow->state == SYN_SENT && hasSyn && sFlow->routeId == 0)
    {
      header.AddOptMPC(OPT_MPC, localToken);       // Adding MP_CAPABLE & Token to TCP option (5 Bytes)
      olen += 5;
    }
  else if (sFlow->state == SYN_SENT && hasSyn && sFlow->routeId != 0)
    {
      header.AddOptJOIN(OPT_JOIN, remoteToken, 0); // addID should be zero?
      olen += 6;
    }

  uint8_t plen = (4 - (olen % 4)) % 4;
  olen = (olen + plen) / 4;
  hlen = 5 + olen;
  header.SetLength(hlen);
  header.SetOptionsLength(olen);
  header.SetPaddingLength(plen);

  m_mptcp->SendPacket(p, header, sFlow->sAddr, sFlow->dAddr, FindOutputNetDevice(sFlow->sAddr));
  //sFlow->rtt->SentSeq (sFlow->TxSeqNumber, 1);           // notify the RTT

  if (sFlow->retxEvent.IsExpired() && (hasFin || hasSyn) && !isAck)
    { // Retransmit SYN / SYN+ACK / FIN / FIN+ACK to guard against lost
//RTO = sFlow->rtt->RetransmitTimeout();
      sFlow->retxEvent = Simulator::Schedule(RTO, &MpTcpSocketBase::SendEmptyPacket, this, sFlowIdx, flags);
      NS_LOG_INFO ("("<<(int)sFlowIdx <<") SendEmptyPacket -> ReTxTimer set for FIN / FIN+ACK / SYN / SYN+ACK now " << Simulator::Now ().GetSeconds () << " Expire at " << (Simulator::Now () + RTO).GetSeconds () << " RTO: " << RTO.GetSeconds());
    }

  //if (!isAck)
  NS_LOG_INFO("("<< (int)sFlowIdx<<") SendEmptyPacket-> "<< header <<" Length: "<< (int)header.GetLength());
}

void
MpTcpSocketBase::allocateSendingBuffer(uint32_t size)
{
  NS_LOG_FUNCTION(this << size);
  sendingBuffer = new DataBuffer(size);
}

void
MpTcpSocketBase::allocateRecvingBuffer(uint32_t size)
{
  NS_LOG_FUNCTION(this << size);
  recvingBuffer = new DataBuffer(size);
}
//
//void
//MpTcpSocketBase::SetunOrdBufMaxSize(uint32_t size)
//{
//  NS_LOG_FUNCTION_NOARGS();
//  //unOrdMaxSize = size;
//}

void
MpTcpSocketBase::SetSndBufSize(uint32_t size)
{
  //m_txBuffer.SetMaxBufferSize(size);
  sendingBuffer = new DataBuffer(size);
}
uint32_t
MpTcpSocketBase::GetSndBufSize(void) const
{
  //return m_txBuffer.MaxBufferSize();
  return 0;
}
void
MpTcpSocketBase::SetRcvBufSize(uint32_t size)
{
  //m_rxBuffer.SetMaxBufferSize(size);
  recvingBuffer = new DataBuffer(size);
}
uint32_t
MpTcpSocketBase::GetRcvBufSize(void) const
{
  //return m_rxBuffer.MaxBufferSize();
  return 0;
}

uint32_t
MpTcpSocketBase::Recv(uint8_t* buf, uint32_t size)
{
  NS_LOG_FUNCTION (this);
  //Null packet means no data to read, and an empty packet indicates EOF
  uint32_t toRead = std::min(recvingBuffer->PendingData(), size);
  return recvingBuffer->Retrieve(buf, toRead);
}

void
MpTcpSocketBase::ForwardUp(Ptr<Packet> p, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface> interface) // ns3.15
{
  NS_LOG_FUNCTION(this<< " SubflowSize["<<subflows.size() << "]");

  Address fromAddress = InetSocketAddress(header.GetSource(), port);
  Address toAddress = InetSocketAddress(header.GetDestination(), m_endPoint->GetLocalPort());

  m_localAddress = header.GetDestination();
  m_remoteAddress = header.GetSource();
  m_remotePort = port;
  if (server)
    NS_LOG_ERROR("PacketSize BEFORE peeling: " << p->GetSize());
  // Peel off TCP header and do validity checking
  TcpHeader mptcpHeader;
  p->RemoveHeader(mptcpHeader);
  if (server)
    NS_LOG_ERROR("PacketSize AFTER peeling: " << p->GetSize() << " Optionsize: " << (int)mptcpHeader.GetOptionsLength() << " Padding:" << (int)mptcpHeader.GetPaddingLength());

  m_localPort = mptcpHeader.GetDestinationPort();
  NS_ASSERT(m_localPort == m_endPoint->GetLocalPort());

  // Listening socket being dealt with here......
  if (subflows.size() == 0 && m_state == LISTEN)
    {
      NS_ASSERT(server && m_state == LISTEN);
      NS_LOG_INFO("Listening socket receives SYN packet, it need to be CLONED... " << mptcpHeader);
      // Update the flow control window
      remoteRecvWnd = (uint32_t) mptcpHeader.GetWindowSize();
      // We need to define another ReadOption with no subflow in it
      if (ReadOptions(p, mptcpHeader) == false)
        return;
      // We need to define another ProcessListen with no subflow in it
      ProcessListen(p, mptcpHeader, fromAddress, toAddress);
      // Reset all variables after cloning is ended to ready for next connection
      mpRecvState = MP_NONE;
      mpEnabled = false;
      remoteToken = 0;
      localToken = 0;
      remoteRecvWnd = 1;
      return;
    }
  // Accepted sockets being dealt with from here.......
  // LookupByAddrs of src and destination.
  uint8_t sFlowIdx = LookupByAddrs(m_localAddress, m_remoteAddress); //m_endPoint->GetPeerAddress());
  NS_ASSERT_MSG((sFlowIdx < maxSubflows), "Subflow number should be smaller than MaxNumOfSubflows");

  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];

  //uint32_t dataLen;   // packet's payload length
  remoteRecvWnd = (uint32_t) mptcpHeader.GetWindowSize(); //update the flow control window

  sFlow->dAddr = m_remoteAddress;
  sFlow->dPort = m_endPoint->GetPeerPort();

  if (mptcpHeader.GetFlags() & TcpHeader::ACK)
    { // This function update subflow's lastMeasureRtt variable.
      EstimateRtt(sFlowIdx, mptcpHeader);
    }

  if (ReadOptions(sFlowIdx, p, mptcpHeader) == false)
    return;

// TCP state machine code in different process functions
// C.f.: tcp_rcv_state_process() in tcp_input.c in Linux kernel
  currentSublow = sFlow->routeId;
  switch (sFlow->state)
    {
  case ESTABLISHED:
    ProcessEstablished(sFlowIdx, p, mptcpHeader);
    break;
  case LISTEN:
    ProcessListen(sFlowIdx, p, mptcpHeader, fromAddress, toAddress);
    break;
  case TIME_WAIT:
// Do nothing
    break;
  case CLOSED:
    NS_LOG_INFO(" ("<< sFlow->routeId << ") " << TcpStateName[sFlow->state] << " -> Send RST");
// Send RST if the incoming packet is not a RST
    if ((mptcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG)) != TcpHeader::RST)
      { // Since sFlow->m_endPoint is not configured yet, we cannot use SendRST here
        TcpHeader h;
        h.SetFlags(TcpHeader::RST);
        h.SetSequenceNumber(SequenceNumber32(sFlow->TxSeqNumber));
        h.SetAckNumber(SequenceNumber32(sFlow->RxSeqNumber));
        h.SetSourcePort(sFlow->sPort);
        h.SetDestinationPort(sFlow->dPort);
        h.SetWindowSize(AdvertisedWindowSize());
        m_mptcp->SendPacket(Create<Packet>(), h, header.GetDestination(), header.GetSource(), FindOutputNetDevice(header.GetDestination()));
      }
    break;
  case SYN_SENT:
    ProcessSynSent(sFlowIdx, p, mptcpHeader);
    break;
  case SYN_RCVD:
    ProcessSynRcvd(sFlowIdx, p, mptcpHeader, fromAddress, toAddress);
    break;
  case FIN_WAIT_1:
  case FIN_WAIT_2:
  case CLOSE_WAIT:
    ProcessWait(sFlowIdx, p, mptcpHeader);
    break;
  case CLOSING:
//ProcessClosing(sFlowIdx, p, mptcpHeader);
    break;
  case LAST_ACK:
    ProcessLastAck(sFlowIdx, p, mptcpHeader);
    break;
  default:
// mute compiler
    break;
    }
}
/*
 * This function is used to initiate new subflow. At the moment when there is a connection via an IP address, then it does not open any new subflow with this address again.
 * For example if you need four subflows, you need to have four IP addresses!
 * Note that SetDestroyCallback(), for each subflow's endpoint, is not setup since MPTCP connection only can be closed when all subflows are closed!
 * We are planning to change this, in line with RFC 6824 in near future!
 */
bool
MpTcpSocketBase::InitiateSubflows()
{
  NS_LOG_FUNCTION_NOARGS(); //
  NS_LOG_DEBUG("----------------------------- InitiateSubflows By Client ---------------------------");

  for (uint32_t i = 0; i < localAddrs.size(); i++)
    for (uint32_t j = i; j < remoteAddrs.size(); j++)
      {
        uint8_t addrID = localAddrs[i]->addrID;
        Ipv4Address local = localAddrs[i]->ipv4Addr;
        Ipv4Address remote = remoteAddrs[j]->ipv4Addr;

        // skip already established flows and if there is no route between a pair
        if (((local == m_localAddress) || (remote == m_remoteAddress)) || (!IsThereRoute(local, remote)))
          {
            NS_LOG_INFO("InitiateSubflows -> Skip subflow which is already established or has not a route (" << local << " -> " << remote<<")");
            continue;
          }NS_LOG_LOGIC ("IsThereRoute() -> Route from src "<< local << " to dst " << remote <<", exist !");

        // Create new subflow
        Ptr<MpTcpSubFlow> sFlow = CreateObject<MpTcpSubFlow>();
        sFlow->routeId = (subflows.size() == 0 ? 0 : subflows[subflows.size() - 1]->routeId + 1);

        // Set up subflow local addrs:port from its endpoint
        sFlow->sAddr = local;
        sFlow->sPort = m_endPoint->GetLocalPort();
        sFlow->dAddr = remote;
        sFlow->dPort = m_remotePort;
        sFlow->MSS = segmentSize;
        sFlow->cwnd = sFlow->MSS;               // We should do this ... since cwnd is 0
        sFlow->state = SYN_SENT;
        sFlow->cnCount = sFlow->cnRetries;
        sFlow->m_endPoint = m_mptcp->Allocate(sFlow->sAddr, sFlow->sPort, sFlow->dAddr, sFlow->dPort); // Insert New Subflow to the list
        if (sFlow->m_endPoint == 0)
          return -1;
        sFlow->m_endPoint->SetRxCallback(MakeCallback(&MpTcpSocketBase::ForwardUp, Ptr<MpTcpSocketBase>(this)));
        subflows.insert(subflows.end(), sFlow);

        // Create packet and add MP_JOIN option to it.
        Ptr<Packet> pkt = Create<Packet>();
        TcpHeader header;
        header.SetFlags(TcpHeader::SYN);
        header.SetSequenceNumber(SequenceNumber32(sFlow->TxSeqNumber));
        header.SetAckNumber(SequenceNumber32(sFlow->RxSeqNumber));
        header.SetSourcePort(sFlow->sPort);
        header.SetDestinationPort(sFlow->dPort);
        header.SetWindowSize(AdvertisedWindowSize());
        header.AddOptJOIN(OPT_JOIN, remoteToken, addrID);
        uint8_t olen = 6;
        uint8_t plen = (4 - (olen % 4)) % 4;
        olen = (olen + plen) / 4;
        uint8_t hlen = 5 + olen;
        header.SetLength(hlen);
        header.SetOptionsLength(olen);
        header.SetPaddingLength(plen);
        NS_LOG_ERROR("InitiateSubflow-> hLen: " << (int) hlen);

        // Send packet lower down the networking stack
        m_mptcp->SendPacket(pkt, header, local, remote, FindOutputNetDevice(local));
        NS_LOG_INFO("InitiateSubflows -> (" << local << " -> " << remote << ") | "<< header);
      }
  return true;
}

void
MpTcpSocketBase::calculateTotalCWND()
{
  totalCwnd = 0;
  for (uint32_t i = 0; i < subflows.size(); i++)
    {
      if (subflows[i]->m_inFastRec)
        totalCwnd += subflows[i]->ssthresh;
      else
        totalCwnd += subflows[i]->cwnd.Get();          // Should be this all the time
    }
}

void
MpTcpSocketBase::ReadUnOrderedData()
{
  NS_LOG_FUNCTION (this);NS_LOG_WARN("ReadUnOrderedData()-> Size: " << unOrdered.size());
  list<DSNMapping *>::iterator current = unOrdered.begin();
  list<DSNMapping *>::iterator next = unOrdered.begin();

  // I changed this method, now whenever a segment is readed it get dropped from that list
  while (next != unOrdered.end())
    {
      ++next;
      DSNMapping *ptrDSN = *current;
      uint32_t sFlowIdx = ptrDSN->subflowIndex;
      Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
      if ((ptrDSN->dataSeqNumber <= nextRxSequence) /*&& (ptrDSN->subflowSeqNumber == sFlow->RxSeqNumber)*/)
        {
          NS_ASSERT(ptrDSN->dataSeqNumber == nextRxSequence);
          uint32_t amount = recvingBuffer->Add(ptrDSN->packet, ptrDSN->dataLevelLength);

          if (amount == 0)
            {
              NS_ASSERT(3!=3);
              break; // reception buffer is full
            }
          NS_ASSERT(amount == ptrDSN->dataLevelLength);

          nextRxSequence += amount;

          /**
           * Send an acumulative acknowledge
           */
          if (ptrDSN->subflowSeqNumber == sFlow->RxSeqNumber)
            {
              NS_LOG_WARN("ReadUnOrderedData-> SubflowSeqNumber: " << ptrDSN->subflowSeqNumber);
              sFlow->RxSeqNumber += amount;
              sFlow->highestAck = std::max(sFlow->highestAck, ptrDSN->acknowledgement - 1);
              //SendEmptyPacket(sFlowIdx, TcpHeader::ACK);
            }
          else
            NS_ASSERT(ptrDSN->subflowSeqNumber < sFlow->RxSeqNumber);

          NotifyDataRecv();
          unOrdered.erase(current);
//          delete ptrDSN;
        }
      else if (ptrDSN->subflowSeqNumber == sFlow->RxSeqNumber)
        {
          NS_LOG_WARN("ReadUnOrderedData-> SubflowSeqNumber: " << ptrDSN->subflowSeqNumber);
          sFlow->RxSeqNumber += ptrDSN->dataLevelLength;
          sFlow->highestAck = std::max(sFlow->highestAck, ptrDSN->acknowledgement - 1);
        }
      current = next;
    }
}

uint8_t
MpTcpSocketBase::ProcessOption(TcpOptions * opt)
{
  uint8_t originalSFlow = 255;
  if (opt != 0)
    {

    }
  return originalSFlow;
}

/*
 * When dupAckCount reach to the default value of 3 then TCP goes to ack recovery process.
 */
void
MpTcpSocketBase::DupAck(uint8_t sFlowIdx, DSNMapping* ptrDSN)
{
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  sFlow->m_dupAckCount++;
  ptrDSN->dupAckCount++; // Used for evaluation purposes only
  uint32_t cwnd = sFlow->cwnd.Get();
  uint32_t segmentSize = sFlow->MSS;
  calculateTotalCWND();

  // Plotting
  uint32_t tmp = (((ptrDSN->subflowSeqNumber) - sFlow->initialSequnceNumber) / sFlow->MSS) % mod;
  sFlow->DUPACK.push_back(make_pair(Simulator::Now().GetSeconds(), tmp));

  // Congestion control algorithms
  if (sFlow->m_dupAckCount == 3 && !sFlow->m_inFastRec)
    { // FastRetrasmsion
      NS_LOG_WARN (Simulator::Now().GetSeconds() <<" DupAck -> Subflow ("<< (int)sFlowIdx <<") 3rd duplicated ACK for segment ("<<ptrDSN->subflowSeqNumber<<")");

      // Cut the window to the half
      ReduceCWND(sFlowIdx, ptrDSN);

      // Plotting
      sFlow->_FReTx.push_back(make_pair(Simulator::Now().GetSeconds(), TimeScale));
    }
  else if (sFlow->m_inFastRec)
    { // Fast Recovery
      // Increase cwnd for every additional DupACK (RFC2582, sec.3 bullet #3)
      sFlow->cwnd += segmentSize;

      // Plotting
      DupAcks.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd));
      sFlow->ssthreshtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->ssthresh));
      NS_LOG_WARN ("DupAck-> FastRecovery. Increase cwnd by one MSS, from " << cwnd <<" -> " << sFlow->cwnd << " AvailableWindow: " << AvailableWindow(sFlowIdx));

      // Send more data into pipe if possible to get ACK clock going
      SendPendingData(sFlow->routeId);
    }
  else
    {
      NS_LOG_WARN("Limited transmit is not enabled... DupAcks: " << ptrDSN->dupAckCount);
    }
//  else if (!sFlow->m_inFastRec && sFlow->m_limitedTx && sendingBuffer->PendingData() > 0)
//    { // RFC3042 Limited transmit: Send a new packet for each duplicated ACK before fast retransmit
//      NS_LOG_INFO ("Limited transmit");
//      uint32_t sz = SendDataPacket(sFlowIdx, sFlow->MSS, false); // WithAck or Without ACK?
//      NotifyDataSent(sz);
//    };
}

std::string
MpTcpSocketBase::PrintCC(uint32_t cc)
{
  switch (cc)
    {
  case 0:
    return "Uncoupled"; //0
    break;
  case 1:
    return "Linked_Increases"; //1
    break;
  case 2:
    return "Semi-Coupled"; //2
    break;
  case 3:
    return "Fully_Coupled"; //3
    break;
  default:
    return "Unknown";
    break;
    }
}

std::string
MpTcpSocketBase::GeneratePlotDetail(void)
{

  std::stringstream detail;
  detail << "CC:" << PrintCC(AlgoCC) << "  sF:" << subflows.size() << " C:" << LinkCapacity / 1000 << "Kbps  RTT:" << RTT << "Ms  D:"
      << totalBytes / 1000 << "Kb  dtQ(" << lostRate << ")  MSS:" << segmentSize << "B";
  return detail.str();
}

void
MpTcpSocketBase::GeneratePktCount()
{
  std::ofstream outfile("pktCount.plt");
  Gnuplot pktCountGraph = Gnuplot("pktCount.png", GeneratePlotDetail());

  pktCountGraph.SetLegend("Subflows", "Packets");
  pktCountGraph.SetTerminal("png");
  pktCountGraph.SetExtra("set xrange [0:4]");

  for (uint16_t idx = 0; idx < subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[idx];

      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::LINES_POINTS);

      std::stringstream title;
      title << " Subflow " << idx;

      dataSet.SetTitle(title.str());
      dataSet.Add(idx, sFlow->PktCount);
      pktCountGraph.AddDataset(dataSet);
      NS_LOG_UNCOND(" Subflow(" << idx << ") Number of Sent Packets : " << sFlow->PktCount);
    }
  pktCountGraph.GenerateOutput(outfile);
  outfile.close();
}

void
MpTcpSocketBase::GenerateSendvsACK()
{
  std::ofstream outfile("pkt.plt");

  Gnuplot rttGraph = Gnuplot("pkt.png", GeneratePlotDetail());
  std::stringstream tmp;
  tmp << " Packet Number (Modulo " << mod << " )";
  rttGraph.SetLegend("Time (s)", tmp.str());
  rttGraph.SetTerminal("png");
//  rttGraph.SetExtra("set xrange [0.0:5.0]");

  std::stringstream t;
  t << "set yrange [" << TimeScale - 2.0 << ":" << mod + 2 << "]";
  rttGraph.SetExtra(t.str());

  //DATA
  for (uint16_t idx = 0; idx < subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[idx];

      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::POINTS);

      std::stringstream title;
      title << "Data";

      dataSet.SetTitle(title.str());

      vector<pair<double, uint32_t> >::iterator it = sFlow->DATA.begin();

      while (it != sFlow->DATA.end())
        {
          dataSet.Add(it->first, it->second);
          it++;
        }
      rttGraph.AddDataset(dataSet);
    }
  // ACK
  for (uint16_t idx = 0; idx < subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[idx];

      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::POINTS);

      std::stringstream title;
      title << "Ack";

      dataSet.SetTitle(title.str());

      vector<pair<double, uint32_t> >::iterator it = sFlow->ACK.begin();

      while (it != sFlow->ACK.end())
        {
          dataSet.Add(it->first, it->second);
          it++;
        }
      rttGraph.AddDataset(dataSet);
    }

  // DROP
  for (uint16_t idx = 0; idx < subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[idx];

      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::POINTS);

      std::stringstream title;
      title << "Drop";

      dataSet.SetTitle(title.str());

      vector<pair<double, uint32_t> >::iterator it = sFlow->DROP.begin();

      while (it != sFlow->DROP.end())
        {
          dataSet.Add(it->first, it->second);
          it++;
        }
      if (sFlow->DROP.size() > 0)
        rttGraph.AddDataset(dataSet);
    }

//  // RETRANSMIT
  for (uint16_t idx = 0; idx < subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[idx];

      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::POINTS);

      std::stringstream title;
      title << "ReTx";

      dataSet.SetTitle(title.str());

      vector<pair<double, uint32_t> >::iterator it = sFlow->RETRANSMIT.begin();

      while (it != sFlow->RETRANSMIT.end())
        {
          dataSet.Add(it->first, it->second);
          it++;
        }
      if (sFlow->RETRANSMIT.size() > 0)
        rttGraph.AddDataset(dataSet);
    }

  // SlowStart
  for (uint16_t idx = 0; idx < subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[idx];

      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::LINES);

      std::stringstream title;
      title << "SS";

      dataSet.SetTitle(title.str());

      vector<pair<double, double> >::iterator it = sFlow->_ss.begin();

      while (it != sFlow->_ss.end())
        {
          dataSet.Add(it->first, it->second);
          it++;
        }
      if (sFlow->_ss.size() > 0)
        rttGraph.AddDataset(dataSet);
    }

  // Congestion Avoidance
  for (uint16_t idx = 0; idx < subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[idx];

      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::LINES);

      std::stringstream title;
      title << "CA";

      dataSet.SetTitle(title.str());

      vector<pair<double, double> >::iterator it = sFlow->_ca.begin();

      while (it != sFlow->_ca.end())
        {
          dataSet.Add(it->first, it->second);
          it++;
        }
      if (sFlow->_ca.size() > 0)
        rttGraph.AddDataset(dataSet);
    }

  // Fast Recovery - FullACK
  for (uint16_t idx = 0; idx < subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[idx];

      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::LINES_POINTS);

      std::stringstream title;
      title << "FAck";

      dataSet.SetTitle(title.str());

      vector<pair<double, double> >::iterator it = sFlow->_FR_FA.begin();

      while (it != sFlow->_FR_FA.end())
        {
          dataSet.Add(it->first, it->second);
          it++;
        }
      if (sFlow->_FR_FA.size())
        rttGraph.AddDataset(dataSet);
    }

  // Fast Recovery - PartialACK
  for (uint16_t idx = 0; idx < subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[idx];

      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::LINES_POINTS);

      std::stringstream title;
      title << "PAck";

      dataSet.SetTitle(title.str());

      vector<pair<double, double> >::iterator it = sFlow->_FR_PA.begin();

      while (it != sFlow->_FR_PA.end())
        {
          dataSet.Add(it->first, it->second);
          it++;
        }
      if (sFlow->_FR_PA.size() > 0)
        rttGraph.AddDataset(dataSet);
    }
  // Fast Retransmission
  for (uint16_t idx = 0; idx < subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[idx];

      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::LINES_POINTS);

      std::stringstream title;
      title << "FReTx";

      dataSet.SetTitle(title.str());

      vector<pair<double, double> >::iterator it = sFlow->_FReTx.begin();

      while (it != sFlow->_FReTx.end())
        {
          dataSet.Add(it->first, it->second);
          it++;
        }
      if (sFlow->_FReTx.size() > 0)
        rttGraph.AddDataset(dataSet);
    }
  // TimeOut
  for (uint16_t idx = 0; idx < subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[idx];

      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::LINES_POINTS);

      std::stringstream title;
      title << "TO";

      dataSet.SetTitle(title.str());

      vector<pair<double, double> >::iterator it = sFlow->_TimeOut.begin();

      while (it != sFlow->_TimeOut.end())
        {
          dataSet.Add(it->first, it->second);
          it++;
        }
      if (sFlow->_TimeOut.size() > 0)
        rttGraph.AddDataset(dataSet);
    }
  rttGraph.GenerateOutput(outfile);
  outfile.close();
}

// RTT VS Time
void
MpTcpSocketBase::GenerateRTT()
{
  std::ofstream outfile("rtt.plt");

  //Gnuplot rttGraph = Gnuplot("rtt.png", GeneratePlotDetail());
  Gnuplot rttGraph;
  rttGraph.SetTitle(GeneratePlotDetail());
  rttGraph.SetLegend("Time (s)", " Time (ms) ");
  //rttGraph.SetTerminal("png");      //postscript eps color enh \"Times-BoldItalic\"");
  rttGraph.SetExtra("set yrange [0:400]");

  // RTT
  for (uint16_t idx = 0; idx < subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[idx];

      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::LINES_POINTS);

      std::stringstream title;
      title << "RTT " << idx;

      dataSet.SetTitle(title.str());

      vector<pair<double, double> >::iterator it = sFlow->_RTT.begin();

      while (it != sFlow->_RTT.end())
        {
          dataSet.Add(it->first, it->second);
          it++;
        }
      rttGraph.AddDataset(dataSet);
    }
  // RTO
  for (uint16_t idx = 0; idx < subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[idx];

      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::LINES_POINTS);

      std::stringstream title;
      title << "RTO " << idx;

      dataSet.SetTitle(title.str());

      vector<pair<double, double> >::iterator it = sFlow->_RTO.begin();

      while (it != sFlow->_RTO.end())
        {
          dataSet.Add(it->first, it->second);
          it++;
        }
      rttGraph.AddDataset(dataSet);
    }

  //TxQueue
  for (uint16_t idx = 0; idx < subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[idx];

      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::LINES_POINTS);

      std::stringstream title;
      title << "TxQueue " << idx;

      dataSet.SetTitle(title.str());

      vector<pair<double, double> >::iterator it = TxQueue.begin();

      while (it != TxQueue.end())
        {
          dataSet.Add(it->first, it->second);
          it++;
        }
      rttGraph.AddDataset(dataSet);
    }

  gnu.AddPlot(rttGraph);
  rttGraph.GenerateOutput(outfile);
  outfile.close();
}
void
MpTcpSocketBase::GenerateCwndTracer()
{
  //std::ofstream outfile("cwnd.plt");

  //Gnuplot cwndGraph = Gnuplot("cwnd.png", GeneratePlotDetail());
  Gnuplot cwndTracerGraph;
  cwndTracerGraph.SetTitle("Cwnd vs Time"); //GeneratePlotDetail()
  cwndTracerGraph.SetLegend("Time (s)", "CWND");
  //cwndGraph.SetTerminal("png");      //postscript eps color enh \"Times-BoldItalic\"");
  //cwndGraph.SetExtra("set xrange [1.0:5.0]");
  //cwndGraph.SetExtra("set yrange [-10.0:200]");

  // cwnd
  for (uint16_t idx = 0; idx < subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[idx];
      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::POINTS);
      std::stringstream title;
      title << "sFlow " << idx;
      dataSet.SetTitle(title.str());
      vector<pair<double, uint32_t> >::iterator it = sFlow->cwndTracer.begin();
      while (it != sFlow->cwndTracer.end())
        {
          dataSet.Add(it->first, it->second / sFlow->MSS);
          it++;
        }
      if (sFlow->cwndTracer.size() > 0)
        cwndTracerGraph.AddDataset(dataSet);
    }
  // ssthreshold
  for (uint16_t idx = 0; idx < subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[idx];
      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::LINES);
      std::stringstream title;
      title << "ssth " << idx;
      dataSet.SetTitle(title.str());
      vector<pair<double, double> >::iterator it = sFlow->ssthreshtrack.begin();
      while (it != sFlow->ssthreshtrack.end())
        {
          dataSet.Add(it->first, it->second / sFlow->MSS);
          it++;
        }
      if (sFlow->ssthreshtrack.size() > 0)
        cwndTracerGraph.AddDataset(dataSet);
    }
  gnu.AddPlot(cwndTracerGraph);
  //cwndTracerGraph.GenerateOutput(outfile);
  //outfile.close();
}

void
MpTcpSocketBase::GenerateCWNDPlot()
{
  NS_LOG_FUNCTION_NOARGS();

  std::ofstream outfile("cwnd.plt");

  Gnuplot cwndGraph = Gnuplot("cwnd.png", GeneratePlotDetail());
  //Gnuplot cwndGraph;
  //cwndGraph.SetTitle(GeneratePlotDetail());
  cwndGraph.SetLegend("Time (s)", "CWND");
  cwndGraph.SetTerminal("png");      //postscript eps color enh \"Times-BoldItalic\"");
  //cwndGraph.SetExtra("set xrange [1.0:5.0]");
  cwndGraph.SetExtra("set yrange [0:200]");
  // cwnd
  NS_LOG_UNCOND("GenerateCWNDPlot -> subflowsSize: " << subflows.size());
  for (uint16_t idx = 0; idx < subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[idx];

      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::POINTS);

      std::stringstream title;
      title << "sFlow " << idx;

      dataSet.SetTitle(title.str());

      vector<pair<double, double> >::iterator it = sFlow->CWNDtrack.begin();

      while (it != sFlow->CWNDtrack.end())
        {
          dataSet.Add(it->first, it->second / sFlow->MSS);
          it++;
        }
      if (sFlow->CWNDtrack.size() > 0)
        cwndGraph.AddDataset(dataSet);
    }

// ssthreshold
  for (uint16_t idx = 0; idx < subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[idx];

      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::LINES);

      std::stringstream title;
      title << "ssth " << idx;

      dataSet.SetTitle(title.str());

      vector<pair<double, double> >::iterator it = sFlow->ssthreshtrack.begin();

      while (it != sFlow->ssthreshtrack.end())
        {
          dataSet.Add(it->first, it->second / sFlow->MSS);
          it++;
        }
      if (sFlow->ssthreshtrack.size() > 0)
        cwndGraph.AddDataset(dataSet);
    }

  // Only if mptcp has one subflow, the following dataset would be added to the plot
//  if (subflows.size() == 1)
//    {
// Fast retransmit Track
    {
      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::POINTS);
      std::stringstream title;
      title << "F-ReTx";
      dataSet.SetTitle(title.str());

      vector<pair<double, double> >::iterator it = reTxTrack.begin();

      while (it != reTxTrack.end())
        {
          dataSet.Add(it->first, it->second / segmentSize);
          it++;
        }
      if (reTxTrack.size() > 0)
        if (reTxTrack.size() > 0)
          cwndGraph.AddDataset(dataSet);
    }

  // TimeOut Track
    {
      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::POINTS);
      std::stringstream title;
      title << "TOut";
      dataSet.SetTitle(title.str());

      vector<pair<double, double> >::iterator it = timeOutTrack.begin();

      while (it != timeOutTrack.end())
        {
          dataSet.Add(it->first, it->second / segmentSize);
          it++;
        }
      if (timeOutTrack.size() > 0)
        cwndGraph.AddDataset(dataSet);
    }

  // PartialAck
    {
      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::POINTS);
      std::stringstream title;
      title << "PAck";
      dataSet.SetTitle(title.str());

      vector<pair<double, double> >::iterator it = PartialAck.begin();

      while (it != PartialAck.end())
        {
          dataSet.Add(it->first, it->second / segmentSize);
          it++;
        }
      if (PartialAck.size() > 0)
        cwndGraph.AddDataset(dataSet);
    }

  // Full Ack
    {
      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::POINTS);
      std::stringstream title;
      title << "FAck";
      dataSet.SetTitle(title.str());

      vector<pair<double, double> >::iterator it = FullAck.begin();

      while (it != FullAck.end())
        {
          dataSet.Add(it->first, it->second / segmentSize);
          it++;
        }
      if (FullAck.size() > 0)
        cwndGraph.AddDataset(dataSet);
    }

  // DupAck
    {
      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::DOTS);
      std::stringstream title;
      title << "DupAck";
      dataSet.SetTitle(title.str());

      vector<pair<double, double> >::iterator it = DupAcks.begin();
      while (it != DupAcks.end())
        {
          dataSet.Add(it->first, it->second / segmentSize);
          it++;
        }
      if (DupAcks.size() > 0)
        cwndGraph.AddDataset(dataSet);
    }

  // PacketDrop
//   {
//   Gnuplot2dDataset dataSet;
//   dataSet.SetStyle(Gnuplot2dDataset::POINTS);
//   std::stringstream title;
//   title << "PacketDrop";
//   dataSet.SetTitle(title.str());
//
//   vector<pair<double, double> >::iterator it = PacketDrop.begin();
//
//   while (it != PacketDrop.end())
//   {
//   dataSet.Add(it->first, it->second / segmentSize);
//   it++;
//   }
//   cwndGraph.AddDataset(dataSet);
//   }
//    }
//gnu.AddPlot(cwndGraph);
  cwndGraph.GenerateOutput(outfile);
  outfile.close();
}

bool
MpTcpSocketBase::StoreUnOrderedData(DSNMapping *ptr1)
{
  NS_LOG_FUNCTION (this);
  /**
   * return the statement depending on successfully inserting or not the data
   * if unOrdered buffer can't hold the out of sequence data and currently received
   */
  bool inserted = false;
  for (list<DSNMapping *>::iterator it = unOrdered.begin(); it != unOrdered.end(); ++it)
    {
      DSNMapping *ptr2 = *it;
      if (ptr1->dataSeqNumber == ptr2->dataSeqNumber)
        {
          NS_LOG_WARN ("Data Sequence ("<< ptr1->dataSeqNumber <<") ALREADY STORED in unOrdered buffer !");
          return false;
        }
      else if (ptr1->dataSeqNumber < ptr2->dataSeqNumber)
        {
          NS_LOG_WARN ("Data Sequence ("<< ptr1->dataSeqNumber <<" with subFlowSeqNb: )" << ptr1->subflowSeqNumber << " HAS stored in unOrdered buffer SUCCESSFULLY!");
          unOrdered.insert(it, ptr1);
          inserted = true;
          break;
        }
    }
  if (!inserted)
    {
      NS_LOG_WARN ("StoreUnOrderedData -> DataSeqNb: " << ptr1->dataSeqNumber << " with subflowSeqNb: " << ptr1->subflowSeqNumber << " has stored at the end of list");
      unOrdered.insert(unOrdered.end(), ptr1);
    }

  return true;
}

/** Peer sent me a FIN. Remember its sequence in rx buffer. */
void
MpTcpSocketBase::PeerClose(uint8_t sFlowIdx, Ptr<Packet> p, const TcpHeader& mptcpHeader)
{
  NS_LOG_FUNCTION (this << mptcpHeader);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];

  // Ignore all out of range packets
  if (mptcpHeader.GetSequenceNumber() < SequenceNumber32(sFlow->RxSeqNumber)
      || (sFlow->m_gotFin && mptcpHeader.GetSequenceNumber() < sFlow->m_finSeq))
    {
      // Note: If FIN already received then its seqNb would not be remember again!
      NS_LOG_INFO("RxSeqNumber:" << sFlow->RxSeqNumber << " ReceivedSeq:" << mptcpHeader.GetSequenceNumber() .GetValue());NS_LOG_INFO("PeerClose() -> Out of range packet, ignore it " << (mptcpHeader.GetSequenceNumber().GetValue() < sFlow->RxSeqNumber) << " OR " << (mptcpHeader.GetSequenceNumber() < sFlow->m_finSeq));
      NS_FATAL_ERROR("Out of range packets received! This might occurs when FIN/ACK get lost ... Don't Panic!");
      return;
    }

  // For any case, remember the FIN position in rx buffer first
  sFlow->SetFinSequence(mptcpHeader.GetSequenceNumber() + SequenceNumber32(p->GetSize()));
  NS_LOG_INFO ("(" << (int)sFlow->routeId<< ") Accepted FIN at seq " << mptcpHeader.GetSequenceNumber () + SequenceNumber32 (p->GetSize ()) << ", PktSize: " << p->GetSize() << " {PeerClose}"); //
  NS_LOG_INFO ("(" << (int)sFlow->routeId<< ") RxSeqNumber: " << sFlow->RxSeqNumber<< " {PeerClose}");

  if (p->GetSize())
    {
      NS_LOG_INFO("(" << (int)sFlowIdx<< ") FIN received with data piggyback, pkt's SeqNb: " << mptcpHeader.GetSequenceNumber () << " pktSize: " << p->GetSize());
      ReceivedData(sFlowIdx, p, mptcpHeader);
    }

  // Return if FIN is out of sequence, otherwise move to CLOSE_WAIT state by DoPeerClose
  if (!sFlow->Finished())
    {
      NS_LOG_INFO("(" << (int)sFlowIdx << ") Return since FIN is out of sequence, its seqNb: " << sFlow->m_finSeq.GetValue() << " RxSeqNb: " << sFlow->RxSeqNumber);
      return;
    }

  // Simultaneous close: Application invoked Close() when we are processing this FIN packet
  if (sFlow->state == FIN_WAIT_1)
    {  // This is not expecting this to happens... as our implementation is not bidirectional.
      NS_LOG_INFO ("("<< (int) sFlow->routeId << ") FIN_WAIT_1 -> CLOSING {Simultaneous close}");
      sFlow->state = CLOSING;
      NS_FATAL_ERROR("Simultaneous close... it's not expected...");
      return;
    }

  DoPeerClose(sFlowIdx); // Change state, respond with ACK
}

/** Received a in-sequence FIN. Close down this socket. */
void
MpTcpSocketBase::DoPeerClose(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION((int)sFlowIdx);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  NS_ASSERT(sFlow->state == ESTABLISHED || sFlow->state == SYN_RCVD);
  /*
   * Receiver gets in-sequence FIN packet from sender.
   * It sends ACK for it and also send its own FIN at the same time since our implementation is unidirectional
   * i.e., receiver is not suppose to send data packet to sender and its sendingBuffer is uninitialized!
   */
  // Move the state of subflow to CLOSE_WAIT
  NS_LOG_INFO ("(" << (int) sFlow->routeId << ") "<< TcpStateName[sFlow->state] << " -> CLOSE_WAIT {DoPeerClose}");
  sFlow->state = CLOSE_WAIT;
  Close(sFlowIdx); // This would cause simultaneous close since receiver also want to close when she got FIN.

  if (sFlow->state == LAST_ACK)
    {
      NS_LOG_LOGIC ("MpTcpSocketBase " << this << " scheduling LATO1");
      sFlow->m_lastAckEvent = Simulator::Schedule(sFlow->rtt->RetransmitTimeout(), &MpTcpSocketBase::LastAckTimeout, this, sFlowIdx);
    }

  /*
   if (!m_closeNotified)
   {
   // The normal behaviour for an application is that, when the peer sent a in-sequence
   // FIN, the app should prepare to close. The app has two choices at this point: either
   // respond with ShutdownSend() call to declare that it has nothing more to send and
   // the socket can be closed immediately; or remember the peer's close request, wait
   // until all its existing data are pushed into the TCP socket, then call Close()
   // explicitly.
   NS_LOG_LOGIC ("TCP " << this << " calling NotifyNormalClose");
   NotifyNormalClose();
   m_closeNotified = true;
   }
   //
   if (m_shutdownSend)
   { // The application declares that it would not sent any more, close this socket
   Close();
   }
   else
   { // Need to ack, the application will close later
   SendEmptyPacket(TcpHeader::ACK);
   }
   */
}

void
MpTcpSocketBase::LastAckTimeout(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION (this);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  sFlow->m_lastAckEvent.Cancel();
  if (sFlow->state == LAST_ACK)
    {
      NS_LOG_INFO("(" << (int) sFlow->routeId << ") LAST_ACK -> CLOSED {LastAckTimeout}");
      CloseAndNotify(sFlowIdx);
    }
//  if (!m_closeNotified)
//    {
//      m_closeNotified = true;
//    }
}

bool
MpTcpSocketBase::FindPacketFromUnOrdered(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION((int)sFlowIdx);
  bool reValue = false;
  list<DSNMapping *>::iterator current = unOrdered.begin();
  while (current != unOrdered.end())
    {
      DSNMapping* ptrDSN = *current;
      if (ptrDSN->subflowIndex == sFlowIdx)
        {
          reValue = true;
          NS_LOG_LOGIC("(" << (int)sFlowIdx << ") FindPacketFromUnOrdered -> SeqNb" << ptrDSN->subflowSeqNumber << " pSize: " << ptrDSN->dataLevelLength);
          break;
        }
      current++;
    }
  return reValue;
}

/** This function closes the endpoint completely. Called upon RST_TX action. */
void
MpTcpSocketBase::SendRST(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION (this << (int) sFlowIdx); //
  NS_LOG_INFO("SendRST -> " << this << " ("<< (int) sFlowIdx << ")");
  SendEmptyPacket(sFlowIdx, TcpHeader::RST);
  //NotifyErrorClose();
  DeallocateEndPoint(sFlowIdx);
}

void
MpTcpSocketBase::CloseAndNotify(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION (this << (int) sFlowIdx);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
//  if (!m_closeNotified)
//    {
//      NotifyNormalClose();
//    }
  if (sFlow->state != TIME_WAIT)
    {
      NS_LOG_INFO("("<< (int)sFlowIdx << ") CloseAndNotify -> DeallocateEndPoint()");
      DeallocateEndPoint(sFlowIdx);
    }NS_LOG_INFO("("<< (int)sFlowIdx << ") CloseAndNotify -> CancelAllTimers() and change the state");
  //m_closeNotified = true;
  CancelAllTimers(sFlowIdx);
  NS_LOG_INFO ("("<< (int)sFlowIdx << ") "<< TcpStateName[sFlow->state] << " -> CLOSED {CloseAndNotify}");
  sFlow->state = CLOSED;
  CloseMultipathConnection();
}

/** Inherit from Socket class: Kill this socket and signal the peer (if any) */
int
MpTcpSocketBase::Close(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION (this << (int)sFlowIdx);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];

  //  if (client)
//      NS_LOG_INFO("Close(" <<(int) sFlowIdx << ")" << ", PendingData: " << sendingBuffer->PendingData() << ", mapDSN.size: " << sFlow->mapDSN.size());

// First we check to see if there is any unread rx data
// Bug number 426 claims we should send reset in this case.
  if (server && unOrdered.size() > 0 && FindPacketFromUnOrdered(sFlowIdx) && !sFlow->Finished()) /* && recvingBuffer->PendingData() != 0 */
    {  // I don't expect this to happens in normal scenarios!
      NS_FATAL_ERROR("Receiver called close() when there are some unread packets in its buffer");
      SendRST(sFlowIdx);
      CloseAndNotify(sFlowIdx);
      NS_LOG_WARN("unOrderedBuffer: " << unOrdered.size() << " currentSubflow: " << sFlow->routeId);
      return 0;
    }

  if (client && sendingBuffer->PendingData() > 0) //if (m_txBuffer.SizeFromSequence(m_nextTxSequence) > 0)
    { // App close with pending data must wait until all data transmitted
//      if (m_closeOnEmpty == false)
//        {
//          m_closeOnEmpty = true;
//          NS_LOG_INFO("-----------------------CLOSE is issued by sender application-----------------------");NS_LOG_INFO ("Socket " << this << " deferring close, Connection state " << TcpStateName[m_state] << " PendingData: " << sendingBuffer->PendingData());
//        }
      return 0;
    }
//  else if (client && sendingBuffer->PendingData() == 0 && sFlow->maxSeqNb != sFlow->TxSeqNumber -1)
//    return 0;

  if (client)
    NS_ASSERT(sendingBuffer->Empty());
  if (server)
    NS_ASSERT_MSG(sFlow->Finished(),
        " state: " << TcpStateName[sFlow->state] << " GotFin: " << sFlow->m_gotFin << " FinSeq: " << sFlow->m_finSeq << " mapDSN: " << sFlow->mapDSN.size());

  return DoClose(sFlowIdx);
}

/** Do the action to close the socket. Usually send a packet with appropriate
 flags depended on the current m_state. */
int
MpTcpSocketBase::DoClose(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION (this << (int)sFlowIdx << subflows.size());

  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  //NS_LOG_INFO("DoClose -> Socket src/des (" << sFlow->sAddr << ":" << sFlow->sPort << "/" << sFlow->dAddr << ":" << sFlow->dPort << ")" << " state: " << TcpStateName[sFlow->state]);
  switch (sFlow->state)
    {
  case SYN_RCVD:
  case ESTABLISHED:
// send FIN to close the peer
    SendEmptyPacket(sFlowIdx, TcpHeader::FIN);
    NS_LOG_INFO ("("<< (int) sFlow->routeId<< ") ESTABLISHED -> FIN_WAIT_1 {DoClose} FIN is sent as separate pkt");
    sFlow->state = FIN_WAIT_1;
    break;
  case CLOSE_WAIT:
// send FIN+ACK to close the peer (in normal scenario receiver should use this when she got FIN from sender)
    SendEmptyPacket(sFlowIdx, TcpHeader::FIN | TcpHeader::ACK);
    NS_LOG_INFO ("("<< (int) sFlow->routeId<< ") CLOSE_WAIT -> LAST_ACK {DoClose}");
    sFlow->state = LAST_ACK;
    break;
  case SYN_SENT:
  case CLOSING:
// Send RST if application closes in SYN_SENT and CLOSING
    NS_LOG_INFO("DoClose -> Socket src/des (" << sFlow->sAddr << ":" << sFlow->sPort << "/" << sFlow->dAddr << ":" << sFlow->dPort << ")" << " sFlow->state: " << TcpStateName[sFlow->state]);
    SendRST(sFlowIdx);
    CloseAndNotify(sFlowIdx);
    break;
  case LISTEN:
  case LAST_ACK:
// In these three states, move to CLOSED and tear down the end point
    CloseAndNotify(sFlowIdx);
    break;
  case CLOSED:
  case FIN_WAIT_1:
  case FIN_WAIT_2:
  case TIME_WAIT:
  default: /* mute compiler */
//NS_LOG_INFO("DoClose -> DoNotting since subflow's state is " << TcpStateName[sFlow->state] << "(" << sFlow->routeId<< ")");
// Do nothing in these four states
    break;
    }
  return 0;
}

int
MpTcpSocketBase::Close(void)
{
  NS_LOG_FUNCTION(this);
  if (subflows.size() > 0)
    {
        { // This block could be removed...
          if (subflows.size() == 1)
            NS_ASSERT(currentSublow == 0);
          NS_LOG_WARN("Close() -> CurrentSubflow: " << (int)currentSublow);
        } //-------------------------------
      return Close(currentSublow);
    }
  else
    { //CloseMultipathConnection(); this could be used as well...
      NS_LOG_INFO("Close has issued for listening socket, "<< this <<", it's endpoints ->  local/remote (" << m_endPoint->GetLocalAddress() << ":" << m_endPoint->GetLocalPort() << "/" << m_endPoint->GetPeerAddress() << ":" << m_endPoint->GetPeerPort() << ") m_state: " << TcpStateName[m_state] << " -> CLOSED");
      NS_ASSERT(subflows.size() == 0);
      m_state = CLOSED;
      NotifyNormalClose();
      m_endPoint->SetDestroyCallback(MakeNullCallback<void>());
      m_mptcp->DeAllocate(m_endPoint);
      m_endPoint = 0;
      std::vector<Ptr<TcpSocketBase> >::iterator it = std::find(m_mptcp->m_sockets.begin(), m_mptcp->m_sockets.end(), this);
      if (it != m_mptcp->m_sockets.end())
        {
          m_mptcp->m_sockets.erase(it);
        }
      CancelAllSubflowTimers();
    }
  return true;
}

// This function would calls NotifyNormalClose() where in turn calls mpTopology:HandlePeerClose where in turn calls close();
bool
MpTcpSocketBase::CloseMultipathConnection()
{
  NS_LOG_FUNCTION_NOARGS();
  bool closed = false;
  uint32_t cpt = 0;
  for (uint32_t i = 0; i < subflows.size(); i++)
    {
      NS_LOG_LOGIC("Subflow (" << i << ") TxSeqNb (" << subflows[i]->TxSeqNumber << ") RxSeqNb = " << subflows[i]->RxSeqNumber << " highestAck (" << subflows[i]->highestAck << ") maxSeqNb (" << subflows[i]->maxSeqNb << ")");

      if (subflows[i]->state == CLOSED)
        cpt++;
      if (subflows[i]->state == TIME_WAIT)
        {
          NS_LOG_INFO("("<< (int)subflows[i]->routeId<< ") "<< TcpStateName[subflows[i]->state] << " -> CLOSED {CloseMultipathConnection}");
          subflows[i]->state = CLOSED;
          cpt++;
        }
    }
  if (cpt == subflows.size())
    {
      if (m_state == ESTABLISHED && client) // We could remove client ... it should work but it generate plots for receiver as well.
        {
          NS_LOG_INFO("CloseMultipathConnection -> GENERATE PLOTS SUCCESSFULLY -> HoOoOrA  pAck: " << pAck);
          //GenerateRTTPlot();
          GenerateCWNDPlot();
          GenerateSendvsACK();
          GenerateRTT();
          GenerateCwndTracer();
          GeneratePktCount();
          generatePlots();
        }
      if (m_state != CLOSED)
        {
          NS_LOG_INFO("CloseMultipathConnection -> MPTCP connection is closed {" << this << "}, m_state: " << TcpStateName[m_state] << " -> CLOSED" << " CurrentSubflow (" << (int)currentSublow << ") SubflowsSize: " <<subflows.size());
          m_state = CLOSED;
          NotifyNormalClose();
          m_endPoint->SetDestroyCallback(MakeNullCallback<void>()); // Remove callback to destroy()
          m_mptcp->DeAllocate(m_endPoint);                          // Deallocating the endPoint
          if (subflows.size() > 0)
            subflows[0]->m_endPoint = 0;
          m_endPoint = 0;
          std::vector<Ptr<TcpSocketBase> >::iterator it = std::find(m_mptcp->m_sockets.begin(), m_mptcp->m_sockets.end(), this);
          if (it != m_mptcp->m_sockets.end())
            {
              m_mptcp->m_sockets.erase(it);
            }
          CancelAllSubflowTimers();
        }
    }
  return closed;
}

void
MpTcpSocketBase::AdvertiseAvailableAddresses()
{
  NS_LOG_FUNCTION(m_node->GetId());
  if (mpEnabled == true)
    {
      // there is at least one subflow
      Ptr<MpTcpSubFlow> sFlow = subflows[0];
      NS_ASSERT(sFlow!=0);

      // Change the MPTCP send state to MP_ADDR
      mpSendState = MP_ADDR;
      MpTcpAddressInfo * addrInfo;
      Ptr<Packet> pkt = Create<Packet>();

      TcpHeader header;
      header.SetFlags(TcpHeader::ACK);
      header.SetSequenceNumber(SequenceNumber32(sFlow->TxSeqNumber));
      header.SetAckNumber(SequenceNumber32(sFlow->RxSeqNumber));
      header.SetSourcePort(m_localPort); // m_endPoint->GetLocalPort()
      header.SetDestinationPort(m_remotePort);
      uint8_t hlen = 0;
      uint8_t olen = 0;

      // Object from L3 to access to routing protocol, Interfaces and NetDevices and so on.
      Ptr<Ipv4L3Protocol> ipv4 = m_node->GetObject<Ipv4L3Protocol>();
      for (uint32_t i = 0; i < ipv4->GetNInterfaces(); i++)
        {
          //Ptr<NetDevice> device = m_node->GetDevice(i);
          Ptr<Ipv4Interface> interface = ipv4->GetInterface(i);
          Ipv4InterfaceAddress interfaceAddr = interface->GetAddress(0);

          // Skip the loop-back
          if (interfaceAddr.GetLocal() == Ipv4Address::GetLoopback())
            continue;

          addrInfo = new MpTcpAddressInfo();
          addrInfo->addrID = i;
          addrInfo->ipv4Addr = interfaceAddr.GetLocal();
          addrInfo->mask = interfaceAddr.GetMask();
          header.AddOptADDR(OPT_ADDR, addrInfo->addrID, addrInfo->ipv4Addr);
          olen += 6;
          localAddrs.insert(localAddrs.end(), addrInfo);
        }
      uint8_t plen = (4 - (olen % 4)) % 4;
      header.SetWindowSize(AdvertisedWindowSize());
      olen = (olen + plen) / 4;
      hlen = 5 + olen;
      header.SetLength(hlen);
      header.SetOptionsLength(olen);
      header.SetPaddingLength(plen);

      //m_mptcp->SendPacket(pkt, header, m_endPoint->GetLocalAddress(), m_remoteAddress);
      m_mptcp->SendPacket(pkt, header, m_localAddress, m_remoteAddress, FindOutputNetDevice(m_localAddress));
      NS_LOG_INFO("AdvertiseAvailableAddresses-> "<< header);
    }
  else
    {
      NS_FATAL_ERROR("Need to be Looked...");
    }
}

bool
MpTcpSocketBase::IsThereRoute(Ipv4Address src, Ipv4Address dst)
{
  NS_LOG_FUNCTION(this << src << dst);
  bool found = false;
  // Look up the source address
//  Ptr<Ipv4> ipv4 = m_node->GetObject<Ipv4>();
  Ptr<Ipv4L3Protocol> ipv4 = m_node->GetObject<Ipv4L3Protocol>();
  if (ipv4->GetRoutingProtocol() != 0)
    {
      Ipv4Header l3Header;
      Socket::SocketErrno errno_;
      Ptr<Ipv4Route> route;
      //.....................................................................................
      NS_LOG_INFO("----------------------------------------------------");NS_LOG_INFO("IsThereRoute() -> src: " << src << " dst: " << dst);
      // Get interface number from IPv4Address via ns3::Ipv4::GetInterfaceForAddress(Ipv4Address address);
      int32_t interface = ipv4->GetInterfaceForAddress(src);        // Morteza uses sign integers
      Ptr<Ipv4Interface> v4Interface = ipv4->GetRealInterfaceForAddress(src);
      Ptr<NetDevice> v4NetDevice = v4Interface->GetDevice();
      PrintIpv4AddressFromIpv4Interface(v4Interface, interface);
      NS_ASSERT_MSG(interface != -1, "There is no interface object for the the src address");
      // Get NetDevice from Interface via ns3::Ipv4::GetNetDevice(uint32_t interface);
      Ptr<NetDevice> oif = ipv4->GetNetDevice(interface);
      NS_ASSERT(oif == v4NetDevice);

      //.....................................................................................
      l3Header.SetSource(src);
      l3Header.SetDestination(dst);
      route = ipv4->GetRoutingProtocol()->RouteOutput(Ptr<Packet>(), l3Header, oif, errno_);
      if ((route != 0)/* && (src == route->GetSource())*/)
        {
          NS_LOG_INFO ("IsThereRoute -> Route from src "<< src << " to dst " << dst << " oit ["<< oif->GetIfIndex()<<"], exist  Gateway: " << route->GetGateway());
          found = true;
        }
      else
        NS_LOG_INFO ("IsThereRoute -> No Route from srcAddr "<< src << " to dstAddr " << dst << " oit ["<<oif->GetIfIndex()<<"], exist Gateway: " << route->GetGateway());
    }NS_LOG_INFO("----------------------------------------------------");
  return found;
}

void
MpTcpSocketBase::PrintIpv4AddressFromIpv4Interface(Ptr<Ipv4Interface> interface, int32_t indexOfInterface)
{
  NS_LOG_FUNCTION_NOARGS();

  for (uint32_t i = 0; i < interface->GetNAddresses(); i++)
    {

      NS_LOG_INFO("Node(" << interface->GetDevice()->GetNode()->GetId() << ") Interface(" << indexOfInterface << ") Ipv4Index(" << i << ")" << " Ipv4Address(" << interface->GetAddress(i).GetLocal()<< ")");

    }
}

Ptr<NetDevice>
MpTcpSocketBase::FindOutputNetDevice(Ipv4Address src)
{

  NS_LOG_INFO("FindOutputNetDevice");
//  return 0;
  Ptr<Ipv4L3Protocol> ipv4 = m_node->GetObject<Ipv4L3Protocol>();
  uint32_t oInterface = ipv4->GetInterfaceForAddress(src);
  Ptr<NetDevice> oNetDevice = ipv4->GetNetDevice(oInterface);

//  Ptr<Ipv4Interface> interface = ipv4->GetRealInterfaceForAddress(src);
//  Ptr<NetDevice> netDevice = interface->GetDevice();
//  NS_ASSERT(netDevice == oNetDevice);
  //NS_LOG_INFO("FindNetDevice -> Src: " << src << " NIC: " << netDevice->GetAddress());
  //return oNetDevice;
  return 0;
}

bool
MpTcpSocketBase::IsLocalAddress(Ipv4Address addr)
{
  NS_LOG_FUNCTION(this << addr);
  bool found = false;
  MpTcpAddressInfo * pAddrInfo;
  for (uint32_t i = 0; i < localAddrs.size(); i++)
    {
      pAddrInfo = localAddrs[i];
      if (pAddrInfo->ipv4Addr == addr)
        {
          found = true;
          break;
        }
    }
  return found;
}

//void
//MpTcpSocketBase::DetectLocalAddresses()
//{
//  NS_LOG_FUNCTION_NOARGS();
//  MpTcpAddressInfo * addrInfo;
//  Ptr<Ipv4L3Protocol> ipv4 = m_node->GetObject<Ipv4L3Protocol>();
//
//  for (uint32_t i = 0; i < ipv4->GetNInterfaces(); i++)
//    {
//      Ptr<Ipv4Interface> interface = ipv4->GetInterface(i);
//      Ipv4InterfaceAddress interfaceAddr = interface->GetAddress(0);
//      // do not consider loopback addresses
//      if ((interfaceAddr.GetLocal() == Ipv4Address::GetLoopback()) || (IsLocalAddress(interfaceAddr.GetLocal())))
//        continue;
//
//      addrInfo = new MpTcpAddressInfo();
//      addrInfo->addrID = i;
//      addrInfo->ipv4Addr = interfaceAddr.GetLocal();
//      addrInfo->mask = interfaceAddr.GetMask();
//      localAddrs.insert(localAddrs.end(), addrInfo);
//    }
//}

uint32_t
MpTcpSocketBase::BytesInFlight(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION(this);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  return sFlow->maxSeqNb - sFlow->highestAck;        //m_highTxMark - m_highestRxAck;
}

uint16_t
MpTcpSocketBase::AdvertisedWindowSize()
{
  //NS_LOG_FUNCTION_NOARGS();
//  uint16_t window = 0;
  /*
   if( recvingBuffer != 0 )
   window = recvingBuffer->FreeSpaceSize ();
   */
//  window = 65535;
//  return window;
  return (uint16_t) 65535;
}

uint32_t
MpTcpSocketBase::AvailableWindow(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION_NOARGS ();

  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  uint32_t window = std::min(remoteRecvWnd, sFlow->cwnd.Get());
  uint32_t unAcked = (sFlow->TxSeqNumber - (sFlow->highestAck + 1));
  uint32_t freeCWND = (window < unAcked) ? 0 : (window - unAcked);
  if (freeCWND < sFlow->MSS && sendingBuffer->PendingData() >= sFlow->MSS)
    {
      NS_LOG_WARN("AvailableWindow: ("<< (int)sFlowIdx <<") -> " << freeCWND << " => 0" << " MSS: " << sFlow->MSS);
      return 0;
    }
  else
    {
      NS_LOG_WARN("AvailableWindow: ("<< (int)sFlowIdx <<") -> " << freeCWND );
      return freeCWND;
    }
}

uint32_t
MpTcpSocketBase::GetTxAvailable()
{
  NS_LOG_FUNCTION_NOARGS();
  return sendingBuffer->FreeSpaceSize();
}

void
MpTcpSocketBase::SetSourceAddress(Ipv4Address src)
{
  NS_LOG_FUNCTION_NOARGS();
  m_localAddress = src;
  if (m_endPoint != 0)
    {
      m_endPoint->SetLocalAddress(src);
    }
}

Ipv4Address
MpTcpSocketBase::GetSourceAddress()
{
  NS_LOG_FUNCTION_NOARGS();
  return m_localAddress;
}

uint8_t
MpTcpSocketBase::LookupByAddrs(Ipv4Address src, Ipv4Address dst)
{
  NS_LOG_FUNCTION(this);
  Ptr<MpTcpSubFlow> sFlow = 0;
  uint8_t sFlowIdx = maxSubflows;

  if (IsThereRoute(src, dst) == false)
    {
      NS_LOG_INFO("LookupByAddrs -> NO ROUTE between (src,dst) = (" <<src << "," << dst << ")");
      for (uint32_t i = 0; i < subflows.size(); i++)
        {
          NS_LOG_INFO("LookupByAddrs -> (" << i <<") -> src: " << subflows[i]->sAddr << " dst: " << subflows[i]->dAddr);
          NS_FATAL_ERROR(
              this << " There should be an issue with your path configuration; make sure there is a route from your source to destination");
        }
    }

  for (uint8_t i = 0; i < subflows.size(); i++)
    {
      sFlow = subflows[i];
      // on address can only participate to a one subflow, so we can find that subflow by unsing the source address or the destination, but the destination address is the correct one, so use it
      if ((sFlow->sAddr == src && sFlow->dAddr == dst))
        {
          sFlowIdx = i;
          break;
        }
    }
  // When subflow is not find or is not exist...
  if (!(sFlowIdx < maxSubflows))
    {
      NS_LOG_DEBUG("LookupByAddrs -> Either subflow(0) or create new one");
      if (m_connected == false && subflows.size() == 1)
        {
          sFlowIdx = 0;
          NS_FATAL_ERROR("This is not a bug! BUT I don't see any reason to triger this condition currently");
        }
      else
        {
          if (IsLocalAddress(m_localAddress))
            {
              NS_ASSERT(server);
              // Sender would create its new subflow when SYN with MP_JOIN being sent.
              sFlowIdx = subflows.size();
              Ptr<MpTcpSubFlow> sFlow = CreateObject<MpTcpSubFlow>();
              sFlow->routeId = subflows[subflows.size() - 1]->routeId + 1;
              sFlow->dAddr = m_remoteAddress;
              sFlow->dPort = m_remotePort;
              sFlow->sAddr = m_localAddress;
              sFlow->sPort = m_localPort;
              sFlow->MSS = segmentSize;
              sFlow->cwnd = sFlow->MSS;
              sFlow->state = LISTEN;
              sFlow->cnCount = sFlow->cnRetries;
              sFlow->m_endPoint = m_mptcp->Allocate(sFlow->sAddr, sFlow->sPort, sFlow->dAddr, sFlow->dPort);
              if (sFlow->m_endPoint == 0)
                return -1;
              sFlow->m_endPoint->SetRxCallback(MakeCallback(&MpTcpSocketBase::ForwardUp, Ptr<MpTcpSocketBase>(this)));
              //sFlow->m_endPoint->SetDestroyCallback(MakeCallback(&MpTcpSocketBase::Destroy, Ptr<MpTcpSocketBase>(this)));
              subflows.insert(subflows.end(), sFlow);
              NS_LOG_INFO("LookupByAddrs -> Subflow(" << (int) sFlowIdx <<") has created its (src,dst) = (" << sFlow->sAddr << "," << sFlow->dAddr << ")" );
            }
          else
            {
              NS_FATAL_ERROR(
                  "This normally would not occurs since MPTCP connection can have subflow only when two sides advertise their addresses!");
            }
        }
    }NS_LOG_DEBUG("LookupByAddrs -> TotalSubflows{" << subflows.size() <<"} (src,dst) = (" << src << "," << dst << "). Forwarded to (" << (int) sFlowIdx << ")");
  return sFlowIdx;
}

void
MpTcpSocketBase::OpenCWND(uint8_t sFlowIdx, uint32_t ackedBytes)
{
  NS_LOG_FUNCTION(this << (int) sFlowIdx << ackedBytes);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];

  double adder = 0;
  uint32_t cwnd = sFlow->cwnd.Get();
  uint32_t ssthresh = sFlow->ssthresh;

  calculateTotalCWND();
  if (cwnd < ssthresh)
    {
      sFlow->cwnd += sFlow->MSS;

      // Plotting
      sFlow->ssthreshtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->ssthresh));
      sFlow->CWNDtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd));
      totalCWNDtrack.push_back(make_pair(Simulator::Now().GetSeconds(), totalCwnd));
      sFlow->_ss.push_back(make_pair(Simulator::Now().GetSeconds(), TimeScale));
      NS_LOG_WARN ("Congestion Control (Slow Start) increment by one segmentSize");
    }
  else
    {
      switch (AlgoCC)
        {
      case RTT_Compensator:
        calculateAlpha(); // Calculate alpha per drop or RTT...RFC 6356 (Section 4.1)
        adder = std::min(alpha * sFlow->MSS * sFlow->MSS / totalCwnd, static_cast<double>(sFlow->MSS * sFlow->MSS) / cwnd);
        adder = std::max(1.0, adder);
        sFlow->cwnd += static_cast<double>(adder);
        // Plotting
        sFlow->ssthreshtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->ssthresh));
        sFlow->CWNDtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd));
        totalCWNDtrack.push_back(make_pair(Simulator::Now().GetSeconds(), totalCwnd));
        NS_LOG_ERROR ("Congestion Control (RTT_Compensator): alpha "<<alpha<<" ackedBytes (" << ackedBytes << ") totalCwnd ("<< totalCwnd / sFlow->MSS<<" packets) -> increment is "<<adder << " cwnd: " << sFlow->cwnd);
        break;

      case Linked_Increases:
        calculateAlpha();
        adder = alpha * sFlow->MSS * sFlow->MSS / totalCwnd;
        adder = std::max(1.0, adder);
        sFlow->cwnd += static_cast<double>(adder);
        // Plotting
        sFlow->ssthreshtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->ssthresh));
        sFlow->CWNDtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd));
        totalCWNDtrack.push_back(make_pair(Simulator::Now().GetSeconds(), totalCwnd));
        NS_LOG_ERROR ("Subflow "<<(int)sFlowIdx<<" Congestion Control (Linked_Increases): alpha "<<alpha<<" increment is "<<adder<<" ssthresh "<< ssthresh << " cwnd "<<cwnd );
        break;

      case Uncoupled_TCPs:
        adder = static_cast<double>(sFlow->MSS * sFlow->MSS) / cwnd;
        adder = std::max(1.0, adder);
        sFlow->cwnd += static_cast<double>(adder);
        // Plotting
        sFlow->ssthreshtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->ssthresh));
        sFlow->CWNDtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd));
        totalCWNDtrack.push_back(make_pair(Simulator::Now().GetSeconds(), totalCwnd));
        NS_LOG_WARN ("Subflow "<<(int)sFlowIdx<<" Congestion Control (Uncoupled_TCPs) increment is "<<adder<<" ssthresh "<< ssthresh << " cwnd "<<cwnd);
        break;

      case Fully_Coupled:
        adder = static_cast<double>(sFlow->MSS * sFlow->MSS) / totalCwnd;
        adder = std::max(1.0, adder);
        sFlow->cwnd += static_cast<double>(adder);
        // plotting
        sFlow->ssthreshtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->ssthresh));
        sFlow->CWNDtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd));
        totalCWNDtrack.push_back(make_pair(Simulator::Now().GetSeconds(), totalCwnd));
        NS_LOG_ERROR ("Subflow "<<(int)sFlowIdx<<" Congestion Control (Fully_Coupled) increment is "<<adder<<" ssthresh "<< ssthresh << " cwnd "<<cwnd);
        break;

      default:
        NS_ASSERT(3!=3);
        break;
        }
      sFlow->_ca.push_back(make_pair(Simulator::Now().GetSeconds(), TimeScale));
    }
}

void
MpTcpSocketBase::calculateAlpha()
{
  // this method is called whenever a congestion happen in order to regulate the agressivety of subflows
  // alpha = cwnd_total * MAX(cwnd_i / rtt_i^2) / {SUM(cwnd_i / rtt_i))^2}   //RFC 6356 formula (2)

  NS_LOG_FUNCTION_NOARGS ();
  alpha = 0;
  double maxi = 0;
  double sumi = 0;

  for (uint32_t i = 0; i < subflows.size(); i++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[i];

      Time time = sFlow->rtt->GetCurrentEstimate();
      double rtt = time.GetSeconds();
      double tmpi = sFlow->cwnd.Get() / (rtt * rtt);
      if (maxi < tmpi)
        maxi = tmpi;

      sumi += sFlow->cwnd.Get() / rtt;
    }
  alpha = (totalCwnd * maxi) / (sumi * sumi);
}

//void
//MpTcpSocketBase::calculateSmoothedCWND(uint8_t sFlowIdx)
//{
//  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
//  if (sFlow->scwnd < sFlow->MSS)
//    sFlow->scwnd = sFlow->cwnd;
//  else
//    sFlow->scwnd = sFlow->scwnd * 0.875 + sFlow->cwnd * 0.125;
//}

void
MpTcpSocketBase::DestroySubflowMapDSN()
{
  NS_LOG_FUNCTION_NOARGS();
  for (uint32_t i = 0; i < subflows.size(); i++)
    {
      Ptr<MpTcpSubFlow> sFlow = subflows[i];
      for (std::list<DSNMapping *>::iterator i = sFlow->mapDSN.begin(); i != sFlow->mapDSN.end(); i++)
        {
          i = sFlow->mapDSN.erase(i);
        }
      sFlow->mapDSN.clear();
    }
}

void
MpTcpSocketBase::DestroyUnOrdered()
{
  NS_LOG_FUNCTION_NOARGS();
  for (std::list<DSNMapping*>::iterator i = unOrdered.begin(); i != unOrdered.end(); i++)
    {
      i = unOrdered.erase(i);
    }
  unOrdered.clear();
}

/** Kill this socket. This is a callback function configured to m_endpoint in
 SetupCallback(), invoked when the endpoint is destroyed. */
void
MpTcpSocketBase::Destroy(void)
{
  NS_LOG_FUNCTION(this);NS_LOG_INFO("Enter Destroy(" << this << ") m_sockets:  " << m_mptcp->m_sockets.size()<< ")");
  m_endPoint = 0;
  if (m_mptcp != 0)
    {
      std::vector<Ptr<TcpSocketBase> >::iterator it = std::find(m_mptcp->m_sockets.begin(), m_mptcp->m_sockets.end(), this);
      if (it != m_mptcp->m_sockets.end())
        {
          m_mptcp->m_sockets.erase(it);
        }
    }
  CancelAllSubflowTimers();
  NS_LOG_INFO("Leave Destroy(" << this << ") m_sockets:  " << m_mptcp->m_sockets.size()<< ")");
}

/** Deallocate the end point and cancel all the timers */
void
MpTcpSocketBase::DeallocateEndPoint(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION(this << (int) sFlowIdx);
  Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
  // Master subflow would be closed when all other slave's subflows are closed.
  if (sFlowIdx == 0)
    {
      NS_LOG_INFO( "("<< (int)sFlowIdx<< ") DeallocateEndPoint -> Master Subflow want to deallocate its endpoint, call on CloseMultipathConnection()");
      CloseMultipathConnection();
    }
  // Slave's subflows
  else
    {
      if (sFlow->m_endPoint != 0)
        {
          NS_LOG_INFO("Salve subflow ("<< (int)sFlowIdx << ") is deallocated its endpoint");
          sFlow->m_endPoint->SetDestroyCallback(MakeNullCallback<void>());
          m_mptcp->DeAllocate(sFlow->m_endPoint);
          sFlow->m_endPoint = 0;
          CancelAllTimers(sFlowIdx);
        }
    }
}

//Ptr<MpTcpSubFlow>
//MpTcpSocketBase::GetSubflow(uint8_t sFlowIdx)
//{
//  return subflows[sFlowIdx];
//}

void
MpTcpSocketBase::SetCongestionCtrlAlgo(CongestionCtrl_t ccalgo)
{
  AlgoCC = ccalgo;
}

void
MpTcpSocketBase::SetDataDistribAlgo(DataDistribAlgo_t ddalgo)
{
  distribAlgo = ddalgo;
}

//DSNMapping*
//MpTcpSocketBase::getAckedSegment(uint64_t lEdge, uint64_t rEdge)
//{
//  for (uint8_t i = 0; i < subflows.size(); i++)
//    {
//      Ptr<MpTcpSubFlow> sFlow = subflows[i];
//      for (list<DSNMapping *>::iterator it = sFlow->mapDSN.begin(); it != sFlow->mapDSN.end(); ++it)
//        {
//          DSNMapping* dsn = *it;
//          if (dsn->dataSeqNumber == lEdge && dsn->dataSeqNumber + dsn->dataLevelLength == rEdge)
//            {
//              return dsn;
//            }
//        }
//    }
//  return 0;
//}
// ...........................................................................
// Extra Functions for evaluation and plotting pusposes only
// ...........................................................................
void
MpTcpSocketBase::getQueuePkt(Ipv4Address addr)
{
  Ptr<Ipv4L3Protocol> l3Protocol = m_node->GetObject<Ipv4L3Protocol>();
  Ptr<Ipv4Interface> ipv4If = l3Protocol->GetInterface(l3Protocol->GetInterfaceForAddress(addr));
  Ptr<NetDevice> net0 = ipv4If->GetDevice();
  PointerValue ptr;
  net0->GetAttribute("TxQueue", ptr);
  Ptr<Queue> txQueue = ptr.Get<Queue>();
  TxQueue.push_back(make_pair(Simulator::Now().GetSeconds(), txQueue->GetNPackets()));
}

void
MpTcpSocketBase::generatePlots()
{
  std::ofstream outfile("allPlots.plt");
  gnu.GenerateOutput(outfile);
  outfile.close();
}

//double
//MpTcpSocketBase::getPathDelay(uint8_t idxPath)
//{
//  TimeValue delay;
//  Ptr<Ipv4L3Protocol> ipv4 = m_node->GetObject<Ipv4L3Protocol>();
//  // interface 0 is the loopback interface
//  Ptr<Ipv4Interface> interface = ipv4->GetInterface(idxPath + 1);
//  Ipv4InterfaceAddress interfaceAddr = interface->GetAddress(0);
//  // do not consider loopback addresses
//  if (interfaceAddr.GetLocal() == Ipv4Address::GetLoopback())
//    return 0.0;
//  Ptr<NetDevice> netDev = interface->GetDevice();
//  Ptr<Channel> P2Plink = netDev->GetChannel();
//  P2Plink->GetAttribute(string("Delay"), delay);
//  return delay.Get().GetSeconds();
//}

//uint64_t
//MpTcpSocketBase::getPathBandwidth(uint8_t idxPath)
//{
//  StringValue str;
//  Ptr<Ipv4L3Protocol> ipv4 = m_node->GetObject<Ipv4L3Protocol>();
//// interface 0 is the loopback interface
//  Ptr<Ipv4Interface> interface = ipv4->GetInterface(idxPath + 1);
//  Ipv4InterfaceAddress interfaceAddr = interface->GetAddress(0);
//// do not consider loopback addresses
//  if (interfaceAddr.GetLocal() == Ipv4Address::GetLoopback())
//    return 0.0;
//  Ptr<NetDevice> netDev = interface->GetDevice();
//
//  if (netDev->IsPointToPoint() == true)
//    {
//      netDev->GetAttribute(string("DataRate"), str);
//    }
//  else
//    {
//      Ptr<Channel> link = netDev->GetChannel();
//      link->GetAttribute(string("DataRate"), str);
//    }
//
//  DataRate bandwidth(str.Get());
//  return bandwidth.GetBitRate();
//}

//double
//MpTcpSocketBase::getGlobalThroughput()
//{
//  double gThroughput = 0;
//  for (uint32_t i = 0; i < subflows.size(); i++)
//    {
//      Ptr<MpTcpSubFlow> sFlow = subflows[i];
//      gThroughput += (sFlow->cwnd * sFlow->MSS * 8) / ((sFlow->rtt->GetCurrentEstimate()).GetSeconds());
//    }
//  return gThroughput;
//}

//double
//MpTcpSocketBase::getConnectionEfficiency()
//{
//  double gThroughput = 0.0;
//  uint64_t gBandwidth = 0;
//  for (uint32_t i = 0; i < subflows.size(); i++)
//    {
//      Ptr<MpTcpSubFlow> sFlow = subflows[i];
//      gThroughput += (sFlow->cwnd * sFlow->MSS * 8) / ((sFlow->rtt->GetCurrentEstimate()).GetSeconds());
//      gBandwidth += getPathBandwidth(i);
//    }
//  return gThroughput / gBandwidth;
//}


//uint32_t
//MpTcpSocketBase::getL3MTU(Ipv4Address addr)
//{
//  // return the MTU associated to the layer 3
//  Ptr<Ipv4L3Protocol> l3Protocol = m_node->GetObject<Ipv4L3Protocol>();
//  return l3Protocol->GetMtu(l3Protocol->GetInterfaceForAddress(addr)) - 100;
//}

//uint64_t
//MpTcpSocketBase::getBandwidth(Ipv4Address addr)
//{
//  uint64_t bd = 0;
//  StringValue uiv;
//  std::string name = std::string("DataRate");
//  Ptr<Ipv4L3Protocol> l3Protocol = m_node->GetObject<Ipv4L3Protocol>();
//  Ptr<Ipv4Interface> ipv4If = l3Protocol->GetInterface(l3Protocol->GetInterfaceForAddress(addr));
//  Ptr<NetDevice> netDevice = ipv4If->GetDevice();
//  // if the device is a point to point one, then the data rate can be retrived directly from the device
//  // if it's a CSMA one, then you should look at the corresponding channel
//  if (netDevice->IsPointToPoint() == true)
//    {
//      netDevice->GetAttribute(name, (AttributeValue &) uiv);
//      // converting the StringValue to a string, then deleting the 'bps' end
//      std::string str = uiv.SerializeToString(0);
//      std::istringstream iss(str.erase(str.size() - 3));
//      iss >> bd;
//    }
//  return bd;
//}

//void
//MpTcpSocketBase::HeartBeat()
//{
//  counter = 0;
//}

}  //namespace ns3
