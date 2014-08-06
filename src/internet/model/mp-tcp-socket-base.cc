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
#include <map>
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
#include "ns3/mp-tcp-scheduler-round-robin.h"
#include "ns3/mp-tcp-id-manager.h"

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
//      .AddConstructor<MpTcpSocketBase>()
// TODO rehabilitate
//      .AddAttribute("CongestionControl","Congestion control algorithm",
//          EnumValue(Uncoupled_TCPs),
//          MakeEnumAccessor(&MpTcpSocketBase::SetCongestionCtrlAlgo),
//          MakeEnumChecker(Uncoupled_TCPs, "Uncoupled_TCPs",Fully_Coupled, "Fully_Coupled", RTT_Compensator, "RTT_Compensator", Linked_Increases,"Linked_Increases"))
//      .AddAttribute("SchedulingAlgorithm", "Algorithm for data distribution between m_subflows", EnumValue(Round_Robin),
//          MakeEnumAccessor(&MpTcpSocketBase::SetDataDistribAlgo),
//          MakeEnumChecker(Round_Robin, "Round_Robin"))
      .AddAttribute("Subflows", "The list of subflows associated to this protocol.",
          ObjectVectorValue(),
          MakeObjectVectorAccessor(&MpTcpSocketBase::m_subflows),
          MakeObjectVectorChecker<MpTcpSocketBase>());
  return tid;
}



MpTcpSocketBase::MpTcpSocketBase() :
  TcpSocketBase(),
  m_mpEnabled(false)
{
  NS_LOG_FUNCTION(this);
//  NS_ASSERT( m_tcp );

  m_remotePathIdManager = CreateObject<MpTcpPathIdManager>();
//  mpTokenRegister = false;

//  m_totalCwnd = 0;

//  client = false;
  m_server = false;

  // TODO remove
  remoteRecvWnd = 1;
//  m_segmentSize = 0;
//  nextTxSequence = 1;
//  nextRxSequence = 1;
  gnu.SetOutFile("allPlots.pdf");

  mod = 60; // ??
  Callback<void, Ptr<Socket> > vPS = MakeNullCallback<void, Ptr<Socket> >();
  Callback<void, Ptr<Socket>, const Address &> vPSA = MakeNullCallback<void, Ptr<Socket>, const Address &>();
  Callback<void, Ptr<Socket>, uint32_t> vPSUI = MakeNullCallback<void, Ptr<Socket>, uint32_t>();
  SetConnectCallback(vPS, vPS);
  SetDataSentCallback(vPSUI);
  SetSendCallback(vPSUI);
  SetRecvCallback(vPS);

  /* Generate a random key */
  m_localKey = GenerateKey(); // TODO later ? on fork or on SYN_SENT
  m_remoteKey = 0;
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
      NS_ASSERT(m_tcp != 0);
      m_tcp->DeAllocate(m_endPoint);
      NS_ASSERT(m_endPoint == 0);
    }
  m_tcp = 0;
  CancelAllSubflowTimers();
//  NS_LOG_INFO(Simulator::Now().GetSeconds() << " ["<< this << "] ~MpTcpSocketBase ->" << m_tcp << " m_endPoint: " << m_endPoint);
}

uint64_t
MpTcpSocketBase::GetLocalKey() const
{
  return m_localKey;
}

int
MpTcpSocketBase::GetRemoteKey(uint64_t& remoteKey) const
{
  if( IsMpTcpEnabled() )
  {
    remoteKey = m_remoteKey;
    return 0;
  }
  return -ERROR_INVAL;
}


//int
//MpTcpSocketBase::SetLocalToken(uint32_t token) const
//{
//
//}


//void
//MpTcpSocketBase::SetAddAddrCallback(Callback<bool, Ptr<Socket>, Address, uint8_t> addAddrCb)
//{
//  NS_LOG_FUNCTION (this << &addAddrCb);
//
//  m_onAddAddr = addAddrCb;
//}

//MpTcpAddressInfo info
// Address info
void
MpTcpSocketBase::NotifyRemoteAddAddr(Address address)
{

  if (!m_onRemoteAddAddr.IsNull())
  {
    // TODO user should not have to deal with MpTcpAddressInfo , info.second
    m_onRemoteAddAddr (this, address, 0);
  }
}

std::vector<MpTcpSubFlow>::size_type
MpTcpSocketBase::GetNSubflows() const
{
  return m_subflows.size();
}

  //std::vector<MpTcpSubFlow>::size_ uint8
Ptr<MpTcpSubFlow>
MpTcpSocketBase::GetSubflow(uint8_t id)
{
//  NS_ASSERT()
  return m_subflows[id];
}




// TODO GetLocalAddr
uint8_t
MpTcpSocketBase::AddLocalAddr(const Ipv4Address& address)
{
  //TODO should be able to improve AddrId allocation to allow for more choices
  // converts Static into member function ? add a modulo in case we add too many local addr ?
  static uint8_t addrId = 0;
  addrId++;

  // TODO check if it's owned by the node ? or not ?

  std::pair< std::map<Ipv4Address,uint8_t>::iterator , bool > result = m_localAddresses.insert( std::make_pair(address, addrId) );
//  std::map<Ipv4Address,uint8_t>::iterator it = m_localAddresses.find( address );
//  if( ! result.second)
//  {
    return result.first->second;
//  }
//  return
}

bool
MpTcpSocketBase::RemLocalAddr(Ipv4Address address, uint8_t& id)
{
  std::map<Ipv4Address,uint8_t>::iterator it  = m_localAddresses.find(address);
  if(it != m_localAddresses.end() )
  {
    id = it->second;
    return true;
  }
  return false;
}

// Accept an iterator ?
//bool
//MpTcpSocketBase::RemLocalAddr(Ipv4Address address)
//{
////  std::map<Ipv4Address,uint8_t>::iterator  it
//  int res = m_localAddresses.erase( address );
//  return (res != 0);
//}




void
MpTcpSocketBase::EstimateRtt(const TcpHeader& TcpHeader)
{
  NS_LOG_FUNCTION_NOARGS();
}


void
MpTcpSocketBase::SetRemoteKey(uint32_t remoteKey)
{
  NS_ASSERT( m_remoteKey == 0);
  //
  remoteKey = (uint64_t)remoteKey;
  m_mpEnabled = true;
}


// Read options from incoming packets
#if 0
bool
MpTcpSocketBase::ReadOptions(Ptr<Packet> pkt, const TcpHeader& mptcpHeader)
{
  NS_LOG_FUNCTION(this << mptcpHeader);
  // why this ?
//  NS_ASSERT(m_remoteKey == 0 && m_mpEnabled == false);
  vector<TcpOptions*> mp_options = mptcpHeader.GetOptions();
  uint8_t flags = mptcpHeader.GetFlags();
  TcpOptions *opt;
  bool hasSyn = flags & TcpHeader::SYN;
  for (uint32_t j = 0; j < mp_options.size(); j++)
    {
      opt = mp_options[j];
      if ((opt->optName == OPT_MPCAPABLE) && hasSyn
//        && (mpRecvState == MP_NONE)
        )
        { // SYN+ACK would be send later on by ProcessSynRcvd(...)
//          mpRecvState = MP_MPC;
          m_mpEnabled = true;
          m_remoteKey = ((OptMultipathCapable *) opt)->senderToken;
        }
      else
        NS_FATAL_ERROR("Unexpected option has received ... This could be a bug please report it to our GitHub page");
    }
  return true; // This should return true otherwise Forwardup() would retrun too.
}

// Read options from incoming packets
// May be upgraded by SOCIS patch ?
bool
MpTcpSocketBase::ReadOptions(uint8_t sFlowIdx, Ptr<Packet> pkt, const TcpHeader& mptcpHeader)
{
  NS_LOG_FUNCTION(this << (int)sFlowIdx << mptcpHeader);
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
  std::vector<TcpOptions*> options = mptcpHeader.GetOptions();
  uint8_t flags = mptcpHeader.GetFlags();
  TcpOptions *opt;
  bool hasSyn = flags & TcpHeader::SYN;
//  bool TxAddr = false;
  for (uint32_t j = 0; j < options.size(); j++)
    {
      opt = options[j];
      if ((opt->optName == OPT_MPCAPABLE) && hasSyn
//      && (mpRecvState == MP_NONE)
      )
        { // SYN+ACK would be send later on by ProcessSynRcvd(...)
//          mpRecvState = MP_MPC;
          m_mpEnabled = true;
          m_remoteKey = ((OptMultipathCapable *) opt)->senderToken;
//          NS_ASSERT(client);
        }
      else if ((opt->optName == OPT_JOIN) && hasSyn)
        {
          /*
          OptJoinConnection * optJoin = (OptJoinConnection *) opt;
          //

          if (
            (mpSendState == MP_ADDADDR) &&
            (GetLocalKey() == optJoin->receiverToken)
            )
            {
              // SYN+ACK would be send later on by ProcessSynRcvd(...)
              // Join option is sent over the path (couple of addresses) not already in use
            }
          */
        }
      else if (
        (opt->optName == OPT_ADDR)
        //&& (mpRecvState == MP_MPC)
        )
        {
          // Receiver store sender's addresses information and send back its addresses.
          // If there are several addresses to advertise then multiple OPT_ADDR would be attached to the TCP Options.
//          MpTcpAddressInfo * addrInfo = new MpTcpAddressInfo();
          uint8_t addrId = ((OptAddAddress *) opt)->addrID;
//          addrInfo->ipv4Addr = ((OptAddAddress *) opt)->addr;

          //TODO support port
          // Convert en address
          if( m_remotePathIdManager->AddRemoteAddr( addrId, ((OptAddAddress *) opt)->addr, 0 ) )
          {
//            TxAddr = true;
// bool remote //new local
//            NotifyNewRemoteAddAddr( );
          }


        }
      else if (opt->optName == OPT_REMADR)
        { // not implemented yet
          NS_LOG_WARN(this << "ReadOption-> OPT_REMADR is not implemented yet");

          /**
          This is achieved through the Remove Address (REMOVE_ADDR) option
         (Figure 13), which will remove a previously added address (or list of
         addresses) from a connection and terminate any subflows currently
         using that address.

         **/
         // TODO look for subflow matching that addr and remove it
         // Also remove from pathManager
//         m_remote
         m_remotePathIdManager->RemRemoteAddr( ((OptAddAddress *) opt)->addrID );

        }
      else if (opt->optName == OPT_DSN)
        { // not implemented yet
          NS_LOG_LOGIC(this << " ReadOption-> OPT_DSN -> we'll deal with it later on");
        }
    }

  return true;
}
#endif





/** Received a packet upon ESTABLISHED state. This function is mimicking the
 role of tcp_rcv_established() in tcp_input.c in Linux kernel. */
 #if 0
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
//      NS_LOG_INFO("No action for received SYN+ACK (duplicated packet ?)")
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
#endif
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
      NS_LOG_LOGIC("Received TCP flags " << tcpflags << " while listening");
      return;
    }

  // Call socket's notify function to let the server app know we got a SYN
  // If the server app refuses the connection, do nothing
  if (!NotifyConnectionRequest(fromAddress))
    {
      NS_LOG_ERROR("Server refuse the incoming connection!");
      return;
    }

  // Clone the socket, simulate fork
  Ptr<MpTcpSocketBase> newSock = MpTcpFork();
  NS_LOG_DEBUG ("Clone new MpTcpSocketBase new connection. ListenerSocket " << this << " AcceptedSocket "<< newSock);
  Simulator::ScheduleNow(&MpTcpSocketBase::CompleteFork, newSock, packet, mptcpHeader, fromAddress, toAddress);
}


/**
TODO if without option create a NewReno
**/
void
MpTcpSocketBase::CompleteFork(Ptr<Packet> p, const TcpHeader& mptcpHeader, const Address& fromAddress, const Address& toAddress)
{
  NS_LOG_FUNCTION(this);
  m_server = true;

  // Get port and address from peer (connecting host)
  if (InetSocketAddress::IsMatchingType(toAddress))
    {
      m_endPoint = m_tcp->Allocate(InetSocketAddress::ConvertFrom(toAddress).GetIpv4(), InetSocketAddress::ConvertFrom(toAddress).GetPort(),
          InetSocketAddress::ConvertFrom(fromAddress).GetIpv4(), InetSocketAddress::ConvertFrom(fromAddress).GetPort());
    }
  NS_ASSERT(InetSocketAddress::ConvertFrom(toAddress).GetIpv4() == m_endPoint->GetLocalAddress());
  NS_ASSERT(InetSocketAddress::ConvertFrom(toAddress).GetPort() == m_endPoint->GetLocalPort());
  NS_ASSERT(InetSocketAddress::ConvertFrom(fromAddress).GetIpv4() == m_endPoint->GetPeerAddress());
  NS_ASSERT(InetSocketAddress::ConvertFrom(fromAddress).GetPort() == m_endPoint->GetPeerPort());

  // We only setup destroy callback for MPTCP connection's endPoints, not on subflows endpoints.
  SetupCallback();

  // TODO isn't there a fct in m_tcp ?
  m_tcp->m_sockets.push_back(this);

  // Create new master subflow (master subsock) and assign its endpoint to the connection endpoint
  //InetSocketAddress( m_endPoint->GetLocalAddress() , )
  Ptr<MpTcpSubFlow> sFlow = CreateSubflow( fromAddress );
  sFlow->m_state = SYN_RCVD;
  sFlow->m_cnCount = sFlow->m_cnRetries;
  sFlow->m_endPoint = m_endPoint; // This is master subsock, its endpoint is the same as connection endpoint.
  sFlow->SetSegSize(m_segmentSize);

  // TODO should be able to set RemoteKey

  NS_LOG_INFO ("("<< (int)sFlow->m_routeId<<") LISTEN -> SYN_RCVD");

  m_subflows.push_back( sFlow );
  //Set the subflow sequence number and send SYN+ACK
  sFlow->m_rxBuffer.SetNextRxSequence( mptcpHeader.GetSequenceNumber() + SequenceNumber32(1) );

  sFlow->SendEmptyPacket( TcpHeader::SYN | TcpHeader::ACK);

  // Update currentSubflow in case close just after 3WHS.
//  NS_LOG_UNCOND("CompleteFork -> receivingBufferSize: " << m_recvingBuffer->bufMaxSize);
  NS_LOG_INFO(this << "  MPTCP connection is initiated (Receiver): "
    );
}

/** Received a packet upon LISTEN state. */
#if 0
void
MpTcpSocketBase::ProcessListen(uint8_t sFlowIdx, Ptr<Packet> packet, const TcpHeader& mptcpHeader, const Address& fromAddress,
    const Address& toAddress)
{
  NS_LOG_FUNCTION (GetNode()->GetId() << mptcpHeader);
  uint8_t tcpflags = mptcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG);
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
  /*
   * Here the SYN is only flag that is expected to receives in normal operation.
   * But, it might also be possible to get SYN with data piggyback when MPTCP has already an ESTABLISHED master subflow.
   */
  if (tcpflags == TcpHeader::SYN)
    { // Receiver got new SYN...Sends SYN+ACK.
      // This is a valid condition when receiver got SYN with MP_JOIN from sender and create new subflow with LISTEN state.
      NS_LOG_INFO(" (" << sFlow->m_routeId << ") " << TcpStateName[sFlow->m_state] << " -> SYN_RCVD");
      sFlow->m_state = SYN_RCVD;
      sFlow->RxSeqNumber = (mptcpHeader.GetSequenceNumber()).GetValue() + 1;
      NS_ASSERT(sFlow->highestAck == mptcpHeader.GetAckNumber().GetValue());
      SendEmptyPacket(sFlowIdx, TcpHeader::SYN | TcpHeader::ACK);
    }
  else if (tcpflags == TcpHeader::ACK)
    {
      // Would ignore packet & replace log level by LOGIC ?
      NS_FATAL_ERROR("Subflow state is LISTEN, how come it receives ACK flag...");
    }

  if (tcpflags == 0 && m_subflows.size() > 1)
    {// Slave subflows can receive SYN flag piggyback data packet.
      ReceivedData(sFlowIdx, packet, mptcpHeader);
    }
}
#endif

 // Schedule-friendly wrapper for Socket::NotifyConnectionSucceeded()

void
MpTcpSocketBase::ConnectionSucceeded(void)
{
  // Wrapper to protected function NotifyConnectionSucceeded() so that it can
  // be called as a scheduled event
//  NotifyConnectionSucceeded();
  //NotifyNewConnectionCreated();
  // The if-block below was moved from ProcessSynSent() to here because we need
  // to invoke the NotifySend() only after NotifyConnectionSucceeded() to
  // reflect the behaviour in the real world.
//  if (GetTxAvailable() > 0)
//    {
//      NotifySend(GetTxAvailable());
//    }

}

/** Received a packet upon SYN_SENT */
#if 0
void
MpTcpSocketBase::ProcessSynSent(uint8_t sFlowIdx, Ptr<Packet> packet, const TcpHeader& mptcpHeader)
{
  NS_LOG_FUNCTION (this << mptcpHeader);
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];

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
      NS_LOG_WARN("---------------------- HandShake is Completed in ClientSide ----------------------"
              << m_subflows.size());
      if (!m_connected)
        { // Only excute for initial subflow since when it has established then MPTCP connection is already established!!
          m_connected = true;
          m_endPoint->SetPeer(m_remoteAddress, m_remotePort);

        }

      NS_LOG_INFO("(" << sFlow->m_routeId << ") "<< TcpStateName[sFlow->state] << " -> ESTABLISHED");
      sFlow->state = ESTABLISHED;
      sFlow->retxEvent.Cancel();
      sFlow->StartTracing("cWindow");
      sFlow->rtt->Init(mptcpHeader.GetAckNumber());
      sFlow->initialSequnceNumber = (mptcpHeader.GetAckNumber().GetValue());
      NS_LOG_INFO("(" <<sFlow->m_routeId << ") InitialSeqNb of data packet should be --->>> " << sFlow->initialSequnceNumber);
      sFlow->RxSeqNumber = (mptcpHeader.GetSequenceNumber()).GetValue() + 1;
      sFlow->highestAck = std::max(sFlow->highestAck, mptcpHeader.GetAckNumber().GetValue() - 1);
      sFlow->TxSeqNumber = mptcpHeader.GetAckNumber().GetValue();
      sFlow->maxSeqNb = sFlow->TxSeqNumber - 1;

      Time estimate;
      estimate = Seconds(1.5);
      sFlow->rtt->SetCurrentEstimate(estimate);

      SendEmptyPacket(sFlowIdx, TcpHeader::ACK);

      // Advertise available addresses...
//      if (m_addrAdvertised == false)
//        {
//          NS_LOG_WARN("---------------------- AdvertiseAvailableAddresses By Client ---------------------");
//          AdvertiseAvailableAddresses();
//          m_addrAdvertised = true;
//        }
      if (m_state != ESTABLISHED)
        {
          m_state = ESTABLISHED;
          //NotifyConnectionSucceeded();
        }NS_LOG_UNCOND("ProcessSynSent -> SubflowsSize: " << m_subflows.size());
    }
  else
    { // Other in-sequence input
      NS_ASSERT(3 != 3);
    }
}
#endif

#if 0
/** Received a packet upon SYN_RCVD */
void
MpTcpSocketBase::ProcessSynRcvd(uint8_t sFlowIdx, Ptr<Packet> packet, const TcpHeader& mptcpHeader, const Address& fromAddress,
    const Address& toAddress)
{
  NS_LOG_FUNCTION (this << mptcpHeader);
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
  uint8_t tcpflags = mptcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG);

  if ((tcpflags == TcpHeader::ACK))
    { // handshake is completed nicely in the receiver.
      NS_LOG_INFO (" ("<< sFlow->m_routeId << ") " << TcpStateName[sFlow->state]<<" -> ESTABLISHED");
      sFlow->state = ESTABLISHED; // Subflow state is ESTABLISHED
      m_state = ESTABLISHED;      // NEED TO CONSIDER IT AGAIN....
      sFlow->m_connected = true;    // This means subflow is established
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
          Simulator::ScheduleNow(&MpTcpSocketBase::ConnectionSucceeded, this);

        }NS_LOG_DEBUG ("---------------------- HandShake is Completed in ServerSide ----------------------" << m_subflows.size());
    }
  else if (tcpflags == TcpHeader::SYN)
    { // SYN/ACK sent might be lost, send SYN/ACK again.
      NS_LOG_INFO ("("<< sFlow->m_routeId << ") " << "SYN_RCVD -> SYN_RCVD");
      sFlow->RxSeqNumber = (mptcpHeader.GetSequenceNumber()).GetValue() + 1;
      SendEmptyPacket(sFlowIdx, TcpHeader::SYN | TcpHeader::ACK);
    }
  else if (tcpflags == (TcpHeader::FIN | TcpHeader::ACK))
    {
    }
}
#endif

#if 0
/** Received a packet upon CLOSE_WAIT, FIN_WAIT_1, or FIN_WAIT_2 states */
void
MpTcpSocketBase::ProcessWait(uint8_t sFlowIdx, Ptr<Packet> packet, const TcpHeader& mptcpHeader)
{
  NS_LOG_FUNCTION (this << sFlowIdx <<packet <<mptcpHeader); //
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
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
      NS_LOG_INFO( "("<<(int) sFlow->m_routeId << ") ProcessWait -> " << mptcpHeader);
      if (tcpflags & TcpHeader::ACK)
        { // Process the ACK first
          NS_LOG_INFO( "("<<(int)sFlow->m_routeId << ") ProcessWait -> ReceviedAck() sFlow->state: " << TcpStateName[sFlow->state]);
          ReceivedAck(sFlowIdx, packet, mptcpHeader);
        }
      sFlow->SetFinSequence(mptcpHeader.GetSequenceNumber());
      NS_LOG_INFO ("("<<(int)sFlow->m_routeId<<") Accepted FIN at seq " << mptcpHeader.GetSequenceNumber () + SequenceNumber32 (packet->GetSize ()) << ", PktSize: " << packet->GetSize() << " {ProcessWait}");
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
  if ((sFlow->m_state  == FIN_WAIT_1 || sFlow->m_state  == FIN_WAIT_2) && sFlow->Finished())
    {
      if (sFlow->m_state  == FIN_WAIT_1)
        {
          NS_LOG_INFO ("("<< (int) sFlowIdx <<") FIN_WAIT_1 -> CLOSING {ProcessWait}");
          sFlow->m_state = CLOSING;
          if (m_sendingBuffer->Empty() && sFlow->m_mapDSN.size() == 0 && mptcpHeader.GetAckNumber().GetValue() == sFlow->highestAck + 1)
            {// This ACK corresponds to the FIN sent
              TimeWait(sFlowIdx);
            }
        }
      else if (sFlow->m_state  == FIN_WAIT_2)
        {
          TimeWait(sFlowIdx);
        }
      SendEmptyPacket(sFlowIdx, TcpHeader::ACK);
    }
}
#endif

#if 0
/** Move TCP to Time_Wait state and schedule a transition to Closed state */
void
MpTcpSocketBase::TimeWait(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION((int) sFlowIdx);
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
  NS_LOG_INFO ("("<< (int) sFlow->m_routeId << ") "<<TcpStateName[sFlow->m_state ] << " -> TIME_WAIT {TimeWait}");
  sFlow->m_state  = TIME_WAIT;
  CancelAllTimers(sFlowIdx);

  // Move from TIME_WAIT to CLOSED after 2*MSL. Max segment lifetime is 2 min according to RFC793, p.28
  sFlow->m_timewaitEvent = Simulator::Schedule(Seconds(2 * 120), &MpTcpSocketBase::CloseMultipathConnection, this);
}
#endif



void
MpTcpSocketBase::CancelAllSubflowTimers(void)
{
  NS_LOG_FUNCTION_NOARGS();

  // TODO use iterator
  for (uint32_t i = 0; i < m_subflows.size(); i++)
    {
      Ptr<MpTcpSubFlow> sFlow = m_subflows[i];
      if (sFlow->m_state != CLOSED)
        {
          sFlow->CancelAllTimers();
          NS_LOG_INFO("CancelAllSubflowTimers() -> Subflow:" << i);
        }
    }
}

#if 0
void
MpTcpSocketBase::ProcessLastAck(uint8_t sFlowIdx, Ptr<Packet> packet, const TcpHeader& mptcpHeader)
{
  NS_LOG_FUNCTION (this << mptcpHeader);
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
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
          NS_LOG_INFO("("<<(int) sFlow->m_routeId << ") ProcessLastAck -> This ACK corresponds to the FIN sent -> CloseAndNotify (" << (int)sFlowIdx << ")");
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
#endif

// Receipt of new packet, put into Rx buffer
void
MpTcpSocketBase::ReceivedData(Ptr<Packet> p, const TcpHeader& mptcpHeader)
{
  // Just override parent's
  // Does nothing
  #if 0

  NS_LOG_FUNCTION (this << mptcpHeader);
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
  uint32_t expectedSeq = sFlow->RxSeqNumber;
  std::vector<TcpOptions*> options = mptcpHeader.GetOptions();
  TcpOptions* opt;
  bool stored = true;

  for (uint32_t i = 0; i < options.size(); i++)
    {
      opt = options[i];
      if (opt->optName == OPT_DSN)
        {
          OptDataSeqMapping* optDSN = (OptDataSeqMapping*) opt;
          uint64_t dataSeqNumber
          uint16_t dataLevelLength;
          uint32_t subflowSeqNumber  = optDSN->subflowSeqNumber;

          if ( subflowSeqNumber == sFlow->RxSeqNumber)
            {
              if (optDSN->dataSeqNumber == nextRxSequence)
                {
                  NS_LOG_WARN("In-order DataPacket Received! SubflowSeqNb: " << optDSN->subflowSeqNumber);
                  uint32_t amountRead = m_recvingBuffer->ReadPacket(p, optDSN->dataLevelLength);
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
    #endif
}


/** Process the newly received ACK */

void
MpTcpSocketBase::ReceivedAck(Ptr<Packet> packet, const TcpHeader& mptcpHeader)
{
//  NS_LOG_FUNCTION ( sFlowIdx << mptcpHeader);

  #if 0
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
  uint32_t ack = (mptcpHeader.GetAckNumber()).GetValue();

  uint32_t tmp = ((ack - sFlow->initialSequnceNumber) / sFlow->GetSegSize()) % mod;
  sFlow->ACK.push_back(make_pair(Simulator::Now().GetSeconds(), tmp));

  // Stop execution if TCPheader is not ACK at all.
  if (0 == (mptcpHeader.GetFlags() & TcpHeader::ACK))
    { // Ignore if no ACK flag
      NS_ASSERT(3!=3);
    }
  // Received ACK. Compare the ACK number against highest unacked seqno.
  else if (ack <= sFlow->highestAck + 1)
    {
      NS_LOG_LOGIC ("This acknowlegment" << mptcpHeader.GetAckNumber ()
        << "do not ack the latest data in subflow level");
      list<DSNMapping *>::iterator current = sFlow->m_mapDSN.begin();
      list<DSNMapping *>::iterator next = sFlow->m_mapDSN.begin();
      while (current != sFlow->m_mapDSN.end())
        {
          ++next;
          DSNMapping *ptrDSN = *current;
          // All segments before ackSeqNum should be removed from the m_mapDSN list.
          if (ptrDSN->subflowSeqNumber + ptrDSN->dataLevelLength <= ack)
            { // Optional task ...
              //next = sFlow->m_mapDSN.erase(current);
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
    #endif
}


void
MpTcpSocketBase::SetSegSize(uint32_t size)
{
  m_segmentSize = size;
  NS_ABORT_MSG_UNLESS(m_state == CLOSED, "Cannot change segment size dynamically.");
}

uint32_t
MpTcpSocketBase::GetSegSize(void) const
{
  return m_segmentSize;
}

uint32_t
MpTcpSocketBase::SendDataPacket(SequenceNumber32 seq, uint32_t maxSize, bool withAck)
{
  NS_LOG_FUNCTION (this << "Should do nothing" << maxSize << withAck);
  return 0;
}

#if 0
uint32_t
MpTcpSocketBase::SendDataPacket(uint8_t sFlowIdx, uint32_t size, bool withAck)
{
  NS_ASSERT(sFlowIdx < m_subflows.size() );
  NS_LOG_FUNCTION (this << (uint32_t)sFlowIdx << size << withAck);
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
  Ptr<Packet> p = 0;
  DSNMapping * ptrDSN = 0;
  uint32_t packetSize = size;
  bool guard = false;
  /*
   * If timeout happens then TxSeqNumber would be shifted down to the seqNb after highestAck,
   * but maxSeqNb would be still related to maxSeqNb ever sent.
   * Thus we can conclude that when maxSeqNb is bigger than TxSeqNumber -1, we are in timeout has occurred.
   * So we have to send packet from subflowBuffer (m_mapDSN) instead of connection buffer (m_sendingBuffer),
   * In other situations maxSeqNb should be equal to TxSeqNumber -1.
   * Boolean 'guard' become true if timeOut is occurred!!
   */
  if (sFlow->maxSeqNb > sFlow->TxSeqNumber)
    {
      uint32_t cunt = 0;
      for (MappingList::iterator it = sFlow->m_mapDSN.begin(); it != sFlow->m_mapDSN.end(); ++it)
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
  {
    NS_ASSERT_MSG(sFlow->maxSeqNb == sFlow->TxSeqNumber -1, " maxSN: " << sFlow->maxSeqNb << " TxSeqNb-1" << sFlow->TxSeqNumber -1);
  }

  /*
   * If no packet has made yet and maxSeqNb is equal to TxSeqNumber -1,
   * then we can safely create a packet from connection buffer (m_sendingBuffer).
   */
  if (p == 0 && ptrDSN == 0)
    {
      NS_ASSERT(!guard);
      NS_ASSERT(sFlow->maxSeqNb == sFlow->TxSeqNumber -1);
      p = m_sendingBuffer->CreatePacket(size);
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

//  uint32_t remainingData = m_sendingBuffer->PendingData();
//  if (m_closeOnEmpty && (remainingData == 0) && !guard) // add guard temporarily
//    {
//      flags |= TcpHeader::FIN; // Add FIN to the flag
//      if (sFlow->state == ESTABLISHED)
//        { // On active close: I am the first one to send FIN
//          NS_LOG_INFO ("(" << (int)sFlow->m_routeId<< ") ESTABLISHED -> FIN_WAIT_1 {} -> FIN is peggyback to last data Packet! m_mapDSN: " << sFlow->m_mapDSN.size() << ", pSize: " << p->GetSize());
//          sFlow->state = FIN_WAIT_1;
//        }
//      /*
//       * When receiver got FIN from peer (sender) and now its app sent all of its pending data,
//       * so server now can attaches FIN to its last data packet. This condition is not expected to occured now,
//       * but we keep it here for future version our implementation that support bidirection communication.
//       */
//      else if (sFlow->state == CLOSE_WAIT)
//        { // On passive close: Peer sent me FIN already
//          NS_LOG_INFO ("CLOSE_WAIT -> LAST_ACK ()");
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
  header.SetDestinationPort(sFlow->m_dPort);
  header.SetWindowSize(AdvertisedWindowSize());
  if (!guard)
    { // If packet is made from m_sendingBuffer, then we got to add the packet and its info to subflow's m_mapDSN.
      sFlow->AddDSNMapping(sFlowIdx, nextTxSequence, packetSize, sFlow->TxSeqNumber, sFlow->RxSeqNumber, p->Copy());
    }
  if (!guard)
    { // if packet is made from m_sendingBuffer, then we use nextTxSequence to OptDSN
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
      uint32_t tmp = (((sFlow->TxSeqNumber + packetSize) - sFlow->initialSequnceNumber) / sFlow->GetSegSize()) % mod;
      sFlow->DROP.push_back(make_pair(Simulator::Now().GetSeconds(), tmp));
    }
  else
    {
      //Socket::()
      //BindToNetDevice
      Ptr<NetDevice> netDevice = FindOutputNetDevice(sFlow->sAddr);
      m_tcp->SendPacket(p, header, sFlow->sAddr, sFlow->dAddr, sFlow->GetBoundNetDevice() );
      if (!guard)
        sFlow->PktCount++;
      uint32_t tmp = (((sFlow->TxSeqNumber + packetSize) - sFlow->initialSequnceNumber) / sFlow->GetSegSize()) % mod;
      sFlow->DATA.push_back(make_pair(Simulator::Now().GetSeconds(), tmp));
    }NS_LOG_WARN(Simulator::Now().GetSeconds() << " ["<< GetNode()->GetId()<< "] SendDataPacket->  " << header <<" dSize: " << packetSize<< " sFlow: " << sFlow->m_routeId);

  // Do some updates.....
  sFlow->rtt->SentSeq(SequenceNumber32(sFlow->TxSeqNumber), packetSize); // Notify the RTT of a data packet sent
  sFlow->TxSeqNumber += packetSize; // Update subflow's nextSeqNum to send.
  sFlow->maxSeqNb = std::max(sFlow->maxSeqNb, sFlow->TxSeqNumber - 1);
  if (!guard)
    {
      nextTxSequence += packetSize;  // Update connection sequence number
    }

  NS_LOG_INFO( "("<< (int) sFlowIdx<< ") DataPacket -----> "
        << header
//        << "  " << m_localAddress << ":" << m_localPort
//        << "->" << m_remoteAddress << ":" << m_remotePort
        );


  if (guard)
    return 0;
  else
    return packetSize;
}
#endif

// No need to reimplement everything, just use SendDataPacket. Check parent's
#if 0
void
MpTcpSocketBase::DoRetransmit(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION (this);
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];

  // Retransmit SYN packet
  if (sFlow->m_state == SYN_SENT)
    {
//      if (sFlow->m_cnCount > 0)
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
  if (m_sendingBuffer->Empty() && sFlow->m_mapDSN.size() == 0)
    {
      if (sFlow->m_state == FIN_WAIT_1 || sFlow->m_state == CLOSING)
        { // Must have lost FIN, re-send
          NS_LOG_INFO("DoRetransmit -> Resent FIN... TxSeqNumber: " << sFlow->TxSeqNumber);
          SendEmptyPacket(sFlowIdx, TcpHeader::FIN);
        }
      return;
    }

  DSNMapping* ptrDSN = sFlow->GetunAckPkt();
  if (ptrDSN == 0)
    {
      NS_LOG_INFO ("Retransmit -> no Unacked data !! m_mapDSN size is "<< sFlow->m_mapDSN.size()
//        << " max Ack seq n�� "<< sFlow->highestAck << " ("
//        << (int)sFlowIdx<< ")"
        );
      NS_ASSERT(3!=3);
      return;
    }

  NS_ASSERT(ptrDSN->subflowSeqNumber == sFlow->highestAck +1);

  // we retransmit only one lost pkt
  Ptr<Packet> pkt = Create<Packet>(ptrDSN->packet, ptrDSN->dataLevelLength);
  TcpHeader header;
  header.SetSourcePort(sFlow->sPort);
  header.SetDestinationPort(sFlow->m_dPort);
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

  m_tcp->SendPacket(pkt, header, sFlow->sAddr, sFlow->dAddr, FindOutputNetDevice(sFlow->sAddr));

  //reset RTO
  SetReTxTimeout(sFlowIdx);

  uint32_t tmp = (((ptrDSN->subflowSeqNumber + ptrDSN->dataLevelLength) - sFlow->initialSequnceNumber) / sFlow->GetSegSize()) % mod;
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
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];

  // This retransmit segment should be the lost segment.
  NS_ASSERT(ptrDSN->subflowSeqNumber >= sFlow->highestAck +1);

  SetReTxTimeout(sFlowIdx); // reset RTO

  // we retransmit only one lost pkt
  Ptr<Packet> pkt = Create<Packet>(ptrDSN->packet, ptrDSN->dataLevelLength);
  if (pkt == 0)
    NS_ASSERT(3!=3);

  TcpHeader header;
  header.SetSourcePort(sFlow->sPort);
  header.SetDestinationPort(sFlow->m_dPort);
  header.SetFlags(TcpHeader::NONE);  // Change to NONE Flag
  header.SetSequenceNumber(SequenceNumber32(ptrDSN->subflowSeqNumber));
  header.SetAckNumber(SequenceNumber32(sFlow->RxSeqNumber));
  header.SetWindowSize(AdvertisedWindowSize());
  // Make sure info here comes from ptrDSN...
  header.AddOptDSN(OPT_DSN, ptrDSN->dataSeqNumber, ptrDSN->dataLevelLength, ptrDSN->subflowSeqNumber);

  NS_LOG_WARN (Simulator::Now().GetSeconds() <<" RetransmitSegment -> "<< " m_localKey "<< m_localKey <<" Subflow "<<(int) sFlowIdx<<" DataSeq "<< ptrDSN->dataSeqNumber <<" SubflowSeq " << ptrDSN->subflowSeqNumber <<" dataLength " << ptrDSN->dataLevelLength << " packet size " << pkt->GetSize() << " 3DupACK");
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
  m_tcp->SendPacket(pkt, header, sFlow->sAddr, sFlow->dAddr, FindOutputNetDevice(sFlow->sAddr));
  uint32_t tmp = (((ptrDSN->subflowSeqNumber + ptrDSN->dataLevelLength) - sFlow->initialSequnceNumber) / sFlow->GetSegSize()) % mod;
  sFlow->RETRANSMIT.push_back(make_pair(Simulator::Now().GetSeconds(), tmp));

  // Notify RTT
  sFlow->rtt->SentSeq(SequenceNumber32(ptrDSN->subflowSeqNumber), ptrDSN->dataLevelLength);

  // In case of RTO, advance m_nextTxSequence
  sFlow->TxSeqNumber = std::max(sFlow->TxSeqNumber, ptrDSN->subflowSeqNumber + ptrDSN->dataLevelLength);

  // highest sent sequence number should be updated!
  sFlow->maxSeqNb = std::max(sFlow->maxSeqNb, sFlow->TxSeqNumber - 1);

  NS_LOG_INFO("("<<(int) sFlowIdx << ") DoRetransmit -> " << header);
}
#endif

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
  return MpTcpFork();
//  CopyObject<MpTcpSocketBase>(this);
}

/** Cut cwnd and enter fast recovery mode upon triple dupack TODO ?*/
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
      return -1; // TODO return -m_errno ?
    }

  // MPTCP connection state is LISTEN
  m_state = LISTEN;
  return 0;
}


// TODO rename ? CreateAndAdd? Add ? Start ? Initiate
//int
Ptr<MpTcpSubFlow>
MpTcpSocketBase::CreateSubflow(
      const Address& _srcAddr
//      , const Address& dstAddr
      )
{
  InetSocketAddress srcAddr = InetSocketAddress::ConvertFrom(_srcAddr);

//  bool masterSocket = false;
  // TODO ajouter la limite du nb de sous flots ?
  // Checker que ca existe pas déjà ?
  // create subflow
  // TODO convert to ASSERT ? and put *real* checks outside ?
  if( IsConnected() )
  {
    if(!IsMpTcpEnabled())
    {
      NS_LOG_ERROR("Remote host does not seem MPTCP compliant so impossible to create additionnal subflows");
//      return -ERROR_INVAL;
      return 0;
    }
  }
  else if( GetNSubflows() > 0 )
  {
    NS_LOG_ERROR("Already attempting to establish a connection");
//    return -ERROR_INVAL;
    return 0;
  }
  else
  {

  }


  Ptr<MpTcpSubFlow> sFlow = CreateObject<MpTcpSubFlow>(this);
  // TODO find associated device and bind to it
  // find srcAddr
//  sFlow->BindToNetDevice (this->FindOutputNetDevice() )
  //
  if ( sFlow->Bind( srcAddr) != 0) {
    NS_LOG_ERROR("Could not bind to srcAddr" << srcAddr);
    return 0;
  }

//  if(!sFlow->Connect( dstAddr) )
//  {
//    NS_LOG_ERROR("Could not connect subflow");
//    return 0;
//  }


  m_subflows.push_back( sFlow );  //subflows.insert(subflows.end(), sFlow);
  // TODO set id of the Flow
  sFlow->m_routeId = m_subflows.size() - 1;
  // Should not be needed since bind register socket
//  m_tcp->m_sockets.push_back(this); // appelé apres un bind ou dans completeFork
  return sFlow;
}



int
MpTcpSocketBase::DoConnect(void)
{
  NS_LOG_FUNCTION (this);

  // A new connection is allowed only if this socket does not have a connection
  if (m_state == CLOSED || m_state == LISTEN || m_state == SYN_SENT || m_state == LAST_ACK || m_state == CLOSE_WAIT)
    {
      // send a SYN packet and change state into SYN_SENT
      Ptr<MpTcpSubFlow> sFlow = CreateSubflow( m_endPoint->GetLocalAddress() );

      NS_ASSERT(sFlow->Connect( m_endPoint->GetPeerAddress() ) );

//      SendEmptyPacket(TcpHeader::SYN);
//      NS_LOG_INFO (TcpStateName[m_state] << " -> SYN_SENT");
//      m_state = SYN_SENT;
    }
  else if (m_state != TIME_WAIT)
    { // In states SYN_RCVD, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, and CLOSING, an connection
      // exists. We send RST, tear down everything, and close this socket.
      // TODO
//      SendRST();
//      CloseAndNotify();
    }
  return 0;

}

/***
TODO remove, use DoConnect instead
***/
#if 0
int
MpTcpSocketBase::Connect(Ipv4Address servAddr, uint16_t servPort)
{
  NS_LOG_FUNCTION(this << servAddr << servPort);

   // TODO should set the m_endpoint too so that subflow can check if it is master or not





  // allocates subflow

  // TODO en fait il ne devrait pas y avoir de m_routeId
  sFlow->m_routeId = (m_subflows.empty()  ? 0 : m_subflows.back()->m_routeId + 1);
  sFlow->dAddr = servAddr;    // Assigned subflow destination address
  sFlow->m_dPort = servPort;    // Assigned subflow destination port
  m_remoteAddress = servAddr; // MPTCP Connection's remote address
  m_remotePort = servPort;    // MPTCP Connection's remote port


  // Following is a duplicate of parent's connect
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

  // weird compared to parent's way of doing things
  if (m_endPoint->GetLocalAddress() == "0.0.0.0")
    {
      // Find approapriate local address from the routing protocol for this endpoint.
      if (SetupEndpoint() != 0)
        { // Route to destination does not exist.
          return -1;
        }
    }
  else
    {
    // TODO this might be removed
    // Make sure there is an route from source to destination. Source might be set wrongly.
      if ((IsThereRoute(m_endPoint->GetLocalAddress(), servAddr)) == false)
        {
          NS_LOG_INFO("Connect -> There is no route from " << m_endPoint->GetLocalAddress() << " to " << m_endPoint->GetPeerAddress());
          //m_tcp->DeAllocate(m_endPoint); // this would fire up destroy function...
          return -1;
        }
    }

  // Set up subflow local addrs:port from endpoint
  sFlow->sAddr = m_endPoint->GetLocalAddress();
  sFlow->sPort = m_endPoint->GetLocalPort();
  sFlow->MSS = m_segmentSize;
  sFlow->cwnd = sFlow->MSS;
  NS_LOG_INFO("Connect -> SegmentSize: " << sFlow->MSS << " tcpSegmentSize: " << m_segmentSize << " m_segmentSize: " << m_segmentSize) ;//
  NS_LOG_UNCOND("Connect -> SendingBufferSize: " << m_sendingBuffer->bufMaxSize);

  // This is master subsocket (master subflow) then its endpoint is the same as connection endpoint.
  sFlow->m_endPoint = m_endPoint;
  m_subflows.push_back( sFlow );  //subflows.insert(subflows.end(), sFlow);
  m_tcp->m_sockets.push_back(this);

  //sFlow->rtt->Reset();
  sFlow->m_cnCount = sFlow->cnRetries;

//  if (sFlow->state == CLOSED || sFlow->state == LISTEN || sFlow->state == SYN_SENT || sFlow->state == LAST_ACK || sFlow->state == CLOSE_WAIT)
//    { // send a SYN packet and change state into SYN_SENT
  NS_LOG_INFO ("("<< (int)sFlow->m_routeId << ") "<< TcpStateName[sFlow->state] << " -> SYN_SENT");

  m_state = SYN_SENT;
  sFlow->state = SYN_SENT;  // Subflow state should be changed first then SendEmptyPacket...

  SendEmptyPacket(sFlow->m_routeId, TcpHeader::SYN);
  m_currentSublow = sFlow->m_routeId; // update currentSubflow in case close just after 3WHS.
  NS_LOG_INFO(this << "  MPTCP connection is initiated (Sender): " << sFlow->sAddr << ":" << sFlow->sPort << " -> " << sFlow->dAddr << ":" << sFlow->m_dPort << " m_state: " << TcpStateName[m_state]);

  // TODO notify connection succeeded ?
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
#endif

bool
MpTcpSocketBase::IsMpTcpEnabled() const
{
  return m_mpEnabled;
}


bool
MpTcpSocketBase::IsConnected() const
{
  return m_connected;
}



int
MpTcpSocketBase::Connect(const Address &address)
{
  NS_LOG_FUNCTION ( this << address );
  // TODO could be removed and rely on parent's m_endPoint instead

//  InetSocketAddress transport = InetSocketAddress::ConvertFrom(address);
//  m_remoteAddress = ; // MPTCP Connection remoteAddress
//  m_remotePort = ; // MPTCP Connection remotePort
return TcpSocketBase::Connect(address);
//  return Connect(transport.GetIpv4(), transport.GetPort() );
}


/** Inherited from Socket class: Bind socket to an end-point in MpTcpL4Protocol */
int
MpTcpSocketBase::Bind()
{
  NS_LOG_FUNCTION (this);
  m_server = false;
  m_endPoint = m_tcp->Allocate();  // Create endPoint with ephemeralPort.
  if (0 == m_endPoint)
    {
      m_errno = ERROR_ADDRNOTAVAIL;
      return -1;
    }
  //m_tcp->m_sockets.push_back(this); // We don't need it for now
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
//  m_localAddress = m_endPoint->GetLocalAddress();
//  m_localPort = m_endPoint->GetLocalPort();

  return 0;
}

/** Inherit from socket class: Bind socket (with specific address) to an end-point in TcpL4Protocol */
int
MpTcpSocketBase::Bind(const Address &address)
{
  NS_LOG_FUNCTION (this<<address);
  m_server = true;
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
      m_endPoint = m_tcp->Allocate();
    }
  else if (ipv4 == Ipv4Address::GetAny() && port != 0)
    { // Allocate with specific port
      m_endPoint = m_tcp->Allocate(port);
    }
  else if (ipv4 != Ipv4Address::GetAny() && port == 0)
    { // Allocate with specific ipv4 address
      m_endPoint = m_tcp->Allocate(ipv4);
    }
  else if (ipv4 != Ipv4Address::GetAny() && port != 0)
    { // Allocate with specific Ipv4 add:port
      m_endPoint = m_tcp->Allocate(ipv4, port);
    }
  else
  {
    NS_LOG_ERROR("Bind to specific add:port has failed!");
  }

  //m_tcp->m_sockets.push_back(this); // we don't need it for now
  NS_LOG_LOGIC("MpTcpSocketBase:Bind(addr) " << this << " got an endpoint " << m_endPoint << " localAddr " << m_endPoint->GetLocalAddress() << ":" << m_endPoint->GetLocalPort() << " RemoteAddr " << m_endPoint->GetPeerAddress() << ":"<< m_endPoint->GetPeerPort());
  return SetupCallback();
}

bool
MpTcpSocketBase::SendBufferedData()
{
  return SendPendingData();
}

//int
//MpTcpSocketBase::FillBuffer(uint8_t* buf, uint32_t size)
//{
//  NS_LOG_FUNCTION( this << size );
//  return m_sendingBuffer->Add(buf, size);
//}



// CAREFUL, note that here it's SequenceNumber64
void
MpTcpSocketBase::NewAck(SequenceNumber64 const& dataLevelSeq)
{
  //!

}

// TODO call 64bits  version ?
void
MpTcpSocketBase::NewAck(SequenceNumber32 const& seq)
{
  //
  TcpSocketBase::NewAck( seq  );
}

/**
 * Sending data via subflows with available window size. It sends data only to ESTABLISHED subflows.
 * It sends data by calling SendDataPacket() function.
 * Called by functions: SendBufferedData, ReceveidAck, NewAck
 */
bool
MpTcpSocketBase::SendPendingData(bool withAck)
{
  NS_LOG_FUNCTION(this);

//  MappingList mappings;
  //start/size
  typedef std::vector< std::pair<uint8_t, std::pair< SequenceNumber32,uint32_t > > > MappingVector;
  MappingVector mappings;
  mappings.reserve( GetNSubflows() );
  m_scheduler->GenerateMappings(mappings);
//  NS_ASSERT_MSG( mappings.size() == , "Should be as many" )

  // Loop through mappings and send Data
  for(MappingVector::iterator it = mappings.begin(); it != mappings.end(); it++ )
  {
    Ptr<MpTcpSubFlow> sf = GetSubflow(it->first);
//    MpTcpMapping& mapping = it->second
//    Retrieve data  Rename SendMappedData
    SequenceNumber32& dataSeq = it->second.first;
    uint16_t mappingSize = it->second.second;
    sf->SendMapping( m_txBuffer.CopyFromSequence(mappingSize, dataSeq ) , dataSeq  );
  }

  #if 0
  // MATT old code: moved to the scheduler


  // This is a condition when main mptcp m_sendingBuffer is empty but they are some packets in a subflow's buffer
  // and also sub-flow is recovering from time-out.
  // this may be a decision to let to the CC
  if (m_sendingBuffer->Empty())
    {
      Ptr<MpTcpSubFlow> sF = m_subflows[sFlowIdx];
      NS_LOG_WARN("(" << (int) sFlowIdx << ") main SendingBuffer is EMPTY, but SubflowBuffer is: "
          << sF->m_mapDSN.size()
        );
      // Sub-flow state is established, SendingBuffer is empty but subflowBuffer (m_mapDSN) is not empty and sub-flow is recovering from timeOut
      // Note that the algorithm used for detecting whether sub-flow is in timeout need to be studied further.
      if (sF->state == ESTABLISHED && sF->m_mapDSN.size() > 0 && sF->maxSeqNb > sF->TxSeqNumber)
        {
          uint32_t window = std::min(AvailableWindow(sFlowIdx), sF->GetSegSize());
          NS_LOG_ERROR("SendingBuffer Empty!, Sub-flow (" << (int)sFlowIdx << ") AvailableWindow" << window);

          // Send all data packets in subflowBuffer (m_mapDSN) until subflow's available window is full.
          while (window != 0 && window >= sF->GetSegSize())
            { // In case case more than one packet can be sent, if subflow's window allow
              if (SendDataPacket(sF->m_routeId, window, false) == 0)
                return false;
              window = std::min(AvailableWindow(sFlowIdx), sF->GetSegSize());
            }
        }

      else
        { // SendingBuffer & SubflowBuffer are EMPTY!!
          NS_LOG_WARN ("MpTcpSocketBase::SendPendingData: SubflowBuffer is empty");
          return false; // Nothing to re-send!!
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

  // TODO let scheduler generate a mapping then send data according to the mapping

  // Send data as much as possible (it depends on subflows AvailableWindow and data in sending buffer)
  while (!m_sendingBuffer->Empty())
    {
      uint8_t count = 0;
      uint32_t window = 0;
      // Search for a subflow with available windows
      while (count < m_subflows.size())
        {
          count++;
          window = std::min(
                AvailableWindow(m_lastUsedsFlowIdx),
                m_sendingBuffer->PendingData()
                ); // Get available window size

          if (window == 0)
            {  // No more available window in the current subflow, try with another one
              NS_LOG_WARN("SendPendingData-> No window available on (" << (int)m_lastUsedsFlowIdx << ")");
              m_lastUsedsFlowIdx = getSubflowToUse();
            }
          else
            {
              NS_LOG_LOGIC ("MpTcpSocketBase::SendPendingData -> PendingData (" << m_sendingBuffer->PendingData() << ") Available window ("<<AvailableWindow (m_lastUsedsFlowIdx)<<")");
              break;
            }
        }
      // No available window for transmission in all subflows, abort sending
      if (count == m_subflows.size() && window == 0)
        break;

      // Take a pointer to the subflow with available window.
//      sFlow = m_algoCC->Get
      sFlow = m_subflows[m_lastUsedsFlowIdx];

      // By this condition only connection initiator can send data need to be change though!
      if (sFlow->state == ESTABLISHED)
        {
//          m_currentSublow = sFlow->m_routeId;
          uint32_t s = std::min(window, sFlow->GetSegSize());  // Send no more than window
          if (sFlow->maxSeqNb > sFlow->TxSeqNumber && m_sendingBuffer->PendingData() <= sFlow->GetSegSize())
            s = sFlow->GetSegSize();
          uint32_t amountSent = SendDataPacket(sFlow->m_routeId, s, false);
          nOctetsSent += amountSent;  // Count total bytes sent in this loop
        } // end of if statement
      m_lastUsedsFlowIdx = getSubflowToUse();
    } // end of main while loop
  NS_LOG_LOGIC (" -> amount data sent = " << nOctetsSent << "... Notify application.");
  NotifyDataSent(GetTxAvailable());
  return (nOctetsSent > 0);
  #endif

  return true;
}


/**
 TCP: Upon RTO:
 1) GetSSThresh() is set to half of flight size
 2) cwnd is set to 1*MSS
 3) retransmit the lost packet
 4) Tcp back to slow start
 */
//
//void
//MpTcpSocketBase::ReTxTimeout(uint8_t sFlowIdx)
//{ // Retransmit timeout
//  NS_LOG_FUNCTION (this);
////  NS_ASSERT_MSG(client, "ReTxTimeout is not implemented for server side yet");
//  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
//
//  NS_LOG_INFO ("Subflow ("<<(int)sFlowIdx<<") ReTxTimeout Expired at time "
//        <<Simulator::Now ().GetSeconds()<< " unacked packets count is "<<sFlow->m_mapDSN.size()
//        << " sFlow->state: " << TcpStateName[sFlow->m_state]
//        ); //
//  //NS_LOG_INFO("TxSeqNb: " << sFlow->TxSeqNumber << " HighestAck: " << sFlow->highestAck);
//  // If erroneous timeout in closed/timed-wait state, just return
//  if (sFlow->m_state == CLOSED || sFlow->m_state  == TIME_WAIT)
//    {
//      NS_LOG_INFO("RETURN");
//      NS_ASSERT(3!=3);
//      return;
//    }
//  // If all data are received (non-closing socket and nothing to send), just return
//  // if (m_state <= ESTABLISHED && m_txBuffer.HeadSequence() >= m_highTxMark)
//  if (sFlow->m_state  <= ESTABLISHED && sFlow->m_mapDSN.size() == 0)
//    {
//      NS_LOG_INFO("RETURN");
//      NS_ASSERT(3!=3);
//      return;
//    }
//  Retransmit(sFlowIdx); // Retransmit the packet
//}


// TODO move that away a t'on besoin de passer le mapping ?
// OnRetransmit()
// OnLoss
#if 0
void
MpTcpSocketBase::ReduceCWND(uint8_t sFlowIdx)
{

  NS_ASSERT(m_algoCC);

//  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
//  uint32_t m_segmentSize = sFlow->GetSegSize();
//  int cwnd_tmp = 0;

  // TODO

//  m_algoCC->OnRetransmit( );

  switch (m_algoCC)
    {
  case Uncoupled_TCPs:
    sFlow->SetSSThresh( std::max(2 * m_segmentSize, BytesInFlight(sFlowIdx) / 2) );
    sFlow->cwnd = sFlow->GetSSThresh() + 3 * m_segmentSize;
    break;
  case Linked_Increases:
    sFlow->SetSSThresh( std::max(2 * m_segmentSize, BytesInFlight(sFlowIdx) / 2) );
    sFlow->cwnd = sFlow->GetSSThresh() + 3 * m_segmentSize;
    break;
  case RTT_Compensator:
    sFlow->SetSSThresh( std::max(2 * m_segmentSize, BytesInFlight(sFlowIdx) / 2) );
    sFlow->cwnd = sFlow->GetSSThresh() + 3 * m_segmentSize;
    break;
  case Fully_Coupled:
    cwnd_tmp = sFlow->cwnd - m_totalCwnd / 2;
    if (cwnd_tmp < 0)
      cwnd_tmp = 0;
    sFlow->SetSSThresh( std::max((uint32_t) cwnd_tmp, 2 * m_segmentSize) );
    sFlow->cwnd = sFlow->GetSSThresh() + 3 * m_segmentSize;
    break;
  default:
    NS_ASSERT(3!=3);
    break;
    }

  // update
//  sFlow->m_recover = SequenceNumber32(sFlow->maxSeqNb + 1);
//  sFlow->m_inFastRec = true;
//
//  // Retrasnmit a specific packet (lost segment)
//  DoRetransmit(sFlowIdx, ptrDSN);
//
//  // plotting
//  reTxTrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd));
//  sFlow->ssthreshtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->GetSSThresh()));
}
    #endif

/** Retransmit timeout */
void
MpTcpSocketBase::Retransmit()
{
  NS_LOG_FUNCTION (this);  //
  #if 0
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
  // Exit From Fast Recovery
  sFlow->m_inFastRec = false;
  // According to RFC2581 sec.3.1, upon RTO, GetSSThresh() is set to half of flight
  // size and cwnd is set to 1*MSS, then the lost packet is retransmitted and
  // TCP back to slow start
  sFlow->SetSSThresh( std::max(2 * sFlow->GetSegSize(), BytesInFlight(sFlowIdx) / 2) );
  sFlow->cwnd = sFlow->GetSegSize(); //  sFlow->cwnd = 1.0;
  sFlow->TxSeqNumber = sFlow->highestAck + 1; // m_nextTxSequence = m_txBuffer.HeadSequence(); // Restart from highest Ack
  sFlow->rtt->IncreaseMultiplier();  // Double the next RTO
  DoRetransmit(sFlowIdx);  // Retransmit the packet
  // plotting
  sFlow->_TimeOut.push_back(make_pair(Simulator::Now().GetSeconds(), TimeScale));
  // rfc 3782 - Recovering from timeOut
  //sFlow->m_recover = SequenceNumber32(sFlow->maxSeqNb + 1);
  #endif
}

//void
//MpTcpSocketBase::SetReTxTimeout(uint8_t sFlowIdx)
//{
//  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
//  if (sFlow->m_retxEvent.IsExpired())
//    {
//      Time rto = sFlow->rtt->RetransmitTimeout();
//      sFlow->m_retxEvent = Simulator::Schedule(rto, &MpTcpSocketBase::ReTxTimeout, this, sFlowIdx);
//    }
//}

#if 0
DSNMapping*
MpTcpSocketBase::getAckedSegment(uint8_t sFlowIdx, uint32_t ack)
{
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
  DSNMapping* ptrDSN = 0;
  for (list<DSNMapping *>::iterator it = sFlow->m_mapDSN.begin(); it != sFlow->m_mapDSN.end(); ++it)
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
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
  DSNMapping* ptrDSN = 0;
  for (list<DSNMapping *>::iterator it = sFlow->m_mapDSN.begin(); it != sFlow->m_mapDSN.end(); ++it)
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
#endif // 0

// whydo we have this one ?
#if 0
void
MpTcpSocketBase::NewAckNewReno(uint8_t sFlowIdx, const TcpHeader& mptcpHeader, TcpOptions* opt)
{
  NS_LOG_FUNCTION (this << (int)sFlowIdx);
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
  SequenceNumber32 ack = mptcpHeader.GetAckNumber();
  uint32_t ackedBytes = ack.GetValue() - (sFlow->highestAck + 1);

  NS_LOG_LOGIC ("TcpNewReno receieved ACK for seq " << ack <<" cwnd " << sFlow->cwnd <<" GetSSThresh() " << sFlow->GetSSThresh());
  // Check for exit condition of fast recovery
  if (sFlow->m_inFastRec && ack < sFlow->m_recover)
    { // Partial ACK, partial window deflation (RFC2582 sec.3 bullet #5 paragraph 3)
      NS_LOG_WARN("NewAckNewReno -> ");
      sFlow->cwnd -= ack.GetValue() - (sFlow->highestAck + 1); // data bytes where acked
      // RFC3782 sec.5, partialAck condition for inflating.
      sFlow->cwnd += sFlow->GetSegSize(); // increase cwnd

      // Plotting
      NS_LOG_LOGIC ("Partial ACK in fast recovery: cwnd set to " << sFlow->cwnd.Get());
      PartialAck.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd.Get()));
      sFlow->ssthreshtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->GetSSThresh()));
      sFlow->_FR_PA.push_back(make_pair(Simulator::Now().GetSeconds(), TimeScale));

      DiscardMappingsUpTo(sFlowIdx, ack.GetValue());
      DSNMapping* ptrDSN = getSegmentOfACK(sFlowIdx, ack.GetValue());
      NS_ASSERT(ptrDSN != 0);
      DoRetransmit(sFlowIdx, ptrDSN);

      MpTcpSocketBase::NewACK(sFlowIdx, mptcpHeader, opt); // update m_nextTxSequence and send new data if allowed by window
      //DoRetransmit(sFlowIdx); // Assume the next seq is lost. Retransmit lost packet
//      pAck++;
      return;
    }
  else if (sFlow->m_inFastRec && ack >= sFlow->m_recover)
    { // Full ACK (RFC2582 sec.3 bullet #5 paragraph 2, option 1)
      NS_LOG_WARN("NewAckNewReno -> FullAck");
      sFlow->cwnd = std::min(sFlow->GetSSThresh(), BytesInFlight(sFlowIdx) + sFlow->GetSegSize() );

      // Exit from Fast recovery
      sFlow->m_inFastRec = false;

      // Plotting
      FullAck.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd.Get()));
      sFlow->ssthreshtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->GetSSThresh()));
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
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
  uint32_t ack = (mptcpHeader.GetAckNumber()).GetValue();
  NS_LOG_LOGIC ("[" << GetNode()->GetId()<< "]" << " Cancelled ReTxTimeout event which was set to expire at " << (Simulator::Now () + Simulator::GetDelayLeft (sFlow->retxEvent)).GetSeconds ());

  // On recieving a "New" ack we restart retransmission timer .. RFC 2988
  sFlow->retxEvent.Cancel();
  Time rto = sFlow->rtt->RetransmitTimeout();
  NS_LOG_LOGIC (this << " Schedule ReTxTimeout at time> " <<Simulator::Now ().GetSeconds () << " to expire at time " <<(Simulator::Now () + rto).GetSeconds ());
  sFlow->retxEvent = Simulator::Schedule(rto, &MpTcpSocketBase::ReTxTimeout, this, sFlowIdx);

  // Note the highest ACK and tell app to send more
  DiscardMappingsUpTo(sFlowIdx, ack);

  if (GetTxAvailable() > 0)
    { // Notify app about free space available in TxBuffer
      NotifyDataSent(GetTxAvailable()); // NotifySend(GetTxAvailable());
    }
  if (ack > sFlow->TxSeqNumber)
    {
      NS_LOG_WARN("NewAck-> ReceivedAck is bigger than TxSeqNumber => Advance TxSeqNumber from " << sFlow->TxSeqNumber << " To " << ack);
      sFlow->TxSeqNumber = ack; // If advanced
    }

  if (
      (m_sendingBuffer->Empty() ) && (sFlow->m_mapDSN.size() == 0) &&
      (sFlow->state != FIN_WAIT_1) && (sFlow->state != CLOSING)
      )
    { // No retransmit timer if no data to retransmit
      NS_LOG_INFO ("("<< (int)sFlow->m_routeId << ") NewAck -> Cancelled ReTxTimeout event which was set to expire at " << (Simulator::Now () + Simulator::GetDelayLeft (sFlow->retxEvent)).GetSeconds () << ", DSNmap: " << sFlow->m_mapDSN.size());
      sFlow->retxEvent.Cancel();
    }

  sFlow->highestAck = std::max(sFlow->highestAck, ack - 1);
  NS_LOG_WARN("NewACK-> sFlow->highestAck: " << sFlow->highestAck);

//  m_currentSublow = sFlow->m_routeId;
  SendPendingData();
}

#endif

int
MpTcpSocketBase::GenerateToken(uint32_t& token) const
{
  // if connection not established yet then we've got not key to generate the token
  if( IsConnected() )
  {
    // TODO hash keys
    token = 2;
    return 0;
  }

  return -ERROR_NOTCONN;
}



uint64_t
MpTcpSocketBase::GenerateKey() const
{
  return (rand() % 1000 + 1);
}



/**
TODO remove ?
**/
#if 0
void
MpTcpSocketBase::SendEmptyPacket(uint8_t sFlowIdx, uint8_t flags)
{
  // Let scheduler use

  NS_LOG_FUNCTION (this << (int)sFlowIdx);
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
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
//      if (sFlow->maxSeqNb != sFlow->TxSeqNumber - 1 && client)
      if (sFlow->maxSeqNb != sFlow->TxSeqNumber - 1 )
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
  header.SetDestinationPort(sFlow->m_dPort);
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
      if (sFlow->m_cnCount == 0)
        { // No more connection retries, give up
          NS_LOG_INFO ("Connection failed.");
          CloseAndNotify(sFlow->m_routeId);
          return;
        }
      else
        { // Exponential backoff of connection time out
          int backoffCount = 0x1 << (sFlow->m_cnRetries - sFlow->m_cnCount);
          RTO = Seconds(sFlow->cnTimeout.GetSeconds() * backoffCount);
          sFlow->m_cnCount = sFlow->m_cnCount - 1;
          NS_LOG_UNCOND("("<< (int)sFlow->m_routeId<< ") SendEmptyPacket -> backoffCount: " << backoffCount << " RTO: " << RTO.GetSeconds() << " cnTimeout: " << sFlow->cnTimeout.GetSeconds() <<" m_cnCount: "<< sFlow->m_cnCount);
        }
    }
  if (((sFlow->state == SYN_SENT) || (sFlow->state == SYN_RCVD && m_mpEnabled == true))
//        && mpSendState == MP_NONE
        )
    {
//      mpSendState = MP_MPC;                  // This state means MP_MPC is sent
      m_localKey = rand() % 1000 + 1;        // Random Local Token
      header.AddOptMPC(OPT_MPCAPABLE, m_localKey); // Adding MP_CAPABLE & Token to TCP option (5 Bytes)
      olen += 5;
      m_tcp->m_TokenMap[m_localKey] = m_endPoint;       //m_tcp->m_TokenMap.insert(std::make_pair(m_localKey, m_endPoint))
      NS_LOG_INFO("("<< (int)sFlow->m_routeId<< ") SendEmptyPacket -> m_localKey is mapped to connection endpoint -> " << m_localKey << " -> " << m_endPoint << " TokenMapsSize: "<< m_tcp->m_TokenMap.size());
    }
  else if (sFlow->state == SYN_SENT && hasSyn && sFlow->m_routeId == 0)
    {
      header.AddOptMPC(OPT_MPCAPABLE, m_localKey);       // Adding MP_CAPABLE & Token to TCP option (5 Bytes)
      olen += 5;
    }
  else if (sFlow->state == SYN_SENT && hasSyn && sFlow->m_routeId != 0)
    {
      header.AddOptJOIN(OPT_JOIN, m_remoteKey, 0); // addID should be zero?
      olen += 6;
    }

  uint8_t plen = (4 - (olen % 4)) % 4;
  olen = (olen + plen) / 4;
  hlen = 5 + olen;
  header.SetLength(hlen);
  header.SetOptionsLength(olen);
  header.SetPaddingLength(plen);

  m_tcp->SendPacket(p, header, sFlow->sAddr, sFlow->dAddr, FindOutputNetDevice(sFlow->sAddr));
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
#endif

//void
//MpTcpSocketBase::allocateSendingBuffer(uint32_t size)
//{
//  NS_LOG_FUNCTION(this << size);
//  m_sendingBuffer = new DataBuffer(size);
//}
//
//void
//MpTcpSocketBase::allocateRecvingBuffer(uint32_t size)
//{
//  NS_LOG_FUNCTION(this << size);
//  m_recvingBuffer = new DataBuffer(size);
//}
//
//void
//MpTcpSocketBase::SetunOrdBufMaxSize(uint32_t size)
//{
//  NS_LOG_FUNCTION_NOARGS();
//  //m_unOrdMaxSize = size;
//}
//
//void
//MpTcpSocketBase::SetSndBufSize(uint32_t size)
//{
//  //m_txBuffer.SetMaxBufferSize(size);
//  m_sendingBuffer = new DataBuffer(size);
//}
//uint32_t
//MpTcpSocketBase::GetSndBufSize(void) const
//{
//  //return m_txBuffer.MaxBufferSize();
//  return 0;
//}
//void
//MpTcpSocketBase::SetRcvBufSize(uint32_t size)
//{
//  //m_rxBuffer.SetMaxBufferSize(size);
//  m_recvingBuffer = new DataBuffer(size);
//}
//uint32_t
//MpTcpSocketBase::GetRcvBufSize(void) const
//{
//  //return m_rxBuffer.MaxBufferSize();
//  return 0;
//}
//
//uint32_t
//MpTcpSocketBase::Recv(uint8_t* buf, uint32_t size)
//{
//  NS_LOG_FUNCTION (this);
//  //Null packet means no data to read, and an empty packet indicates EOF
//  uint32_t toRead = std::min(m_recvingBuffer->PendingData(), size);
//  return m_recvingBuffer->Retrieve(buf, toRead);
//}

  #if 0
void
MpTcpSocketBase::ForwardUp(Ptr<Packet> p, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface> interface) // ns3.15
{
  NS_LOG_FUNCTION(this<< " SubflowSize["<<m_subflows.size() << "]");



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
  if (m_subflows.empty() && m_state == LISTEN)
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
      m_mpEnabled = false;
      m_remoteKey = 0;
      m_localKey = 0;
      remoteRecvWnd = 1;
      return;
    }
  // Accepted sockets being dealt with from here.......
  // LookupByAddrs of src and destination.
  uint8_t sFlowIdx = LookupByAddrs(m_localAddress, m_remoteAddress); //m_endPoint->GetPeerAddress());
//  NS_ASSERT_MSG((sFlowIdx < m_maxSubflows), "Subflow number should be smaller than MaxNumOfSubflows");

  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];

  //uint32_t dataLen;   // packet's payload length
  remoteRecvWnd = (uint32_t) mptcpHeader.GetWindowSize(); //update the flow control window

  sFlow->dAddr = m_remoteAddress;
  sFlow->m_dPort = m_endPoint->GetPeerPort();

  if (mptcpHeader.GetFlags() & TcpHeader::ACK)
    { // This function update subflow's lastMeasureRtt variable.
      EstimateRtt(sFlowIdx, mptcpHeader);
    }

  if (ReadOptions(sFlowIdx, p, mptcpHeader) == false)
    return;

// TCP state machine code in different process functions
// C.f.: tcp_rcv_state_process() in tcp_input.c in Linux kernel
//  m_currentSublow = sFlow->m_routeId;
  switch (sFlow->state)
    {
  case ESTABLISHED:
    ProcessEstablished(sFlowIdx, p, mptcpHeader);
    break;

  // This is only valid when a master socket already exists
  case LISTEN:
    ProcessListen(sFlowIdx, p, mptcpHeader, fromAddress, toAddress);
    break;
  case TIME_WAIT:
// Do nothing
    break;
  case CLOSED:
    NS_LOG_INFO(" ("<< sFlow->m_routeId << ") " << TcpStateName[sFlow->state] << " -> Send RST");
// Send RST if the incoming packet is not a RST
    if ((mptcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG)) != TcpHeader::RST)
      { // Since sFlow->m_endPoint is not configured yet, we cannot use SendRST here
        TcpHeader h;
        h.SetFlags(TcpHeader::RST);
        h.SetSequenceNumber(SequenceNumber32(sFlow->TxSeqNumber));
        h.SetAckNumber(SequenceNumber32(sFlow->RxSeqNumber));
        h.SetSourcePort(sFlow->sPort);
        h.SetDestinationPort(sFlow->m_dPort);
        h.SetWindowSize(AdvertisedWindowSize());
        m_tcp->SendPacket(Create<Packet>(), h, header.GetDestination(), header.GetSource(), FindOutputNetDevice(header.GetDestination()));
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
#endif


void
MpTcpSocketBase::GetAllAdvertisedDestinations(std::vector<InetSocketAddress>& cont)
{
  NS_ASSERT(m_remotePathIdManager);
  m_remotePathIdManager->GetAllAdvertisedDestinations(cont);
}


void
MpTcpSocketBase::SetNewAddrCallback(Callback<bool, Ptr<Socket>, Address, uint8_t> remoteAddAddrCb,
                          Callback<void, uint8_t> remoteRemAddrCb)

{
  //
  m_onRemoteAddAddr = remoteAddAddrCb;
  m_onAddrDeletion = remoteRemAddrCb;
}


#if 0
void
MpTcpSocketBase::ReadUnOrderedData()
{
  NS_LOG_FUNCTION (this);NS_LOG_WARN("ReadUnOrderedData()-> Size: " << m_unOrdered.size());
  MappingList::iterator current = m_unOrdered.begin();
  list<DSNMapping *>::iterator next = m_unOrdered.begin();

  // I changed this method, now whenever a segment is readed it get dropped from that list
  while (next != m_unOrdered.end())
    {
      ++next;
      DSNMapping *ptrDSN = *current;
      uint32_t sFlowIdx = ptrDSN->subflowIndex;
      Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
      if ((ptrDSN->dataSeqNumber <= nextRxSequence) /*&& (ptrDSN->subflowSeqNumber == sFlow->RxSeqNumber)*/)
        {
          NS_ASSERT(ptrDSN->dataSeqNumber == nextRxSequence);
          uint32_t amount = m_recvingBuffer->Add(ptrDSN->packet, ptrDSN->dataLevelLength);

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
          m_unOrdered.erase(current);
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
#endif

void
MpTcpSocketBase::OnSubflowDupack(Ptr<MpTcpSubFlow> sf, MpTcpMapping mapping)
{
  NS_LOG_LOGIC("Subflow Dupack");
}

void
MpTcpSocketBase::OnSubflowRetransmit(Ptr<MpTcpSubFlow> sf)
{
  NS_LOG_LOGIC("Subflow retransmit");
}



uint32_t
MpTcpSocketBase::Window()
{
  NS_LOG_FUNCTION (this);
  return std::min( m_rWnd.Get(), m_cWnd.Get() );
}

Time
MpTcpSocketBase::ComputeReTxTimeoutForSubflow( Ptr<MpTcpSubFlow> sf)
{
  NS_ASSERT(sf);

  return sf->m_rtt->RetransmitTimeout();
}


/*
 * When dupAckCount reach to the default value of 3 then TCP goes to ack recovery process.
 */
 #if 0
void
MpTcpSocketBase::DupAck(uint8_t sFlowIdx, DSNMapping* ptrDSN)
{
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
  sFlow->m_dupAckCount++;
  ptrDSN->dupAckCount++; // Used for evaluation purposes only
  uint32_t cwnd = sFlow->cwnd.Get();
  uint32_t m_segmentSize = sFlow->GetSegSize();
  calculateTotalCWND();

  // Plotting
  uint32_t tmp = (((ptrDSN->subflowSeqNumber) - sFlow->initialSequenceNumber) / sFlow->GetSegSize() % mod);
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
      sFlow->cwnd += m_segmentSize;

      // Plotting
      DupAcks.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd));
      sFlow->ssthreshtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->GetSSThresh()));
      NS_LOG_WARN ("DupAck-> FastRecovery. Increase cwnd by one MSS, from " << cwnd <<" -> " << sFlow->cwnd << " AvailableWindow: " << AvailableWindow(sFlowIdx));

      // Send more data into pipe if possible to get ACK clock going
      SendPendingData();
    }
  else
    {
      NS_LOG_WARN("Limited transmit is not enabled... DupAcks: " << ptrDSN->dupAckCount);
    }
//  else if (!sFlow->m_inFastRec && sFlow->m_limitedTx && m_sendingBuffer->PendingData() > 0)
//    { // RFC3042 Limited transmit: Send a new packet for each duplicated ACK before fast retransmit
//      NS_LOG_INFO ("Limited transmit");
//      uint32_t sz = SendDataPacket(sFlowIdx, sFlow->MSS, false); // WithAck or Without ACK?
//      NotifyDataSent(sz);
//    };
}
#endif


std::string
MpTcpSocketBase::GeneratePlotDetail(void)
{

  std::stringstream detail;
  detail
        << "  sF:" << m_subflows.size()
//        << " C:" << LinkCapacity / 1000
//        << "Kbps  RTT:" << RTT << "Ms  D:"
//      << totalBytes / 1000
      << "Kb"
      << "MSS:" << m_segmentSize << "B";
  return detail.str();
}

//void
//MpTcpSocketBase::GeneratePktCount()
//{
//  std::ofstream outfile("pktCount.plt");
//  Gnuplot pktCountGraph = Gnuplot("pktCount.png", GeneratePlotDetail());
//
//  pktCountGraph.SetLegend("Subflows", "Packets");
//  pktCountGraph.SetTerminal("png");
//  pktCountGraph.SetExtra("set xrange [0:4]");
//
//  for (uint16_t idx = 0; idx < m_subflows.size(); idx++)
//    {
//      Ptr<MpTcpSubFlow> sFlow = m_subflows[idx];
//
//      Gnuplot2dDataset dataSet;
//      dataSet.SetStyle(Gnuplot2dDataset::LINES_POINTS);
//
//      std::stringstream title;
//      title << " Subflow " << idx;
//
//      dataSet.SetTitle(title.str());
//      dataSet.Add(idx, sFlow->PktCount);
//      pktCountGraph.AddDataset(dataSet);
//      NS_LOG_UNCOND(" Subflow(" << idx << ") Number of Sent Packets : " << sFlow->PktCount);
//    }
//  pktCountGraph.GenerateOutput(outfile);
//  outfile.close();
//}

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
  for (uint16_t idx = 0; idx < m_subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = m_subflows[idx];

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
  for (uint16_t idx = 0; idx < m_subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = m_subflows[idx];

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
  for (uint16_t idx = 0; idx < m_subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = m_subflows[idx];

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
  for (uint16_t idx = 0; idx < m_subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = m_subflows[idx];

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
  for (uint16_t idx = 0; idx < m_subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = m_subflows[idx];

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
  for (uint16_t idx = 0; idx < m_subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = m_subflows[idx];

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
  for (uint16_t idx = 0; idx < m_subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = m_subflows[idx];

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
  for (uint16_t idx = 0; idx < m_subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = m_subflows[idx];

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
  for (uint16_t idx = 0; idx < m_subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = m_subflows[idx];

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
  for (uint16_t idx = 0; idx < m_subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = m_subflows[idx];

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
  for (uint16_t idx = 0; idx < m_subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = m_subflows[idx];

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
  for (uint16_t idx = 0; idx < m_subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = m_subflows[idx];

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
  for (uint16_t idx = 0; idx < m_subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = m_subflows[idx];

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
  for (uint16_t idx = 0; idx < m_subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = m_subflows[idx];
      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::POINTS);
      std::stringstream title;
      title << "sFlow " << idx;
      dataSet.SetTitle(title.str());
      vector<pair<double, uint32_t> >::iterator it = sFlow->cwndTracer.begin();
      while (it != sFlow->cwndTracer.end())
        {
          dataSet.Add(it->first, it->second / sFlow->GetSegSize() );
          it++;
        }
      if (sFlow->cwndTracer.size() > 0)
        cwndTracerGraph.AddDataset(dataSet);
    }
  // ssthreshold
  for (uint16_t idx = 0; idx < m_subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = m_subflows[idx];
      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::LINES);
      std::stringstream title;
      title << "ssth " << idx;
      dataSet.SetTitle(title.str());
      vector<pair<double, double> >::iterator it = sFlow->ssthreshtrack.begin();
      while (it != sFlow->ssthreshtrack.end())
        {
          dataSet.Add(it->first, it->second / sFlow->GetSegSize( ) );
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
  NS_LOG_UNCOND("GenerateCWNDPlot -> subflowsSize: " << m_subflows.size());
  for (uint16_t idx = 0; idx < m_subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = m_subflows[idx];

      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::POINTS);

      std::stringstream title;
      title << "sFlow " << idx;

      dataSet.SetTitle(title.str());

      vector<pair<double, double> >::iterator it = sFlow->CWNDtrack.begin();

      while (it != sFlow->CWNDtrack.end())
        {
          dataSet.Add(it->first, it->second / sFlow->GetSegSize( ) );
          it++;
        }
      if (sFlow->CWNDtrack.size() > 0)
        cwndGraph.AddDataset(dataSet);
    }

// ssthreshold
  for (uint16_t idx = 0; idx < m_subflows.size(); idx++)
    {
      Ptr<MpTcpSubFlow> sFlow = m_subflows[idx];

      Gnuplot2dDataset dataSet;
      dataSet.SetStyle(Gnuplot2dDataset::LINES);

      std::stringstream title;
      title << "ssth " << idx;

      dataSet.SetTitle(title.str());

      vector<pair<double, double> >::iterator it = sFlow->ssthreshtrack.begin();

      while (it != sFlow->ssthreshtrack.end())
        {
          dataSet.Add(it->first, it->second / sFlow->GetSegSize( ) );
          it++;
        }
      if (sFlow->ssthreshtrack.size() > 0)
        cwndGraph.AddDataset(dataSet);
    }

  // Only if mptcp has one subflow, the following dataset would be added to the plot
//  if (m_subflows.size() == 1)
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
          dataSet.Add(it->first, it->second / m_segmentSize);
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
          dataSet.Add(it->first, it->second / m_segmentSize);
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
          dataSet.Add(it->first, it->second / m_segmentSize);
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
          dataSet.Add(it->first, it->second / m_segmentSize);
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
          dataSet.Add(it->first, it->second / m_segmentSize);
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
//   dataSet.Add(it->first, it->second / m_segmentSize);
//   it++;
//   }
//   cwndGraph.AddDataset(dataSet);
//   }
//    }
//gnu.AddPlot(cwndGraph);
  cwndGraph.GenerateOutput(outfile);
  outfile.close();
}

#if 0
bool
MpTcpSocketBase::StoreUnOrderedData(DSNMapping *ptr1)
{
  NS_LOG_FUNCTION (this);
  /**
   * return the statement depending on successfully inserting or not the data
   * if unOrdered buffer can't hold the out of sequence data and currently received
   */
  bool inserted = false;
  for (list<DSNMapping *>::iterator it = m_unOrdered.begin(); it != m_unOrdered.end(); ++it)
    {
      DSNMapping *ptr2 = *it;
      if (ptr1->dataSeqNumber == ptr2->dataSeqNumber)
        {
          NS_LOG_WARN ("Data Sequence ("<< ptr1->dataSeqNumber <<") ALREADY STORED in m_unOrdered buffer !");
          return false;
        }
      else if (ptr1->dataSeqNumber < ptr2->dataSeqNumber)
        {
          NS_LOG_WARN ("Data Sequence ("<< ptr1->dataSeqNumber <<" with subFlowSeqNb: )" << ptr1->subflowSeqNumber << " HAS stored in m_unOrdered buffer SUCCESSFULLY!");
          m_unOrdered.insert(it, ptr1);
          inserted = true;
          break;
        }
    }
  if (!inserted)
    {
      NS_LOG_WARN ("StoreUnOrderedData -> DataSeqNb: " << ptr1->dataSeqNumber << " with subflowSeqNb: " << ptr1->subflowSeqNumber << " has stored at the end of list");
      m_unOrdered.insert(m_unOrdered.end(), ptr1);
    }

  return true;
}
#endif

/** Peer sent me a FIN. Remember its sequence in rx buffer. */
#if 0
void
MpTcpSocketBase::PeerClose(uint8_t sFlowIdx, Ptr<Packet> p, const TcpHeader& mptcpHeader)
{
  NS_LOG_FUNCTION (this << mptcpHeader);
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];

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
  NS_LOG_INFO ("(" << (int)sFlow->m_routeId<< ") Accepted FIN at seq " << mptcpHeader.GetSequenceNumber () + SequenceNumber32 (p->GetSize ()) << ", PktSize: " << p->GetSize() << " {PeerClose}"); //
  NS_LOG_INFO ("(" << (int)sFlow->m_routeId<< ") RxSeqNumber: " << sFlow->RxSeqNumber<< " {PeerClose}");

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
      NS_LOG_INFO ("("<< (int) sFlow->m_routeId << ") FIN_WAIT_1 -> CLOSING {Simultaneous close}");
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
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
  NS_ASSERT(sFlow->state == ESTABLISHED || sFlow->state == SYN_RCVD);
  /*
   * Receiver gets in-sequence FIN packet from sender.
   * It sends ACK for it and also send its own FIN at the same time since our implementation is unidirectional
   * i.e., receiver is not suppose to send data packet to sender and its m_sendingBuffer is uninitialized!
   */
  // Move the state of subflow to CLOSE_WAIT
  NS_LOG_INFO ("(" << (int) sFlow->m_routeId << ") "<< TcpStateName[sFlow->state] << " -> CLOSE_WAIT {DoPeerClose}");
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
#endif
//
//void
//MpTcpSocketBase::LastAckTimeout(uint8_t sFlowIdx)
//{
//  NS_LOG_FUNCTION (this);
//  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
//  sFlow->m_lastAckEvent.Cancel();
//  if (sFlow->state == LAST_ACK)
//    {
//      NS_LOG_INFO("(" << (int) sFlow->m_routeId << ") LAST_ACK -> CLOSED {LastAckTimeout}");
//      CloseAndNotify(sFlowIdx);
//    }
////  if (!m_closeNotified)
////    {
////      m_closeNotified = true;
////    }
//}
//

#if 0
// looks used only when closing the socket
// disabled during revamp of the socket & DSN mapping handling
bool
MpTcpSocketBase::FindPacketFromUnOrdered(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION((int)sFlowIdx);
  bool reValue = false;
  MappingList::iterator current = m_unOrdered.begin();
  while (current != m_unOrdered.end())
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
#endif



#if 0
void
MpTcpSocketBase::CloseAndNotify(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION (this << (int) sFlowIdx);
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
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
#endif // 0

/** Inherit from Socket class: Kill this socket and signal the peer (if any) */
#if 0
int
MpTcpSocketBase::Close(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION (this << (int)sFlowIdx);
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];

  //  if (client)
//      NS_LOG_INFO("Close(" <<(int) sFlowIdx << ")" << ", PendingData: " << m_sendingBuffer->PendingData() << ", m_mapDSN.size: " << sFlow->m_mapDSN.size());

// First we check to see if there is any unread rx data
// Bug number 426 claims we should send reset in this case.
  if (server && m_unOrdered.size() > 0 && FindPacketFromUnOrdered(sFlowIdx) && !sFlow->Finished()) /* && m_recvingBuffer->PendingData() != 0 */
    {  // I don't expect this to happens in normal scenarios!
      NS_FATAL_ERROR("Receiver called close() when there are some unread packets in its buffer");
      SendRST(sFlowIdx);
      CloseAndNotify(sFlowIdx);
      NS_LOG_WARN("m_unOrderedBuffer: " << m_unOrdered.size() << " currentSubflow: " << sFlow->m_routeId);
      return 0;
    }

  if (client && m_sendingBuffer->PendingData() > 0) //if (m_txBuffer.SizeFromSequence(m_nextTxSequence) > 0)
    { // App close with pending data must wait until all data transmitted
//      if (m_closeOnEmpty == false)
//        {
//          m_closeOnEmpty = true;
//          NS_LOG_INFO("-----------------------CLOSE is issued by sender application-----------------------");NS_LOG_INFO ("Socket " << this << " deferring close, Connection state " << TcpStateName[m_state] << " PendingData: " << m_sendingBuffer->PendingData());
//        }
      return 0;
    }
//  else if (client && m_sendingBuffer->PendingData() == 0 && sFlow->maxSeqNb != sFlow->TxSeqNumber -1)
//    return 0;

  if (client)
    NS_ASSERT(m_sendingBuffer->Empty());
  if (server)
    NS_ASSERT_MSG(sFlow->Finished(),
        " state: " << TcpStateName[sFlow->state] << " GotFin: " << sFlow->m_gotFin << " FinSeq: " << sFlow->m_finSeq << " m_mapDSN: " << sFlow->m_mapDSN.size());

  return DoClose(sFlowIdx);
}
#endif

/** Do the action to close the socket. Usually send a packet with appropriate
 flags depended on the current m_state. */
 #if 0
int
MpTcpSocketBase::DoClose(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION (this << (int)sFlowIdx << m_subflows.size());

  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
  //NS_LOG_INFO("DoClose -> Socket src/des (" << sFlow->sAddr << ":" << sFlow->sPort << "/" << sFlow->dAddr << ":" << sFlow->m_dPort << ")" << " state: " << TcpStateName[sFlow->state]);
  switch (sFlow->state)
    {
  case SYN_RCVD:
  case ESTABLISHED:
// send FIN to close the peer
    SendEmptyPacket(sFlowIdx, TcpHeader::FIN);
    NS_LOG_INFO ("("<< (int) sFlow->m_routeId<< ") ESTABLISHED -> FIN_WAIT_1 {DoClose} FIN is sent as separate pkt");
    sFlow->state = FIN_WAIT_1;
    break;
  case CLOSE_WAIT:
// send FIN+ACK to close the peer (in normal scenario receiver should use this when she got FIN from sender)
    SendEmptyPacket(sFlowIdx, TcpHeader::FIN | TcpHeader::ACK);
    NS_LOG_INFO ("("<< (int) sFlow->m_routeId<< ") CLOSE_WAIT -> LAST_ACK {DoClose}");
    sFlow->state = LAST_ACK;
    break;
  case SYN_SENT:
  case CLOSING:
// Send RST if application closes in SYN_SENT and CLOSING
    NS_LOG_INFO("DoClose -> Socket src/des (" << sFlow->sAddr << ":" << sFlow->sPort << "/" << sFlow->dAddr << ":" << sFlow->m_dPort << ")" << " sFlow->state: " << TcpStateName[sFlow->state]);
//    SendRST(sFlowIdx);
//    CloseAndNotify(sFlowIdx);
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
//NS_LOG_INFO("DoClose -> DoNotting since subflow's state is " << TcpStateName[sFlow->state] << "(" << sFlow->m_routeId<< ")");
// Do nothing in these four states
    break;
    }
  return 0;
}

#endif

int
MpTcpSocketBase::Close(void)
{
  #if 0
  NS_LOG_FUNCTION(this);
  // Should attempt to close all subflows
  int res = 0;
  for( std::vector<Ptr<MpTcpSubFlow>::iterator i = m_subflows.begin(); i != m_subflows.end(); i++ )
  {
    res += std::abs( i->Close() );

  }

  return (res ==0);

  if (m_subflows.size() > 0)
    {
        { // This block could be removed...
          if (m_subflows.size() == 1)
//            NS_ASSERT(m_currentSublow == 0);
//          NS_LOG_WARN("Close() -> CurrentSubflow: " << (int)m_currentSublow);
        } //-------------------------------
      return Close(m_currentSublow);
    }
  else
    { //CloseMultipathConnection(); this could be used as well...
      NS_LOG_INFO("Close has issued for listening socket, "<< this <<", it's endpoints ->  local/remote (" << m_endPoint->GetLocalAddress() << ":" << m_endPoint->GetLocalPort() << "/" << m_endPoint->GetPeerAddress() << ":" << m_endPoint->GetPeerPort() << ") m_state: " << TcpStateName[m_state] << " -> CLOSED");
      NS_ASSERT(m_subflows.size() == 0);
      m_state = CLOSED;
      NotifyNormalClose();
      m_endPoint->SetDestroyCallback(MakeNullCallback<void>());
      m_tcp->DeAllocate(m_endPoint);
      m_endPoint = 0;
// No need to do that anymore
//      std::vector<Ptr<TcpSocketBase> >::iterator it = std::find(m_tcp->m_sockets.begin(), m_tcp->m_sockets.end(), this);
//      if (it != m_tcp->m_sockets.end())
//        {
//          m_tcp->m_sockets.erase(it);
//        }
      CancelAllSubflowTimers();
    }
  return true;
  #endif

  return 0;
}

// This function would calls NotifyNormalClose() where in turn calls mpTopology:HandlePeerClose where in turn calls close();
#if 0
bool
MpTcpSocketBase::CloseMultipathConnection()
{
  NS_LOG_FUNCTION_NOARGS();
  bool closed = false;
  uint32_t cpt = 0;
  for (uint32_t i = 0; i < m_subflows.size(); i++)
    {
      NS_LOG_LOGIC("Subflow (" << i << ") TxSeqNb (" << m_subflows[i]->TxSeqNumber << ") RxSeqNb = " << m_subflows[i]->RxSeqNumber << " highestAck (" << m_subflows[i]->highestAck << ") maxSeqNb (" << m_subflows[i]->maxSeqNb << ")");

      if (m_subflows[i]->m_state == CLOSED)
        cpt++;
      if (m_subflows[i]->m_state == TIME_WAIT)
        {
          NS_LOG_INFO("("<< (int)m_subflows[i]->m_routeId<< ") "<< TcpStateName[m_subflows[i]->state] << " -> CLOSED {CloseMultipathConnection}");
          m_subflows[i]->state = CLOSED;
          cpt++;
        }
    }
  if (cpt == m_subflows.size())
    {
      // We could remove client ... it should work but it generate plots for receiver as well.
//      if (m_state == ESTABLISHED && client)
      if (m_state == ESTABLISHED )
        {
          NS_LOG_INFO("CloseMultipathConnection -> GENERATE PLOTS SUCCESSFULLY -> HoOoOrA  pAck: "
//              << pAck
              );
          //GenerateRTTPlot();
          // TODO remove, should be done on per
          GenerateCWNDPlot();
          GenerateSendvsACK();
          GenerateRTT();
          GenerateCwndTracer();
          GeneratePktCount();
          generatePlots();
        }
      if (m_state != CLOSED)
        {
          NS_LOG_INFO("CloseMultipathConnection -> MPTCP connection is closed {" << this << "}, m_state: " << TcpStateName[m_state] << " -> CLOSED" << " CurrentSubflow (" << (int)m_currentSublow << ") SubflowsSize: " <<m_subflows.size());
          m_state = CLOSED;
          NotifyNormalClose();
          m_endPoint->SetDestroyCallback(MakeNullCallback<void>()); // Remove callback to destroy()
          m_tcp->DeAllocate(m_endPoint);                          // Deallocating the endPoint
          if (m_subflows.size() > 0)
            m_subflows[0]->m_endPoint = 0;
          m_endPoint = 0;
          std::vector<Ptr<TcpSocketBase> >::iterator it = std::find(m_tcp->m_sockets.begin(), m_tcp->m_sockets.end(), this);
          if (it != m_tcp->m_sockets.end())
            {
              m_tcp->m_sockets.erase(it);
            }
          CancelAllSubflowTimers();
        }
    }
  return closed;
}
#endif

//same as parent ? remove ?
bool
MpTcpSocketBase::IsThereRoute(Ipv4Address src, Ipv4Address dst)
{
  NS_LOG_FUNCTION(this << src << dst);
  bool found = false;
  // Look up the source address
//  Ptr<Ipv4> ipv4 = m_node->GetObject<Ipv4>();
  Ptr<Ipv4L3Protocol> ipv4 = GetNode()->GetObject<Ipv4L3Protocol>();
  if (ipv4->GetRoutingProtocol() != 0)
    {
      Ipv4Header l3Header;
      Socket::SocketErrno errno_;
      Ptr<Ipv4Route> route;
      //.....................................................................................
      //NS_LOG_INFO("----------------------------------------------------");NS_LOG_INFO("IsThereRoute() -> src: " << src << " dst: " << dst);
      // Get interface number from IPv4Address via ns3::Ipv4::GetInterfaceForAddress(Ipv4Address address);
      int32_t interface = ipv4->GetInterfaceForAddress(src);        // Morteza uses sign integers
      Ptr<Ipv4Interface> v4Interface = ipv4->GetRealInterfaceForAddress(src);
      Ptr<NetDevice> v4NetDevice = v4Interface->GetDevice();

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
          NS_LOG_DEBUG (" -> Route from src "<< src << " to dst " << dst << " oit ["<< oif->GetIfIndex()<<"], exist  Gateway: " << route->GetGateway());
          found = true;
        }
      else
        NS_LOG_DEBUG (" -> No Route from srcAddr "<< src << " to dstAddr " << dst << " oit ["<<oif->GetIfIndex()<<"], exist Gateway: " << route->GetGateway());
    }//NS_LOG_INFO("----------------------------------------------------");
  return found;
}

//void
//MpTcpSocketBase::PrintIpv4AddressFromIpv4Interface(Ptr<Ipv4Interface> interface, int32_t indexOfInterface)
//{
//  NS_LOG_FUNCTION_NOARGS();
//
//  for (uint32_t i = 0; i < interface->GetNAddresses(); i++)
//    {
//
//      NS_LOG_INFO("Node(" << interface->GetDevice()->GetNode()->GetId() << ") Interface(" << indexOfInterface << ") Ipv4Index(" << i << ")" << " Ipv4Address(" << interface->GetAddress(i).GetLocal()<< ")");
//
//    }
//}

/**
Used many times, may be worth registering the NetDevice in a subflow member ?
**/
Ptr<NetDevice>
MpTcpSocketBase::FindOutputNetDevice(Ipv4Address src)
{

  Ptr<Ipv4L3Protocol> ipv4 = GetNode()->GetObject<Ipv4L3Protocol>();
  uint32_t oInterface = ipv4->GetInterfaceForAddress(src);
//  Ptr<Ipv4Interface> GetRealInterfaceForAddress()
  Ptr<NetDevice> oNetDevice = ipv4->GetNetDevice(oInterface);

//  Ptr<Ipv4Interface> interface = ipv4->GetRealInterfaceForAddress(src);
//  Ptr<NetDevice> netDevice = interface->GetDevice();
//  NS_ASSERT(netDevice == oNetDevice);
  //NS_LOG_INFO("FindNetDevice -> Src: " << src << " NIC: " << netDevice->GetAddress());
  return oNetDevice;
}


/**
TODO
**/
bool
MpTcpSocketBase::IsLocalAddress(Ipv4Address addr)
{
  NS_LOG_ERROR(this << "IsLocalAddressd" << addr);


  bool found = false;

//  MpTcpAddressInfo * pAddrInfo;
//  for (uint32_t i = 0; i < m_localAddrs.size(); i++)
//    {
//      pAddrInfo = m_localAddrs[i];
//      if (pAddrInfo->ipv4Addr == addr)
//        {
//          found = true;
//          break;
//        }
//    }
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
//      m_localAddrs.insert(m_localAddrs.end(), addrInfo);
//    }
//}

// const
uint32_t
MpTcpSocketBase::BytesInFlight()
{
  NS_LOG_FUNCTION(this << "test");
  uint32_t total = 0;
  for( SubflowList::const_iterator it = m_subflows.begin(); it != m_subflows.end(); it++ )
  {
    total += (*it)->BytesInFlight();
  }

//  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
//  return sFlow->maxSeqNb - sFlow->highestAck;        //m_highTxMark - m_highestRxAck;
  return total;
}

// TODO buggy ?
uint16_t
MpTcpSocketBase::AdvertisedWindowSize()
{
  NS_LOG_FUNCTION(this);
  return TcpSocketBase::AdvertisedWindowSize();
}

#if 0
// TODO remove
uint32_t
MpTcpSocketBase::AvailableWindow(uint8_t sFlowIdx)
{
  NS_LOG_FUNCTION_NOARGS ();

  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
  uint32_t window = std::min(remoteRecvWnd, sFlow->cwnd.Get());
  uint32_t unAcked = (sFlow->TxSeqNumber - (sFlow->highestAck + 1));
  uint32_t freeCWND = (window < unAcked) ? 0 : (window - unAcked);
  if (
    (freeCWND < sFlow->GetSegSize() )
    && (m_sendingBuffer->PendingData() >= sFlow->GetSegSize() )
    )
    {
      NS_LOG_WARN("AvailableWindow: ("<< (int)sFlowIdx <<") -> " << freeCWND << " => 0" << " MSS: " << sFlow->GetSegSize() );
      return 0;
    }
  else
    {
      NS_LOG_WARN("AvailableWindow: ("<< (int)sFlowIdx <<") -> " << freeCWND );
      return freeCWND;
    }
}
#endif

// TODO use also a TcpTxBuffer ? MpTcpTxBuffer ?
//uint32_t
//MpTcpSocketBase::GetTxAvailable()
//{
//  NS_LOG_FUNCTION_NOARGS();
//  return m_sendingBuffer->FreeSpaceSize();
//}



// should not be needed since this class does not do demultiplexing anymore
#if 0
uint8_t
MpTcpSocketBase::LookupByAddrs(Ipv4Address src, Ipv4Address dst)
{
  NS_LOG_FUNCTION(this);
  Ptr<MpTcpSubFlow> sFlow = 0;
  uint8_t sFlowIdx = 42;

  if (IsThereRoute(src, dst) == false)
    {
      NS_LOG_INFO(" -> NO ROUTE between (src,dst) = (" <<src << "," << dst << ")");
      // TODO use iterators
      for (uint32_t i = 0; i < m_subflows.size(); i++)
        {
          NS_LOG_INFO(" -> (" << i <<") -> src: " << m_subflows[i]->sAddr << " dst: " << m_subflows[i]->dAddr);
          NS_FATAL_ERROR(
              this << " There should be an issue with your path configuration; make sure there is a route from your source to destination");
        }
    }

  for (uint8_t i = 0; i < m_subflows.size(); i++)
    {
      sFlow = m_subflows[i];
      // on address can only participate to a one subflow, so we can find that subflow by unsing the source address or the destination, but the destination address is the correct one, so use it
      if ((sFlow->sAddr == src && sFlow->dAddr == dst))
        {
          sFlowIdx = i;
          break;
        }
    }
  // When subflow is not find or is not exist...
//  if (!(sFlowIdx < m_maxSubflows))
  if (!(sFlowIdx < GetNSubflows()))
    {
      NS_LOG_DEBUG(" -> Either subflow(0) or create new one");
      if (m_connected == false && m_subflows.size() == 1)
        {
          sFlowIdx = 0;
          NS_FATAL_ERROR("This is not a bug! BUT I don't see any reason to triger this condition currently");
        }
      else
        {
          //(IsLocalAddress(m_localAddress)
          // TODO check address is ours ?
          if (true)
            {
              NS_ASSERT(server);
              // Sender would create its new subflow when SYN with MP_JOIN being sent.
              sFlowIdx = m_subflows.size();
              Ptr<MpTcpSubFlow> sFlow = CreateObject<MpTcpSubFlow>(this);
              sFlow->m_routeId = m_subflows[m_subflows.size() - 1]->m_routeId + 1;
              sFlow->dAddr = m_remoteAddress;
              sFlow->m_dPort = m_remotePort;
              sFlow->sAddr = m_localAddress;
              sFlow->sPort = m_localPort;
              sFlow->SetSegSize(m_segmentSize);
              sFlow->cwnd = sFlow->GetSegSize();
              sFlow->state = LISTEN;
              sFlow->m_cnCount = sFlow->m_cnRetries;
              sFlow->m_endPoint = m_tcp->Allocate(sFlow->sAddr, sFlow->sPort, sFlow->dAddr, sFlow->m_dPort);
              if (sFlow->m_endPoint == 0)
                return -1;
              sFlow->m_endPoint->SetRxCallback(MakeCallback(&MpTcpSocketBase::ForwardUp, Ptr<MpTcpSocketBase>(this)));
              //sFlow->m_endPoint->SetDestroyCallback(MakeCallback(&MpTcpSocketBase::Destroy, Ptr<MpTcpSocketBase>(this)));
              m_subflows.insert(m_subflows.end(), sFlow);
              NS_LOG_INFO(" -> Subflow(" << (int) sFlowIdx <<") has created its (src,dst) = (" << sFlow->sAddr << "," << sFlow->dAddr << ")" );
            }
          else
            {
              NS_FATAL_ERROR(
                  "This normally would not occurs since MPTCP connection can have subflow only when two sides advertise their addresses!");
            }
        }
    }
  NS_LOG_DEBUG(" -> TotalSubflows{" << GetNSubflows() <<"} (src,dst) = (" << src << "," << dst << "). Forwarded to (" << (int) sFlowIdx << ")");
  return sFlowIdx;
}
#endif


//const
uint32_t
MpTcpSocketBase::CalculateTotalCWND()
{
  uint32_t totalCwnd = 0;
  for (uint32_t i = 0; i < m_subflows.size(); i++)
    {
      // fast recovery
      if (m_subflows[i]->m_inFastRec)
        totalCwnd += m_subflows[i]->GetSSThresh();
      else
        totalCwnd += m_subflows[i]->m_cWnd.Get();          // Should be this all the time
    }

    return totalCwnd;
}

#if 0
void
MpTcpSocketBase::OpenCWND(uint8_t sFlowIdx, uint32_t ackedBytes)
{
  NS_LOG_FUNCTION(this << (int) sFlowIdx << ackedBytes);
  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];

//  double adder = 0;
  uint32_t cwnd = sFlow->cwnd.Get();
  uint32_t ssthresh = sFlow->GetSSThresh();

  int MSS = sFlow->GetSegSize();


//  calculateTotalCWND();

  // Here we assume all CC react the same
  // ideally that should change but owuld need a revision in ns3 CC
  if (cwnd < ssthresh)
    {
      sFlow->cwnd += MSS;

//      // Plotting
//      sFlow->ssthreshtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->GetSSThresh() ));
//      sFlow->CWNDtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd));
//      totalCWNDtrack.push_back(make_pair(Simulator::Now().GetSeconds(), m_totalCwnd));
      sFlow->_ss.push_back(make_pair(Simulator::Now().GetSeconds(), TimeScale));
      NS_LOG_WARN ("Congestion Control (Slow Start) increment by one m_segmentSize");
    }
  else
    {
//      switch (AlgoCC)
//        {
//    /* dunno that one */
//      case RTT_Compensator:
//        calculateAlpha(); // Calculate alpha per drop or RTT...RFC 6356 (Section 4.1)
//        adder = std::min(alpha * MSS * MSS / m_totalCwnd, static_cast<double>(MSS * MSS) / cwnd);
//        adder = std::max(1.0, adder);
//        sFlow->cwnd += static_cast<double>(adder);
//
//
//        NS_LOG_ERROR ("Congestion Control (RTT_Compensator): alpha "<<alpha
//                    <<" ackedBytes (" << ackedBytes
//                    << ") m_totalCwnd ("<< m_totalCwnd / sFlow->GetSegSize()
//                    <<" packets) -> increment is "<<adder
//                    << " cwnd: " << sFlow->cwnd
//                    );
//        break;
//
//      case Linked_Increases:
//        calculateAlpha();
//        adder = alpha * MSS * MSS / m_totalCwnd;
//        adder = std::max(1.0, adder);
//        sFlow->cwnd += static_cast<double>(adder);
//
//        NS_LOG_ERROR ("Subflow "
//                <<(int)sFlowIdx
//                <<" Congestion Control (Linked_Increases): alpha "<<alpha
//                <<" increment is "<<adder
//                <<" GetSSThresh() "<< GetSSThresh()
//                << " cwnd "<<cwnd );
//        break;
//
//      case Uncoupled_TCPs:
//        adder = static_cast<double>(MSS * MSS) / cwnd;
//        adder = std::max(1.0, adder);
//        sFlow->cwnd += static_cast<double>(adder);
//        NS_LOG_WARN ("Subflow "<<(int)sFlowIdx<<" Congestion Control (Uncoupled_TCPs) increment is "<<adder<<" GetSSThresh() "<< GetSSThresh() << " cwnd "<<cwnd);
//        break;
//
//
//      default:
//        NS_ASSERT(3!=3);
//        break;
//        }
      sFlow->_ca.push_back(make_pair(Simulator::Now().GetSeconds(), TimeScale));
    }

//   NS_LOG_WARN ("Subflow "<<(int)sFlowIdx<<" Congestion Control (Uncoupled_TCPs) increment is "<<adder<<" GetSSThresh() "<< GetSSThresh() << " cwnd "<<cwnd);
    // Plotting
    sFlow->ssthreshtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->GetSSThresh()));
    sFlow->CWNDtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd));
//    totalCWNDtrack.push_back(make_pair(Simulator::Now().GetSeconds(), m_totalCwnd));

}
#endif

//void
//MpTcpSocketBase::calculateAlpha()
//{
//  // this method is called whenever a congestion happen in order to regulate the agressivety of m_subflows
//  // alpha = cwnd_total * MAX(cwnd_i / rtt_i^2) / {SUM(cwnd_i / rtt_i))^2}   //RFC 6356 formula (2)
//
//  NS_LOG_FUNCTION_NOARGS ();
//  alpha = 0;
//  double maxi = 0;
//  double sumi = 0;
//
//  for (uint32_t i = 0; i < m_subflows.size(); i++)
//    {
//      Ptr<MpTcpSubFlow> sFlow = m_subflows[i];
//
//      Time time = sFlow->rtt->GetCurrentEstimate();
//      double rtt = time.GetSeconds();
//      double tmpi = sFlow->cwnd.Get() / (rtt * rtt);
//      if (maxi < tmpi)
//        maxi = tmpi;
//
//      sumi += sFlow->cwnd.Get() / rtt;
//    }
//  alpha = (m_totalCwnd * maxi) / (sumi * sumi);
//}

//void
//MpTcpSocketBase::calculateSmoothedCWND(uint8_t sFlowIdx)
//{
//  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
//  if (sFlow->scwnd < sFlow->MSS)
//    sFlow->scwnd = sFlow->cwnd;
//  else
//    sFlow->scwnd = sFlow->scwnd * 0.875 + sFlow->cwnd * 0.125;
//}

//void
//MpTcpSocketBase::DestroySubflowMapDSN()
//{
//  NS_LOG_FUNCTION_NOARGS();
//  for (uint32_t i = 0; i < m_subflows.size(); i++)
//    {
//      Ptr<MpTcpSubFlow> sFlow = m_subflows[i];
//      for (std::list<DSNMapping *>::iterator i = sFlow->m_mapDSN.begin(); i != sFlow->m_mapDSN.end(); i++)
//        {
//          i = sFlow->m_mapDSN.erase(i);
//        }
//      sFlow->m_mapDSN.clear();
//    }
//}

// Why that ? socket should not be closed unless  everything
//void
//MpTcpSocketBase::DestroyUnOrdered()
//{
//  NS_LOG_FUNCTION_NOARGS();
//  for (std::list<DSNMapping*>::iterator i = m_unOrdered.begin(); i != m_unOrdered.end(); i++)
//    {
//      i = m_unOrdered.erase(i);
//    }
//  m_unOrdered.clear();
//}

/** Kill this socket. This is a callback function configured to m_endpoint in
 SetupCallback(), invoked when the endpoint is destroyed. */
//void
//MpTcpSocketBase::Destroy(void)
//{
//  NS_LOG_FUNCTION(this);NS_LOG_INFO("Enter Destroy(" << this << ") m_sockets:  " << m_tcp->m_sockets.size()<< ")");
//  m_endPoint = 0;
//  if (m_tcp != 0)
//    {
//      std::vector<Ptr<TcpSocketBase> >::iterator it = std::find(m_tcp->m_sockets.begin(), m_tcp->m_sockets.end(), this);
//      if (it != m_tcp->m_sockets.end())
//        {
//          m_tcp->m_sockets.erase(it);
//        }
//    }
//  CancelAllSubflowTimers();
//  NS_LOG_INFO("Leave Destroy(" << this << ") m_sockets:  " << m_tcp->m_sockets.size()<< ")");
//}

/** Deallocate the end point and cancel all the timers */
//void
//MpTcpSocketBase::DeallocateEndPoint(uint8_t sFlowIdx)
//{
//  NS_LOG_FUNCTION(this << (int) sFlowIdx);
//  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
//  // Master subflow would be closed when all other slave's subflows are closed.
//  if (sFlowIdx == 0)
//    {
//      NS_LOG_INFO( "("<< (int)sFlowIdx<< ") DeallocateEndPoint -> Master Subflow want to deallocate its endpoint, call on CloseMultipathConnection()");
//      CloseMultipathConnection();
//    }
//  // Slave's subflows
//  else
//    {
//      if (sFlow->m_endPoint != 0)
//        {
//          NS_LOG_INFO("Salve subflow ("<< (int)sFlowIdx << ") is deallocated its endpoint");
//          sFlow->m_endPoint->SetDestroyCallback(MakeNullCallback<void>());
//          m_tcp->DeAllocate(sFlow->m_endPoint);
//          sFlow->m_endPoint = 0;
//          CancelAllTimers(sFlowIdx);
//        }
//    }
//}

//Ptr<MpTcpSubFlow>
//MpTcpSocketBase::GetSubflow(uint8_t sFlowIdx)
//{
//  return m_subflows[sFlowIdx];
//}
//
//void
//MpTcpSocketBase::SetCongestionCtrlAlgo(Ptr<MpTcpCongestionControl> ccalgo)
//{
////  AlgoCC = ccalgo;
//  NS_ASSERT( ccalgo);
//
//  // TODO change connection should not have started
//  NS_ASSERT_MSG( m_state != CLOSED  , "test" );
//  m_algoCC = ccalgo;
//}


//DSNMapping*
//MpTcpSocketBase::getAckedSegment(uint64_t lEdge, uint64_t rEdge)
//{
//  for (uint8_t i = 0; i < m_subflows.size(); i++)
//    {
//      Ptr<MpTcpSubFlow> sFlow = m_subflows[i];
//      for (list<DSNMapping *>::iterator it = sFlow->m_mapDSN.begin(); it != sFlow->m_mapDSN.end(); ++it)
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
//void
//MpTcpSocketBase::getQueuePkt(Ipv4Address addr)
//{
//  Ptr<Ipv4L3Protocol> l3Protocol = m_node->GetObject<Ipv4L3Protocol>();
//  Ptr<Ipv4Interface> ipv4If = l3Protocol->GetInterface(l3Protocol->GetInterfaceForAddress(addr));
//  Ptr<NetDevice> net0 = ipv4If->GetDevice();
//  PointerValue ptr;
//  net0->GetAttribute("TxQueue", ptr);
//  Ptr<Queue> txQueue = ptr.Get<Queue>();
//  TxQueue.push_back(make_pair(Simulator::Now().GetSeconds(), txQueue->GetNPackets()));
//}

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
//  for (uint32_t i = 0; i < m_subflows.size(); i++)
//    {
//      Ptr<MpTcpSubFlow> sFlow = m_subflows[i];
//      gThroughput += (sFlow->cwnd * sFlow->MSS * 8) / ((sFlow->rtt->GetCurrentEstimate()).GetSeconds());
//    }
//  return gThroughput;
//}

//double
//MpTcpSocketBase::getConnectionEfficiency()
//{
//  double gThroughput = 0.0;
//  uint64_t gBandwidth = 0;
//  for (uint32_t i = 0; i < m_subflows.size(); i++)
//    {
//      Ptr<MpTcpSubFlow> sFlow = m_subflows[i];
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
