/*
 * MultiPath-TCP (MPTCP) implementation.
 * Programmed by :
 *  - Matthieu Coudron (Université Pierre et Marie Curie - Paris)
 *  - Morteza Kheirkhah from University of Sussex.
 * Some codes here are modeled from ns3::TCPNewReno implementation.
 * Email: m.kheirkhah@sussex.ac.uk
 * matthieu.coudron@lip6.fr
 */
#undef NS_LOG_APPEND_CONTEXT
#define NS_LOG_APPEND_CONTEXT \
  if (m_node) { std::clog << Simulator::Now ().GetSeconds () << " [node " << m_node->GetId () << ": ] "; }
//<< TcpStateName[m_node->GetTcp()->GetState()] <<

#include <iostream>
#include <cmath>
#include "ns3/mp-tcp-typedefs.h"
#include "ns3/simulator.h"
#include "ns3/log.h"
#include "ns3/abort.h"
#include "ns3/mp-tcp-subflow.h"
#include "ns3/mp-tcp-socket-base.h"
#include "ns3/tcp-l4-protocol.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv4-end-point.h"
#include "ipv6-end-point.h" // it is not exported in ns3.19
#include "ns3/node.h"
#include "ns3/ptr.h"
#include "ns3/tcp-option-mptcp.h"
#include "ns3/mp-tcp-id-manager.h"
//#include "ns3/ipv4-address.h"
#include "ns3/trace-helper.h"

#include <openssl/sha.h>

NS_LOG_COMPONENT_DEFINE("MpTcpSubflow");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED(MpTcpSubFlow);

TypeId
MpTcpSubFlow::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::MpTcpSubFlow")
      .SetParent<TcpSocketBase>()
//      .AddConstructor<MpTcpSubFlow>()
      // TODO should be inherited
      .AddTraceSource("CongestionWindow",
          "The congestion control window to trace.",
           MakeTraceSourceAccessor(&MpTcpSubFlow::m_cWnd))
    ;
  return tid;
}





//TypeId
//MpTcpSubFlow::GetInstanceTypeId(void) const
//{
//  return GetTypeId();
//}

//bool
void
MpTcpSubFlow::SetMeta(Ptr<MpTcpSocketBase> metaSocket)
{
  NS_ASSERT(metaSocket);
  NS_ASSERT(m_state == CLOSED);
  NS_LOG_FUNCTION(this);
  m_metaSocket = metaSocket;

  // kinda hackish
  m_TxMappings.m_txBuffer = &m_txBuffer;
  m_RxMappings.m_rxBuffer = &m_rxBuffer;

//  return true;
}

void
MpTcpSubFlow::DumpInfo() const
{
      NS_LOG_LOGIC ("MpTcpSubFlow " << this << " SendPendingData" <<
//          " w " << w <<
          " rxwin " << m_rWnd <<
          " segsize " << m_segmentSize <<
          " nextTxSeq " << m_nextTxSequence <<
          " highestRxAck " << m_txBuffer.HeadSequence () <<
          " pd->Size " << m_txBuffer.Size () <<
          " pd->SFS " << m_txBuffer.SizeFromSequence (m_nextTxSequence)
          );
}

Ptr<TcpSocketBase>
MpTcpSubFlow::Fork(void)
{
  // Call CopyObject<> to clone me
//  NS_LOG_ERROR("Not implemented");


  return ForkAsSubflow();
}

//Ptr<MpTcpSubFlow>
//MpTcpSubFlow::ForkAsSubflow(void)
//{
//  return CopyObject<MpTcpSubFlow> (this);
//}

/* */
void
MpTcpSubFlow::DupAck(const TcpHeader& t, uint32_t count)
{
  NS_LOG_DEBUG("DupAck ignored as specified in RFC");
//  if( count > 3)
  GetMeta()->OnSubflowDupAck(this);
}


// TODO check with parent's
void
MpTcpSubFlow::CancelAllTimers()
{
  NS_LOG_FUNCTION(this);
  //(int) sFlowIdx
  m_retxEvent.Cancel();
  m_lastAckEvent.Cancel();
  m_timewaitEvent.Cancel();
  NS_LOG_LOGIC( "CancelAllTimers");
}



void
MpTcpSubFlow::SetSSThresh(uint32_t threshold)
{
  m_ssThresh = threshold;
}


uint32_t
MpTcpSubFlow::GetSSThresh(void) const
{
  return m_ssThresh;
}


void
MpTcpSubFlow::SetInitialCwnd(uint32_t cwnd)
{
  NS_ABORT_MSG_UNLESS(m_state == CLOSED, "MpTcpsocketBase::SetInitialCwnd() cannot change initial cwnd after connection started.");
  m_initialCWnd = cwnd;
}

uint32_t
MpTcpSubFlow::GetInitialCwnd(void) const
{
  return m_initialCWnd;
}


// Ideally this should be a sha1 but hey ns3 is for prototyping !
//uint32_t
//MpTcpSubFlow::GetLocalToken() const
//{
////  NS_LOG_ERROR("Not implemented yet");
//  // TODO
//  return GetMeta()->GetLocalKey() >> 32 ;
//}
//
//uint32_t
//MpTcpSubFlow::GetRemoteToken() const
//{
////  NS_LOG_ERROR("Not implemented yet");
//  return GetMeta()->GetLocalKey() >> 32 ;
//
//}




//int
//MpTcpSubFlow::Connect(const Address & address)
//{
//  NS_LOG_FUNCTION (this << address);
//  return TcpSocketBase::Connect
//}
#if 0
void
MpTcpSubFlow::SendEmptyPacket(TcpHeader& header)
{
  if (flags & TcpHeader::SYN && flags & TcpHeader::ACK)
  {
    //
    NS_ASSERT(m_state == SYN_RCVD);
  }
  else if (flags == TcpHeader::SYN )
  {
    // Add an MP_CAPABLE or MP_JOIN option
    // is possible in SYN_RCVD if peer did not receive ack of 3WHS
    NS_ASSERT(m_state == LISTEN || m_state == SYN_RCVD);
      if( IsMaster() )
      {
        Ptr<TcpOptionMpTcpCapable> mpc =  CreateObject<TcpOptionMpTcpCapable>();
        mpc->SetSenderKey( m_metaSocket->GetLocalKey() );
        header.AppendOption( mpc );
      }
      else
      {
        // Join option InitialSyn
        Ptr<TcpOptionMpTcpJoin> join =  CreateObject<TcpOptionMpTcpJoin>();
        //TODO retrieve from meta
//        join->SetLocalToken(0);
        join->SetState(TcpOptionMpTcpJoin::Syn);
        join->SetPeerToken(0);
        join->SetNonce(0);
//        join->SetAddressId(0);
//        join->set
        header.AppendOption( join );
      }
  }
  // Quand on ferme la connexion qu'arrive-t'il ?
//  else if(m_state == SYN_SENT )
//  {
//
//  }
//  else if(m_state == SYN_SENT )
//  {
//
//  }

  Ptr<Packet> p = Create<Packet>();
  SendPacket(header, p );


//  header.SetWindowSize(AdvertisedWindowSize());
}
#endif


TcpStates_t
MpTcpSubFlow::GetState() const
{
  //!
  return m_state;
}


int
MpTcpSubFlow::DoConnect()
{
  NS_LOG_FUNCTION (this);


  // A new connection is allowed only if this socket does not have a connection
  if (m_state == CLOSED || m_state == LISTEN || m_state == SYN_SENT || m_state == LAST_ACK || m_state == CLOSE_WAIT)
    { // send a SYN packet and change state into SYN_SENT
      TcpHeader header;
      GenerateEmptyPacketHeader(header,TcpHeader::SYN);

      // code moved inside SendEmptyPacket
      InitializeCwnd ();
      AppendMpTcp3WHSOption(header);

      TcpSocketBase::SendEmptyPacket(header);
//      NS_ASSERT( header.)
      NS_LOG_INFO (TcpStateName[m_state] << " -> SYN_SENT");
      m_state = SYN_SENT;
    }
  else if (m_state != TIME_WAIT)
  { // In states SYN_RCVD, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, and CLOSING, an connection
    // exists. We send RST, tear down everything, and close this socket.
    SendRST();
    CloseAndNotify();
  }
  return 0;
}


/** Inherit from Socket class: Kill this socket and signal the peer (if any) */
int
MpTcpSubFlow::Close(void)
{
  NS_LOG_FUNCTION (this);
  // First we check to see if there is any unread rx data
  // Bug number 426 claims we should send reset in this case.

  if (m_rxBuffer.Size() != 0)
    {
      SendRST();
      return 0;
    }

  //
//  if( GetMeta()->GetNClosingSubflows() )
//  {
//
//  }


  if (m_txBuffer.SizeFromSequence(m_nextTxSequence) > 0)
    { // App close with pending data must wait until all data transmitted
      if (m_closeOnEmpty == false)
        {
          m_closeOnEmpty = true;
          NS_LOG_INFO ("Socket " << this << " deferring close, state " << TcpStateName[m_state]);
        }
      return 0;
    }
  return DoClose();
}



// Does this constructor even make sense ? no ? to remove ?
MpTcpSubFlow::MpTcpSubFlow(const MpTcpSubFlow& sock)
  : TcpSocketBase(sock),
  m_cWnd(sock.m_cWnd),
  m_ssThresh(sock.m_ssThresh),
  m_initialCWnd (sock.m_initialCWnd),
  m_localNonce(sock.m_localNonce),
  m_remoteToken(sock.m_remoteToken)
  // TODO

//    m_retxThresh (sock.m_retxThresh),
//    m_inFastRec (false),
//    m_limitedTx (sock.m_limitedTx)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_LOGIC ("Invoked the copy constructor");
}

MpTcpSubFlow::MpTcpSubFlow(
//Ptr<MpTcpSocketBase> metaSocket
//, bool master
) :
    TcpSocketBase(),
    m_routeId(0),
    m_ssThresh(65535),
    m_initialCWnd(10),
//    m_mapDSN(0),
    m_lastMeasuredRtt(Seconds(0.0)),
     // TODO move out to MpTcpCControl


//    m_metaSocket(metaSocket),
    m_backupSubflow(false),
    m_localNonce(0),
    m_remoteToken(0)
{
  NS_LOG_FUNCTION(this);

  // TODO use/create function to generate initial random number seq
//  TxSeqNumber = rand() % 1000;
//  RxSeqNumber = 0;

// Set up by factory no ?
//  rtt = CreateObject<RttMeanDeviation>();
//  rtt->Gain(0.1);
//  Time estimate;
//  estimate = Seconds(1.5);
//  rtt->SetCurrentEstimate(estimate);
  m_cnRetries = 3;
  Time est = MilliSeconds(200);
  m_cnTimeout = est;
//  initialSequnceNumber = 0;
  m_retxThresh = 3; // TODO retrieve from meta
  m_inFastRec = false;
  m_limitedTx = false;
  m_dupAckCount = 0;
//  PktCount = 0;
  m_recover = SequenceNumber32(0);
  m_gotFin = false;
}

MpTcpSubFlow::~MpTcpSubFlow()
{
  NS_LOG_FUNCTION(this);
  //std::list<DSNMapping *>
//  for (MappingList::iterator it = m_mapDSN.begin(); it != m_mapDSN.end(); ++it)
//    {
//      DSNMapping * ptrDSN = *it;
//      delete ptrDSN;
//    }
//  m_mapDSN.clear();
}


void
MpTcpSubFlow::CloseAndNotify(void)
{
  //TODO
  TcpSocketBase::CloseAndNotify();
  GetMeta()->OnSubflowClosed( this );
}


/**
Maybe we could allow this providing a mapping already exists ?
**/
int
MpTcpSubFlow::Send(Ptr<Packet> p, uint32_t flags)
{
  NS_FATAL_ERROR("Use sendmapping instead");
  return 0;
}

//, uint32_t maxSize
// rename globalSeqNb ?

void
MpTcpSubFlow::SendEmptyPacket(uint8_t flags)
{
  NS_LOG_FUNCTION(this << " flags" << flags);
  TcpSocketBase::SendEmptyPacket(flags);
}


void
MpTcpSubFlow::SendEmptyPacket(TcpHeader& header)
{
  NS_LOG_FUNCTION(this << header);
  TcpSocketBase::SendEmptyPacket(header);
}

/**
//! GetLength()
this fct asserts when the mapping length is 0 but in fact it can be possible
when there is an infinite mapping
**/
int
MpTcpSubFlow::SendMapping(Ptr<Packet> p, MpTcpMapping& mapping)
{
  NS_LOG_FUNCTION (this << mapping);
  NS_ASSERT(p);

  NS_ASSERT_MSG(mapping.GetLength() != 0,"Mapping should not be empty" );
  NS_ASSERT_MSG(mapping.GetLength() == p->GetSize(), "You should fill the mapping" );
  // backup its value because send will change it
  //SequenceNumber32 nextTxSeq = m_nextTxSequence;

  // Check m_txBuffer can handle it otherwise it will get refused

    // Everything went fine
  //if(res >= 0)
  //{*
  // TODO in fact there could be an overlap between recorded mappings and the current one
  // so the following check is not enough. To change later
  if(m_txBuffer.Available() < mapping.GetLength())
  {
    NS_LOG_ERROR("Too much data to send");
    return -ERROR_MSGSIZE;
  }


    //MpTcpMapping mapping;
    //mapping.Configure( mptcpSeq, p->GetSize()  );

  // In fact this must be mapped to the last unmapped value
//  NS_LOG_UNCOND("before mapping to ssn m_nextTxSequence [" << m_nextTxSequence << "]");
//  mapping.MapToSSN( m_nextTxSequence );

    // record mapping TODO check if it does not already exist
    // TODO GetMappingForDSN
    // GetMappingForSSN
  //GetMappingForSegment(m_TxMappings,)
  NS_ASSERT_MSG(m_TxMappings.AddMappingLooseSSN( mapping  ) >= 0,"2 mappings overlap");

  //}
  NS_LOG_DEBUG("mapped updated: " << mapping);

  int res = TcpSocketBase::Send(p,0);



  return res;
}



uint32_t
MpTcpSubFlow::SendDataPacket(SequenceNumber32 seq, uint32_t maxSize, bool withAck)
{
  //!
//  NS_LOG_FUNCTION (this << "seq" << seq << "with max size " << maxSize << "and ack"<< withAck);  //NS_LOG_INFO("SendDataPacket -> SeqNb: " << seq);
  TcpHeader header;

  GenerateEmptyPacketHeader(header, withAck ? TcpHeader::ACK : 0);

  return SendDataPacket( header, seq, maxSize);
}


// split into 2 functions 1 to GenerateHeaders, other one to add options
// ajouter une fct DoSend
uint32_t
MpTcpSubFlow::SendDataPacket(TcpHeader& header, const SequenceNumber32& ssn, uint32_t maxSize)
{
  NS_LOG_FUNCTION(this << "Sending SSN [" << ssn.GetValue() << "]");

  MpTcpMapping mapping;
  bool result = m_TxMappings.GetMappingForSSN( ssn, mapping);
  if(!result)
  {
    m_TxMappings.Dump();
    NS_FATAL_ERROR("Could not find mapping associated to ssn");
  }

//  // Add list to ListErrorModel object
//  Ptr<ListErrorModel> rem = CreateObject<ListErrorModel>();
//  rem->SetList(sampleList);

  // TODO use rather GetOrCreateOption(
  Ptr<TcpOptionMpTcpDSS> dsnOption = Create<TcpOptionMpTcpDSS>();

  // TODO don't send  mapping for every subsequent packet
    // Add DSN option
//  NS_LOG_DEBUG("Adding DSN option" << mapping);
  dsnOption->SetMapping( mapping );


//  NS_ASSERT( dsnOption->GetMapping().HeadSSN() )
  header.AppendOption( dsnOption );
//  }

  // check

  return TcpSocketBase::SendDataPacket(header, ssn, maxSize);
}


/*
behavior should be the same as in TcpSocketBase
TODO check if m_cWnd is

*/
void
MpTcpSubFlow::Retransmit(void)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_LOGIC (this << " ReTxTimeout Expired at time " << Simulator::Now ().GetSeconds ());
  m_inFastRec = false;

  // If erroneous timeout in closed/timed-wait state, just return
  if (m_state == CLOSED || m_state == TIME_WAIT) {
    NS_LOG_WARN("erroneous timeout");
    return;
  }
  // If all data are received (non-closing socket and nothing to send), just return
  if (m_state <= ESTABLISHED && m_txBuffer.HeadSequence () >= m_highTxMark) {
    NS_FATAL_ERROR("May be removed");
    return;
  }

  // According to RFC2581 sec.3.1, upon RTO, ssthresh is set to half of flight
  // size and cwnd is set to 1*MSS, then the lost packet is retransmitted and
  // TCP back to slow start
  m_ssThresh = std::max (2 * m_segmentSize, BytesInFlight () / 2);
  m_cWnd = m_segmentSize;
  m_nextTxSequence = m_txBuffer.HeadSequence (); // Restart from highest Ack
  NS_LOG_INFO ("RTO. " << m_rtt->RetransmitTimeout() << " Reset cwnd to " << m_cWnd <<
               ", ssthresh to " << m_ssThresh << ", restart from seqnum " << m_nextTxSequence);


  GetMeta()->OnSubflowRetransmit(this);

  m_rtt->IncreaseMultiplier ();             // Double the next RTO
  DoRetransmit ();                          // Retransmit the packet

//  TcpSocketBase::Retransmit();

//  NS_FATAL_ERROR("TODO retransmit");
  // pass on mapping


}

/**
Received a packet upon LISTEN state.

*/
void
MpTcpSubFlow::ProcessListen(Ptr<Packet> packet, const TcpHeader& tcpHeader, const Address& fromAddress, const Address& toAddress)
{
  NS_LOG_FUNCTION (this << tcpHeader);

  // Extract the flags. PSH and URG are not honoured.
  uint8_t tcpflags = tcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG);

  // Fork a socket if received a SYN. Do nothing otherwise.
  // C.f.: the LISTEN part in tcp_v4_do_rcv() in tcp_ipv4.c in Linux kernel
  if (tcpflags != TcpHeader::SYN)
    {
      return;
    }

  // Call socket's notify function to let the server app know we got a SYN
  // If the server app refuses the connection, do nothing
  if (!NotifyConnectionRequest(fromAddress))
    {
      return;
    }


  // Clone the socket, simulate fork
//  Ptr<MpTcpSubFlow> newSock = Fork();
  Ptr<MpTcpSubFlow> newSock = ForkAsSubflow();
  NS_LOG_LOGIC ("Cloned a TcpSocketBase " << newSock);
  // TODO TcpSocketBase::
  Simulator::ScheduleNow(&MpTcpSubFlow::CompleteFork, newSock, packet, tcpHeader, fromAddress, toAddress);
}

Ptr<MpTcpSocketBase>
MpTcpSubFlow::GetMeta() const
{
  NS_ASSERT(m_metaSocket);
  //!
  return m_metaSocket;
}



void
MpTcpSubFlow::ProcessEstablished(Ptr<Packet> packet, const TcpHeader& header)
{
  Ptr<TcpOptionMpTcpDSS> dss;

  //! TODO in the long term, I should rather loop over options and assign a callback ?
  if(GetMpTcpOption(header, dss))
  {
    ParseDSS(packet,header,dss);
  }

  TcpSocketBase::ProcessEstablished(packet,header);
}

/**
I ended up duplicating this code to update the meta r_Wnd, which would have been hackish otherwise

**/
void
MpTcpSubFlow::DoForwardUp(Ptr<Packet> packet, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface> incomingInterface)
{
  NS_LOG_FUNCTION(this);
  //m_rWnd = tcpHeader.GetWindowSize();


  NS_LOG_FUNCTION(this);

  NS_LOG_LOGIC ("Socket " << this << " forward up " <<
      m_endPoint->GetPeerAddress () <<
      ":" << m_endPoint->GetPeerPort () <<
      " to " << m_endPoint->GetLocalAddress () <<
      ":" << m_endPoint->GetLocalPort ());
  Address fromAddress = InetSocketAddress(header.GetSource(), port);
  Address toAddress = InetSocketAddress(header.GetDestination(), m_endPoint->GetLocalPort());

  //NS_LOG_INFO("Before: " << packet->GetSize());
  // Peel off TCP header and do validity checking
  TcpHeader tcpHeader;
  packet->RemoveHeader(tcpHeader);
  if (tcpHeader.GetFlags() & TcpHeader::ACK)
    {
      EstimateRtt(tcpHeader);
    }
  ReadOptions(tcpHeader);
  //NS_LOG_INFO("After cuttingHeader: " << packet->GetSize());
  // Update Rx window size, i.e. the flow control window
  if (m_rWnd.Get() == 0 && tcpHeader.GetWindowSize() != 0)
    { // persist probes end
      NS_LOG_LOGIC (this << " Leaving zerowindow persist state");
      m_persistEvent.Cancel();
    }

  m_rWnd = tcpHeader.GetWindowSize();
  GetMeta()->m_rWnd = tcpHeader.GetWindowSize();
  // Discard fully out of range data packets
  if (packet->GetSize() && OutOfRange(tcpHeader.GetSequenceNumber(), tcpHeader.GetSequenceNumber() + packet->GetSize()))
    {
      NS_LOG_LOGIC ("At state " << TcpStateName[m_state] <<
          " received packet of seq [" << tcpHeader.GetSequenceNumber () <<
          ":" << tcpHeader.GetSequenceNumber () + packet->GetSize () <<
          ") out of range [" << m_rxBuffer.NextRxSequence () << ":" <<
          m_rxBuffer.MaxRxSequence () << ")");
      // Acknowledgement should be sent for all unacceptable packets (RFC793, p.69)
      if (m_state == ESTABLISHED && !(tcpHeader.GetFlags() & TcpHeader::RST))
        {
          SendEmptyPacket(TcpHeader::ACK);
        }
      return;
    }

  // TCP state machine code in different process functions
  // C.f.: tcp_rcv_state_process() in tcp_input.c in Linux kernel
  switch (m_state)
    {
  case ESTABLISHED:
    ProcessEstablished(packet, tcpHeader);
    break;
  case LISTEN:
    ProcessListen(packet, tcpHeader, fromAddress, toAddress);
    break;
  case TIME_WAIT:
    // Do nothing
    break;
  case CLOSED:
    // Send RST if the incoming packet is not a RST
    if ((tcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG)) != TcpHeader::RST)
      { // Since m_endPoint is not configured yet, we cannot use SendRST here
        TcpHeader h;
        h.SetFlags(TcpHeader::RST);
        h.SetSequenceNumber(m_nextTxSequence);
        h.SetAckNumber(m_rxBuffer.NextRxSequence());
        h.SetSourcePort(tcpHeader.GetDestinationPort());
        h.SetDestinationPort(tcpHeader.GetSourcePort());
        h.SetWindowSize(AdvertisedWindowSize());
        AddOptions(h);
        m_tcp->SendPacket(Create<Packet>(), h, header.GetDestination(), header.GetSource(), m_boundnetdevice);
      }
    break;
  case SYN_SENT:
    ProcessSynSent(packet, tcpHeader);
    break;
  case SYN_RCVD:
    ProcessSynRcvd(packet, tcpHeader, fromAddress, toAddress);
    break;
  case FIN_WAIT_1:
  case FIN_WAIT_2:
  case CLOSE_WAIT:
    ProcessWait(packet, tcpHeader);
    break;
  case CLOSING:
    ProcessClosing(packet, tcpHeader);
    break;
  case LAST_ACK:
    ProcessLastAck(packet, tcpHeader);
    break;
  default: // mute compiler
    break;
    }

}
void
MpTcpSubFlow::ProcessClosing(Ptr<Packet> packet, const TcpHeader& tcpHeader)
{
  NS_LOG_FUNCTION (this << tcpHeader);

//  ProcessOptions()

  return TcpSocketBase::ProcessClosing(packet,tcpHeader);
}

/** Received a packet upon CLOSE_WAIT, FIN_WAIT_1, or FIN_WAIT_2 states */
void
MpTcpSubFlow::ProcessWait(Ptr<Packet> packet, const TcpHeader& tcpHeader)
{
  NS_LOG_FUNCTION (this << tcpHeader);

  Ptr<TcpOptionMpTcpDSS> dss;

  //! TODO in the long term, I should rather loop over options and assign a callback ?
  if(GetMpTcpOption(tcpHeader, dss))
  {
    ParseDSS(packet,tcpHeader,dss);
  }

  TcpSocketBase::ProcessWait(packet,tcpHeader);

}


void
MpTcpSubFlow::CompleteFork(Ptr<Packet> p, const TcpHeader& h, const Address& fromAddress, const Address& toAddress)
{
  NS_LOG_INFO( this << "Completing fork of MPTCP subflow");
  // Get port and address from peer (connecting host)
  // TODO upstream ns3 should assert that to and from Address are of the same kind

  if (InetSocketAddress::IsMatchingType(toAddress))
    {
      m_endPoint = m_tcp->Allocate(InetSocketAddress::ConvertFrom(toAddress).GetIpv4(),
          InetSocketAddress::ConvertFrom(toAddress).GetPort(), InetSocketAddress::ConvertFrom(fromAddress).GetIpv4(),
          InetSocketAddress::ConvertFrom(fromAddress).GetPort());
      m_endPoint6 = 0;
    }
  else if (Inet6SocketAddress::IsMatchingType(toAddress))
    {
      m_endPoint6 = m_tcp->Allocate6(Inet6SocketAddress::ConvertFrom(toAddress).GetIpv6(),
          Inet6SocketAddress::ConvertFrom(toAddress).GetPort(), Inet6SocketAddress::ConvertFrom(fromAddress).GetIpv6(),
          Inet6SocketAddress::ConvertFrom(fromAddress).GetPort());
      m_endPoint = 0;
    }

  m_tcp->m_sockets.push_back(this);
//  }

  // Change the cloned socket from LISTEN state to SYN_RCVD
  NS_LOG_INFO ( TcpStateName[m_state] << " -> SYN_RCVD");
  m_state = SYN_RCVD;
  m_cnCount = m_cnRetries;

  InitializeCwnd();

  SetupCallback();

  // TODO upload
  m_TxMappings.m_txBuffer = &m_txBuffer;
  m_RxMappings.m_rxBuffer = &m_rxBuffer;

  // Set the sequence number and send SYN+ACK
  m_rxBuffer.SetNextRxSequence(h.GetSequenceNumber() + SequenceNumber32(1));



  TcpHeader answerHeader;
  GenerateEmptyPacketHeader( answerHeader, TcpHeader::SYN | TcpHeader::ACK );

  m_masterSocket = true;  //!< Only for the master socket is completeFork called

  AppendMpTcp3WHSOption(answerHeader);

//  NS_ASSERT( answerHeader.HasOption(TcpOption::P))
  SendEmptyPacket(answerHeader);
}

Ptr<MpTcpPathIdManager>
MpTcpSubFlow::GetIdManager()
{
  return GetMeta()->m_remotePathIdManager;
}


void
MpTcpSubFlow::InitializeCwnd (void)
{
  NS_LOG_LOGIC(this << "InitialCWnd:" << m_initialCWnd << " SegmentSize:" << m_segmentSize);
  /*
   * Initialize congestion window, default to 1 MSS (RFC2001, sec.1) and must
   * not be larger than 2 MSS (RFC2581, sec.3.1). Both m_initiaCWnd and
   * m_segmentSize are set by the attribute system in ns3::TcpSocket.
   */
  m_cWnd = m_initialCWnd * m_segmentSize;
}


void
MpTcpSubFlow::ConnectionSucceeded(void)
{
  // TODO use SetConnectCallback
  // SetSubflowConnectCallback
  // Use callbacks on
  //!
  //if(IsMaster()Ķ
     //GetMeta()->NotifyConnectionSucceeded();
  m_connected = true;
  GetMeta()->OnSubflowEstablishment(this);
  TcpSocketBase::ConnectionSucceeded();
}

/** Received a packet upon SYN_SENT */
void
MpTcpSubFlow::ProcessSynSent(Ptr<Packet> packet, const TcpHeader& tcpHeader)
{
  NS_LOG_FUNCTION (this << tcpHeader);
  NS_ASSERT(m_state == SYN_SENT);

  // Extract the flags. PSH and URG are not honoured.
  uint8_t tcpflags = tcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG);

  if (tcpflags == 0)
    { // Bare data, accept it and move to ESTABLISHED state. This is not a normal behaviour. Remove this?
      NS_ASSERT(false);
//      NS_LOG_INFO ("SYN_SENT -> ESTABLISHED");
//      m_state = ESTABLISHED;
//      m_connected = true;
//      m_retxEvent.Cancel();
//      m_delAckCount = m_delAckMaxCount;
//      ReceivedData(packet, tcpHeader);
//      Simulator::ScheduleNow(&TcpSocketBase::ConnectionSucceeded, this);
    }
  else if (tcpflags == TcpHeader::ACK)
    { // Ignore ACK in SYN_SENT
    }
  else if (tcpflags == TcpHeader::SYN)
    {
      NS_FATAL_ERROR("Not supported at the moment");
      // Received SYN, move to SYN_RCVD state and respond with SYN+ACK
      // TODO
//      NS_LOG_INFO ("SYN_SENT -> SYN_RCVD");
//      m_state = SYN_RCVD;
//      m_cnCount = m_cnRetries;  //reset
//      m_rxBuffer.SetNextRxSequence(tcpHeader.GetSequenceNumber() + SequenceNumber32(1));
//      SendEmptyPacket(TcpHeader::SYN | TcpHeader::ACK);
    }
    else if (tcpflags == (TcpHeader::SYN | TcpHeader::ACK) &&
             (m_nextTxSequence + SequenceNumber32(1) == tcpHeader.GetAckNumber()))
    {

//      NS_LOG_INFO("Received a SYN/ACK as answer");

      //NS_ASSERT();
      // TODO overwrite so that it warns meta
      Simulator::ScheduleNow(&MpTcpSubFlow::ConnectionSucceeded, this);


      // check for option TODO fall back on TCP in that case
//      NS_ASSERT( tcpHeader.HasOption( TcpOption::MPTCP ) );



      // Check cryptographic materials
      if( IsMaster())
      {
        /**
        * Here is how the MPTCP 3WHS works:
        *  o  SYN (A->B): A's Key for this connection.
        *  o  SYN/ACK (B->A): B's Key for this connection.
        *  o  ACK (A->B): A's Key followed by B's Key.
        *
        */

        // Expect an MP_CAPABLE option
        Ptr<TcpOptionMpTcpCapable> mpcRcvd;
        NS_ASSERT_MSG( GetMpTcpOption(tcpHeader, mpcRcvd), "There must be an MP_CAPABLE option in the SYN Packet" );

        GetMeta()->SetPeerKey( mpcRcvd->GetSenderKey() );

      }
      else
      {
        /**
               |             |   SYN + MP_JOIN(Token-B, R-A)  |
               |             |------------------------------->|
               |             |<-------------------------------|
               |             | SYN/ACK + MP_JOIN(HMAC-B, R-B) |
               |             |                                |
               |             |     ACK + MP_JOIN(HMAC-A)      |
               |             |------------------------------->|
               |             |<-------------------------------|
               |             |             ACK                |

         HMAC-A = HMAC(Key=(Key-A+Key-B), Msg=(R-A+R-B))
         HMAC-B = HMAC(Key=(Key-B+Key-A), Msg=(R-B+R-A))
          */

        Ptr<TcpOptionMpTcpJoin> join;
        // TODO should be less restrictive in case there is a loss

        NS_ASSERT_MSG( GetMpTcpOption(tcpHeader, join), "There must be an MP_JOIN option in the SYN Packet" );
        NS_ASSERT_MSG( join && join->GetState() == TcpOptionMpTcpJoin::SynAck, "the MPTCP join option received is not of the expected 1 out of 3 MP_JOIN types." );

        // Here we should check the tokens
//        uint8_t buf[20] =
//        opt3->GetTruncatedHmac();


      }

      m_retxEvent.Cancel();
      m_rxBuffer.SetNextRxSequence(tcpHeader.GetSequenceNumber() + SequenceNumber32(1));
      m_highTxMark = ++m_nextTxSequence;
      m_txBuffer.SetHeadSequence(m_nextTxSequence);

      // TODO support IPv6
      GetIdManager()->AddRemoteAddr(0, m_endPoint->GetPeerAddress(), m_endPoint->GetPeerPort() );

      TcpHeader answerHeader;
      GenerateEmptyPacketHeader(answerHeader, TcpHeader::ACK);
      AppendMpTcp3WHSOption(answerHeader);

      NS_LOG_INFO ("SYN_SENT -> ESTABLISHED");
      m_state = ESTABLISHED;

      // TODO send ConnectionSucceeded or NotifyNewConnectionCreated ?
//      GetMeta()->OnSubflowEstablishment(this);
//      m_connected = true;





      // TODO here we send a packet  with wrong seq number
      // and another ack will be emitted just after
      SendEmptyPacket(answerHeader);

      NS_LOG_UNCOND("m_nextTxSequence [" << m_nextTxSequence << "]");

      // TODO check if that's ok
      fLowStartTime = Simulator::Now().GetSeconds();

      // TODO check we can send rightaway data ?
      SendPendingData(m_connected);

      NS_LOG_UNCOND("m_nextTxSequence [" << m_nextTxSequence << "]");

      // Always respond to first data packet to speed up the connection.
      // Remove to get the behaviour of old NS-3 code.
      m_delAckCount = m_delAckMaxCount;
      initialSeqNb = tcpHeader.GetAckNumber().GetValue();
      //sampleList.push_back(8);
      //sampleList.push_back(15);
      NS_LOG_INFO("initialSeqNb: " << initialSeqNb);
    }
  else
    { // Other in-sequence input
      if (tcpflags != TcpHeader::RST)
        { // When (1) rx of FIN+ACK; (2) rx of FIN; (3) rx of bad flags
          NS_LOG_LOGIC ("Illegal flag " << std::hex << static_cast<uint32_t> (tcpflags) << std::dec << " received. Reset packet is sent.");
          SendRST();
        }
      CloseAndNotify();
    }
}


//void
//MpTcpSubFlow::SendEmptyPacket(TcpHeader& header)
//{
//  // Automatically append DSS
//  if(header.GetFlags() & TcpHeader::ACK)
//  {
//
//  }
//}


//TcpOptionMpTcpJoin::State
// TODO move to meta and adapt meta state
void
MpTcpSubFlow::AppendMpTcp3WHSOption(TcpHeader& hdr) const
{
  //NS_ASSERT(m_state == SYN_SENT || m_state == SYN_RCVD);

  if( IsMaster() )
  {

    Ptr<TcpOptionMpTcpCapable> mpc =  CreateObject<TcpOptionMpTcpCapable>();
    switch(hdr.GetFlags()){
      case TcpHeader::SYN:
      case (TcpHeader::SYN | TcpHeader::ACK):
        mpc->SetSenderKey( GetMeta()->GetLocalKey() );
        break;
      case TcpHeader::ACK:
        mpc->SetSenderKey( GetMeta()->GetLocalKey() );
        mpc->SetRemoteKey( GetMeta()->GetRemoteKey() );
        break;


//        mpc->SetSenderKey( GetMeta()->GetLocalKey() );
//        break;

      default:
        NS_FATAL_ERROR("Should never happen");
        break;
    };
    NS_LOG_INFO("Appended option" << mpc);
    hdr.AppendOption( mpc );
  }
  else
  {
    Ptr<TcpOptionMpTcpJoin> join =  CreateObject<TcpOptionMpTcpJoin>();

    switch(hdr.GetFlags())
    {
      case TcpHeader::SYN:
        {
          join->SetState(TcpOptionMpTcpJoin::Syn);
          uint32_t token = 0;
          uint64_t idsn = 0;
//          int result = 0;
//          result =
          MpTcpSocketBase::GenerateTokenForKey( MPTCP_SHA1, GetMeta()->GetRemoteKey(), token, idsn );

          join->SetPeerToken(token);
          join->SetNonce(0);
        }
        break;

      case TcpHeader::ACK:
        {
          uint8_t hmac[20];

        join->SetState(TcpOptionMpTcpJoin::Ack);
        join->SetHmac( hmac );
        }
        break;

      case (TcpHeader::SYN | TcpHeader::ACK):
        {
          join->SetState(TcpOptionMpTcpJoin::SynAck);
          //! TODO request from meta its id
          uint8_t id = 0;
          // TODO
          NS_FATAL_ERROR("TODO");
  //        id = GetIdManager()->GetLocalAddrId( InetSocketAddress(m_endPoint->GetLocalAddress(),m_endPoint->GetLocalPort()) );
          join->SetAddressId( id );
          join->SetTruncatedHmac(424242); // who cares
          join->SetNonce(4242); //! truly random :)
        }
        break;

      default:
        NS_FATAL_ERROR("Should never happen");
        break;
    }

    NS_LOG_INFO("Appended option" << join);
    hdr.AppendOption( join );
  }

  //!
//  if()
}


void
MpTcpSubFlow::NotifySend (uint32_t spaceAvailable)
{
  GetMeta()->NotifySend(spaceAvailable);
}

// TODO and normally I should wait for a fourth ack
void
MpTcpSubFlow::ProcessSynRcvd(Ptr<Packet> packet, const TcpHeader& tcpHeader, const Address& fromAddress,
    const Address& toAddress)
{
  //!
  NS_LOG_FUNCTION (this << tcpHeader);




  // Extract the flags. PSH and URG are not honoured.
  uint8_t tcpflags = tcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG);
  if (tcpflags == 0 || (tcpflags == TcpHeader::ACK && m_nextTxSequence + SequenceNumber32(1) == tcpHeader.GetAckNumber()))
    { // If it is bare data, accept it and move to ESTABLISHED state. This is
      // possibly due to ACK lost in 3WHS. If in-sequence ACK is received, the
      // handshake is completed nicely.
      NS_LOG_INFO ( "SYN_RCVD -> ESTABLISHED");
      // TODO we should check for the mptcp capable option
      m_state = ESTABLISHED;
      m_connected = true;
      m_retxEvent.Cancel();
      m_highTxMark = ++m_nextTxSequence;
      m_txBuffer.SetHeadSequence(m_nextTxSequence);


      // Expecting ack
      Ptr<TcpOptionMpTcpCapable> main;
      NS_ASSERT( GetMpTcpOption(tcpHeader, main) );
//      NS_LOG_INFO ( "Should contain both keys" );



      // I think it's already set sooner. To check
      if (m_endPoint)
        {
          m_endPoint->SetPeer(InetSocketAddress::ConvertFrom(fromAddress).GetIpv4(),
              InetSocketAddress::ConvertFrom(fromAddress).GetPort());
        }
      else if (m_endPoint6)
        {
          m_endPoint6->SetPeer(Inet6SocketAddress::ConvertFrom(fromAddress).GetIpv6(),
              Inet6SocketAddress::ConvertFrom(fromAddress).GetPort());
        }
      // Always respond to first data packet to speed up the connection.
      // Remove to get the behaviour of old NS-3 code.
      m_delAckCount = m_delAckMaxCount;
      ReceivedAck(packet, tcpHeader);
      GetMeta()->OnSubflowEstablishment(this);
      NotifyNewConnectionCreated(this, fromAddress);
      // As this connection is established, the socket is available to send data now
      if (GetTxAvailable() > 0)
        {
          NotifySend(GetTxAvailable());
        }
    }
  else if (tcpflags == TcpHeader::SYN)
    { // Probably the peer lost my SYN+ACK
      m_rxBuffer.SetNextRxSequence(tcpHeader.GetSequenceNumber() + SequenceNumber32(1));
      SendEmptyPacket(TcpHeader::SYN | TcpHeader::ACK);
    }
  else if (tcpflags == (TcpHeader::FIN | TcpHeader::ACK))
    {
      if (tcpHeader.GetSequenceNumber() == m_rxBuffer.NextRxSequence())
        { // In-sequence FIN before connection complete. Set up connection and close.
          m_connected = true;
          m_retxEvent.Cancel();
          m_highTxMark = ++m_nextTxSequence;
          m_txBuffer.SetHeadSequence(m_nextTxSequence);
          if (m_endPoint)
            {
              m_endPoint->SetPeer(InetSocketAddress::ConvertFrom(fromAddress).GetIpv4(),
                  InetSocketAddress::ConvertFrom(fromAddress).GetPort());
            }
          else if (m_endPoint6)
            {
              m_endPoint6->SetPeer(Inet6SocketAddress::ConvertFrom(fromAddress).GetIpv6(),
                  Inet6SocketAddress::ConvertFrom(fromAddress).GetPort());
            }
          PeerClose(packet, tcpHeader);
        }
    }
  else
    { // Other in-sequence input
      if (tcpflags != TcpHeader::RST)
        { // When (1) rx of SYN+ACK; (2) rx of FIN; (3) rx of bad flags
          NS_LOG_LOGIC ("Illegal flag " << tcpflags << " received. Reset packet is sent.");
          if (m_endPoint)
            {
              m_endPoint->SetPeer(InetSocketAddress::ConvertFrom(fromAddress).GetIpv4(),
                  InetSocketAddress::ConvertFrom(fromAddress).GetPort());
            }
          else if (m_endPoint6)
            {
              m_endPoint6->SetPeer(Inet6SocketAddress::ConvertFrom(fromAddress).GetIpv6(),
                  Inet6SocketAddress::ConvertFrom(fromAddress).GetPort());
            }
          SendRST();
        }
      CloseAndNotify();
    }


  // In case our syn/ack got lost
//  if (tcpflags == TcpHeader::SYN)
//    {
//      NS_FATAL_ERROR("Not implemented yet");
//      // TODO check for MP_CAPABLE
//      // factorize with code from Listen( that sends options !!
//
//      // Probably the peer lost my SYN+ACK
//      // So we need to resend it with the MPTCP option
//      // This could be a join case too
//      Ptr<TcpOptionMpTcpCapable> mpc;
//      TcpHeader answerHeader;
//      GenerateEmptyPacketHeader(answerHeader,TcpHeader::SYN | TcpHeader::ACK);
//      mpc->SetSenderKey( GetMeta()->GetLocalKey() );
//      m_rxBuffer.SetNextRxSequence(tcpHeader.GetSequenceNumber() + SequenceNumber32(1));
//
//      answerHeader.AppendOption(mpc);
//      SendEmptyPacket(answerHeader);
//      return;
//    }

  //
//  TcpSocketBase::ProcessSynRcvd( packet, tcpHeader, fromAddress, toAddress);

}

bool
MpTcpSubFlow::SendPendingData(bool withAck)
{
  //!
  NS_LOG_FUNCTION(this);
  return TcpSocketBase::SendPendingData(withAck);
}


bool
MpTcpSubFlow::IsMaster() const
{
  NS_ASSERT(GetMeta());
  return m_masterSocket;
  // TODO it will never return true
//  return (m_endPoint == m_metaSocket->m_endPoint); // This is master subsock, its endpoint is the same as connection endpoint.
  // is that enough ?
//  return (m_metaSocket->m_subflows.size() == 1);
}


bool
MpTcpSubFlow::BackupSubflow() const
{
  return m_backupSubflow;
}


/**
should be able to advertise several in one packet if enough space
It is possible
http://tools.ietf.org/html/rfc6824#section-3.4.1
   A host can send an ADD_ADDR message with an already assigned Address
   ID, but the Address MUST be the same as previously assigned to this
   Address ID, and the Port MUST be different from one already in use
   for this Address ID.  If these conditions are not met, the receiver
   SHOULD silently ignore the ADD_ADDR.  A host wishing to replace an
   existing Address ID MUST first remove the existing one
   (Section 3.4.2).

   A host that receives an ADD_ADDR but finds a connection set up to
   that IP address and port number is unsuccessful SHOULD NOT perform
   further connection attempts to this address/port combination for this
   connection.  A sender that wants to trigger a new incoming connection
   attempt on a previously advertised address/port combination can
   therefore refresh ADD_ADDR information by sending the option again.

**/
void
MpTcpSubFlow::AdvertiseAddress(Ipv4Address addr, uint16_t port)
{
  NS_LOG_FUNCTION("Started advertising address");
//  NS_ASSERT( );
#if 0
  // TODO check subflow is established !!
  uint8_t addrId = m_metaSocket->AddLocalAddr(addr);


  // Change the MPTCP send state to MP_ADDADDR
//      MpTcpAddressInfo * addrInfo;
  Ptr<Packet> pkt = Create<Packet>();

  TcpHeader header;
  GenerateEmptyPacketHeader(header);
//  header.SetFlags(TcpHeader::ACK);
//  //SequenceNumber32(m_txNextSequence)
//  header.SetSequenceNumber( m_nextTxSequence);
//  header.SetAckNumber( m_rxBuffer.NextRxSequence() );
//  header.SetSourcePort( m_endPoint->GetLocalPort() ); // m_endPoint->GetLocalPort()
//  header.SetDestinationPort( m_endPoint->GetPeerPort() );
//  header.SetWindowSize(AdvertisedWindowSize());
//  uint8_t hlen = 0;
//  uint8_t olen = 0;


//      IPv4Address;;ConvertFrom ( addr );
  Ptr<TcpOptionMpTcpAddAddress> addAddrOption = CreateObject<TcpOptionMpTcpAddAddress>();
  addAddrOption->SetAddress( InetSocketAddress( m_endPoint->GetLocalAddress(),0), addrId );
//  addAddrOption->SetAddress( m_endPoint->GetLocalAddress() );

  header.AppendOption( addAddrOption );
//  header.AddOptADDR(OPT_ADDR, addrId, Ipv4Address::ConvertFrom ( addr ) );
//  olen += 6;

//  uint8_t plen = (4 - (olen % 4)) % 4;

//  olen = (olen + plen) / 4;
//  hlen = 5 + olen;
//  header.SetLength(hlen);
//  header.SetOptionsLength(olen);
//  header.SetPaddingLength(plen);


  m_tcp->SendPacket(pkt, header, m_endPoint->GetLocalAddress(), m_endPoint->GetPeerAddress());
  // we 've got to rely on

//      this->SendPacket(pkt, header, m_localAddress, m_remoteAddress, FindOutputNetDevice(m_localAddress) );
  NS_LOG_INFO("Advertise  Addresses-> "<< header);
  #endif
}


bool
MpTcpSubFlow::StopAdvertisingAddress(Ipv4Address address)
{
  // TODO factor some code with AdvertiseAddress ?
  // TODO check subflow is established !!
  #if 0
  uint8_t addrId = 0;

//  addrId  = m_metaSocket->RemLocalAddr(addr);
//FindLocalAddrId
  if( !m_metaSocket->RemLocalAddr(address,addrId) )
  {
    //
    return false;
  }

  // Change the MPTCP send state to MP_ADDADDR
//      MpTcpAddressInfo * addrInfo;
  Ptr<Packet> pkt = Create<Packet>();

  TcpHeader header;
  GenerateEmptyPacketHeader(header,TcpHeader::ACK);
//  header.SetFlags(TcpHeader::ACK);
//  header.SetSequenceNumber( m_nextTxSequence );    // SequenceNumber32(TxSeqNumber)
//  header.SetAckNumber( m_rxBuffer.NextRxSequence() );
//  header.SetSourcePort( m_endPoint->GetLocalPort() ); // m_endPoint->GetLocalPort()
//  header.SetDestinationPort ( m_endPoint->GetPeerPort() );
//  header.SetWindowSize(AdvertisedWindowSize());


//      IPv4Address;;ConvertFrom ( addr );
  Ptr<TcpOptionMpTcpRemoveAddress> remOpt = CreateObject<TcpOptionMpTcpRemoveAddress>();
  remOpt->AddAddressId( addrId );
  header.AppendOption( remOpt );



  m_tcp->SendPacket(pkt, header, m_endPoint->GetLocalAddress(), m_endPoint->GetPeerAddress());
  // we 've got to rely on

//      this->SendPacket(pkt, header, m_localAddress, m_remoteAddress, FindOutputNetDevice(m_localAddress) );
  NS_LOG_INFO("Advertise  Addresses-> "<< header);
  #endif
  return true;
}



//bool
//MpTcpSubFlow::Finished(void)
//{
//  return (m_gotFin && m_finSeq.GetValue() < RxSeqNumber);
//}

//void
//MpTcpSubFlow::StartTracing( std::string traced)
//{
//  //NS_LOG_UNCOND("("<< m_routeId << ") MpTcpSubFlow -> starting tracing of: "<< traced);
//  TraceConnectWithoutContext(traced, MakeCallback(&MpTcpSubFlow::CwndTracer, this)); //"CongestionWindow"
//}





/**
TODO check with its parent equivalent, may miss a few features
Receipt of new packet, put into Rx buffer

SlowStart and fast recovery remains untouched in MPTCP.
The reaction should be different depending on if we handle NR-SACK or not
*/
void
MpTcpSubFlow::NewAck(SequenceNumber32 const& ack)
{
  NS_LOG_FUNCTION (this << ack);


  MpTcpMapping mapping;

  // TODO move elsewhere on rece
//  if(!m_TxMappings.GetMappingForSegment( ack-1, mapping) )
//  {
//    NS_LOG_DEBUG("Could not find an adequate Tx mapping for ack " << ack);
//    return;
//  }

  NS_LOG_FUNCTION (this << ack);
  NS_LOG_LOGIC ("Subflow receieved ACK for seq " << ack <<
                " cwnd " << m_cWnd <<
                " ssthresh " << m_ssThresh
              );



  // Check for exit condition of fast recovery
  if (m_inFastRec)
    { // RFC2001, sec.4; RFC2581, sec.3.2
      // First new ACK after fast recovery: reset cwnd
      m_cWnd = m_ssThresh;
      m_inFastRec = false;
      NS_LOG_INFO ("Reset cwnd to " << m_cWnd);
    };


  // Increase of cwnd based on current phase (slow start or congestion avoidance)
  if (m_cWnd < m_ssThresh)
    { // Slow start mode, add one segSize to cWnd. Default m_ssThresh is 65535. (RFC2001, sec.1)
      m_cWnd += m_segmentSize;
      NS_LOG_INFO ("In SlowStart, updated to cwnd " << m_cWnd << " ssthresh " << m_ssThresh);
    }
  else
    {
      /** TODO in the future, there should be a way to easily override this in future releases
      **/

      // Congestion avoidance mode, increase by (segSize*segSize)/cwnd. (RFC2581, sec.3.1)
//
      OpenCwndInCA(0);

      // To increase cwnd for one segSize per RTT, it should be (ackBytes*segSize)/cwnd
//      double adder = static_cast<double> (m_segmentSize * m_segmentSize) / m_cWnd.Get ();
//      adder = std::max (1.0, adder);
//      m_cWnd += static_cast<uint32_t> (adder);
      NS_LOG_INFO ("In CongAvoid, updated to cwnd " << m_cWnd << " ssthresh " << m_ssThresh);
    }




  if (m_state != SYN_RCVD)
    { // Set RTO unless the ACK is received in SYN_RCVD state
      NS_LOG_LOGIC (this << " Cancelled ReTxTimeout event which was set to expire at " <<
          (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
      m_retxEvent.Cancel();
      // On recieving a "New" ack we restart retransmission timer .. RFC 2988
      m_rto = m_rtt->RetransmitTimeout();
      NS_LOG_LOGIC (this << " Schedule ReTxTimeout at time " <<
          Simulator::Now ().GetSeconds () << " to expire at time " <<
          (Simulator::Now () + m_rto.Get ()).GetSeconds ());
      m_retxEvent = Simulator::Schedule(m_rto, &MpTcpSubFlow::ReTxTimeout, this);
    }

  if (m_rWnd.Get() == 0 && m_persistEvent.IsExpired())
    { // Zero window: Enter persist state to send 1 byte to probe
      NS_LOG_LOGIC (this << "Enter zerowindow persist state");NS_LOG_LOGIC (this << "Cancelled ReTxTimeout event which was set to expire at " <<
          (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
      m_retxEvent.Cancel();
      NS_LOG_LOGIC ("Schedule persist timeout at time " <<
          Simulator::Now ().GetSeconds () << " to expire at time " <<
          (Simulator::Now () + m_persistTimeout).GetSeconds ());
      m_persistEvent = Simulator::Schedule(m_persistTimeout, &MpTcpSubFlow::PersistTimeout, this);
      NS_ASSERT(m_persistTimeout == Simulator::GetDelayLeft (m_persistEvent));
    }

  // Note the highest ACK and tell app to send more
  NS_LOG_LOGIC ("TCP " << this << " NewAck " << ack <<
      " numberAck " << (ack - m_txBuffer.HeadSequence ())); // Number bytes ack'ed

  // TODO: get mapping associated with that Ack and
//  MpTcpMapping mapping;
  if(!m_TxMappings.GetMappingForSSN(ack, mapping) ) {

    NS_LOG_WARN("Late ack ! Dumping Tx Mappings");
    m_TxMappings.Dump();
  }
  else {
    // TODO check if all mappings below that are acked before removing them
    //    m_txBuffer.DiscardUpTo(ack);

    /** TODO here we have to update the nextTxBuffer
    but we can discard only if the full mapping was acknowledged
    */

    if(m_nextTxSequence > mapping.TailSSN()) {

      m_txBuffer.DiscardUpTo(m_nextTxSequence);
    }
//      std::distance(s.begin(), s.lower_bound(x))
    // #error
  }

// TODO I should call


  if (GetTxAvailable() > 0)
    {
      // Ok, va appeler la meta
      NotifySend(GetTxAvailable());
    }

  if (ack > m_nextTxSequence)
    {
      m_nextTxSequence = ack; // If advanced
    }

  if (m_txBuffer.Size() == 0 && m_state != FIN_WAIT_1 && m_state != CLOSING)
    { // No retransmit timer if no data to retransmit
      NS_LOG_WARN (this << " Cancelled ReTxTimeout event which was set to expire at " <<
          (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
      m_retxEvent.Cancel();
      return;
    }

  if (m_txBuffer.Size() == 0)
    {
//      throughput = 10000000 * 8 / (Simulator::Now().GetSeconds() - fLowStartTime);
//      NS_LOG_UNCOND("goodput -> " << throughput / 1000000 << " Mbps {Tx Buffer is now empty}  P-AckHits:" << pAckHit);
      return;
    }
  // Try to send more data
  SendPendingData(m_connected);

//  TcpSocketBase::NewAck( ack );
  // WRONG  they can be sparse. This should be done by meta
  // DiscardTxMappingsUpToDSN( ack );
  //  Je peux pas le discard tant que
  //  m_txBuffer.DiscardUpTo( ack );
  // TODO check the full mapping is reachable
//  if( m_txBuffer.Available(mapping.HeadDSN(), mapping.MaxSequence()))
//  {
//    Packet pkt = m_rxBuffer.Extract(mapping.HeadDSN(), mapping.GetLength() );
//
//    //! pass on data
//    GetMeta()->ReceivedData( pkt, mapping );
//
//  }

}

//void
//MpTcpSubFlow::DiscardTxMappingsUpToDSN(SequenceNumber32 seq)
//{
//  NS_LOG_INFO("Discarding mappings up to " << seq);
//  MappingList& l = m_TxMappings;
//  for( MappingList::iterator it = l.begin(); it != l.end(); it++ )
//  {
//    //HeadDSN
//    if( it->TailDSN() < seq  )
//    {
//      //it =
////      NS_ASSERT( );
//      // TODO check mapping transfer was completed on this subflow
////      if( m_txBuffer.HeadSequence() <  )
////      {
////
////      }
//      l.erase(it);
//    }
//  }
//}

Ptr<Packet>
MpTcpSubFlow::RecvFrom(uint32_t maxSize, uint32_t flags, Address &fromAddress)
{
  NS_FATAL_ERROR("Disabled in MPTCP. Use RecvWithMapping");
  return 0;
}

Ptr<Packet>
MpTcpSubFlow::Recv(uint32_t maxSize, uint32_t flags)
{
  //!
  NS_FATAL_ERROR("Disabled in MPTCP. Use RecvWithMapping");
  return 0;
}

Ptr<Packet>
MpTcpSubFlow::Recv(void)
{
  //!
  NS_FATAL_ERROR("Disabled in MPTCP. Use RecvWithMapping");
  return 0;
}


//bool
//MpTcpSubFlow::TranslateSSNtoDSN(SequenceNumber32 ssn,SequenceNumber32 &dsn)
//{
//  // first find if a mapping exists
//  MpTcpMapping mapping;
//  if(!GetMappingForSegment( m_RxMappings, ssn, mapping) )
//  {
//    //!
//    return false;
//  }
//
//  return mapping.TranslateSSNToDSN(ssn,dsn);
//}

// use with a maxsize ? rename to ReceivedMappedData
// We should be able to precise what range of data we can support
Ptr<Packet>
MpTcpSubFlow::RecvWithMapping( uint32_t maxSize, SequenceNumber32 &dsn)
{
  //!
  NS_LOG_FUNCTION(this << "maxSize ["<< maxSize << "]" );
//  Ptr<Packet> p = TcpSocketBase::Recv();

  // I can reuse
//   = 3303000;


  //NS_ABORT_MSG_IF(flags, "use of flags is not supported in TcpSocketBase::Recv()");
//  if (m_rxBuffer.Size() == 0 && m_state == CLOSE_WAIT)
  if (m_state == CLOSE_WAIT)
    {
      NS_LOG_ERROR("CLOSE_WAIT");
      return Create<Packet>(); // Send EOF on connection close
    }



  // TODO sthg more rigorous later on
  // should be able to set the DSN
  //////////////////////////////////////////Y//
  /// we want to retrieve the SSN of the first byte that
  /// will be extracted from the TcpRxBuffer
  /// TODO That would do a nice addition to the TcpRxBuffer
  // sthg liek GetHead/MinSeq
//  SequenceNumber32 headSSN = m_rxBuffer.NextRxSequence()-m_rxBuffer.Available();
  SequenceNumber32 headSSN = m_rxBuffer.GetHeadRxSequence();

  NS_LOG_LOGIC("Extracting from SSN [" << headSSN << "]");
  //SequenceNumber32 headDSN;

//  m_RxMappings.
  MpTcpMapping mapping;
//  if(!m_RxMappings.GetMappingForSSN(headSSN,mapping))
  if(!m_RxMappings.TranslateSSNtoDSN(headSSN, dsn))
  {
    m_RxMappings.Dump();
    NS_FATAL_ERROR("Could not associate a mapping to ssn [" << headSSN << "]");
  }
//  dsn = mapping.
  // extract at most the size of the mapping
  // If there is more data, it should be extracted through another call to RecvWithMapping

  //std::min(maxSize, (uint32_t)mapping.GetLength() )
  Ptr<Packet> outPacket = m_rxBuffer.Extract( maxSize );

//  NS_ASSERT(outPacket->GetSize());
  return outPacket;
}

//MpTcpSubFlow::TranslateSubflowSeqToDataSeq();

// TODO move to Meta
//void
//MpTcpSubFlow::AppendDataAck(TcpHeader& hdr) const
//{
//  NS_LOG_FUNCTION(this);
//
////  Ptr<TcpOptionMpTcpDSS> dss;
////  GetOrCreateMpTcpOption()
//  Ptr<TcpOptionMpTcpDSS> dss;
//  GetOrCreateMpTcpOption(hdr,dss);
//
//  NS_ASSERT(dss->GetDataAck() == 0);
//
////   = CreateObject<TcpOptionMpTcpDSS>();
//  dss->SetDataAck( GetMeta()->m_rxBuffer.NextRxSequence().GetValue() );
//
//  // TODO check the option is not in the header already
////  NS_ASSERT_MSG( hdr.GetOption()GetOp)
//
////  hdr.AppendOption(dss);
//}



void
MpTcpSubFlow::SetupMetaTracing(const std::string prefix)
{
//  f.open(filename, std::ofstream::out | std::ofstream::trunc);
  SetupSocketTracing(this, prefix);
}


/**
TODO here I should look for an associated mapping.

ProcessEstablished

If there is not, then I discard the stuff
std::ostream& ns3::operator<<(std::ostream&,const ns3::TcpOptionMptcpMain&)

TODO I should also notify the meta, maybe with an enum saying if it's new data/old etc...
*/
void
MpTcpSubFlow::ReceivedData(Ptr<Packet> p, const TcpHeader& tcpHeader)
{
  NS_LOG_FUNCTION (this << tcpHeader);
//  NS_LOG_FUNCTION (this << tcpHeader);NS_LOG_LOGIC ("seq " << tcpHeader.GetSequenceNumber () <<
//      " ack " << tcpHeader.GetAckNumber () <<
//      " pkt size " << p->GetSize ()
//      );
  // Following was moved to ReceivedAck sincethis is from there that ReceivedData can
  // be called

  MpTcpMapping mapping;
  bool sendAck = false;

  TcpHeader answerHeader;
  GenerateEmptyPacketHeader(answerHeader, TcpHeader::ACK);
//  OutOfRange
  // If cannot find an adequate mapping, then it should [check RFC]
  if(!m_RxMappings.GetMappingForSSN(tcpHeader.GetSequenceNumber(), mapping) )
  {

    m_RxMappings.Dump();
    NS_FATAL_ERROR("Could not find mapping associated ");

//    NS_LOG_DEBUG("Could not find an adequate mapping for");
    // TODO remove that later
//    NS_ASSERT_MSG(false,"No mapping received for that ack nb");

    // TODO we should create here a DSS option else it will not be freed at the sender

    //SendEmptyPacket(ackHeader);
    return;
  }

  //TcpHeader ackHeader;
//  GenerateEmptyPacketHeader(ackHeader,TcpHeader::ACK);
//  Ptr<TcpOptionMpTcpDSS> dss = CreateObject<TcpOptionMpTcpDSS>();

  // TODO this function sends ACK without the mptcp DSS option .
  //TcpSocketBase::ReceivedData( p, mptcpHeader );

  // This part was copy/pasted from TcpSocketBase
  //NS_LOG_FUNCTION (this << tcpHeader);
  //NS_LOG_LOGIC ("seq " << tcpHeader.GetSequenceNumber () <<
    //  " ack " << tcpHeader.GetAckNumber () <<
      //" pkt size " << p->GetSize () );

  // Put into Rx buffer
  SequenceNumber32 expectedSSN = m_rxBuffer.NextRxSequence();
  if (!m_rxBuffer.Add(p, tcpHeader))
    { // Insert failed: No data or RX buffer full
      NS_LOG_DEBUG("Insert failed, No data or RX buffer full");

//      dss->SetDataAck( GetMeta()->m_rxBuffer.NextRxSequence().GetValue() );
      GetMeta()->AppendDataAck( answerHeader );
      SendEmptyPacket(answerHeader);
      return;
    }
  else
  {
    // we received new data
    // We should pass it to the meta


    if (m_rxBuffer.Size() > m_rxBuffer.Available() || m_rxBuffer.NextRxSequence() > expectedSSN + p->GetSize())
      { // A gap exists in the buffer, or we filled a gap: Always ACK
        // TODO
        sendAck = true;
//        dss->SetDataAck(GetMeta()->m_rxBuffer.NextRxSequence().GetValue());
//        SendEmptyPacket(answerHeader);
      }
    else
      { // In-sequĶence packet: ACK if delayed ack count allows
        // TODO i removed delayed ack. may reestablish later
  //      if (++m_delAckCount >= m_delAckMaxCount)
  //        {
  //          m_delAckEvent.Cancel();
  //          m_delAckCount = 0;
            sendAck = true;
//            dss->SetDataAck(GetMeta()->m_rxBuffer.NextRxSequence().GetValue());
//            SendEmptyPacket(answerHeader);
  //        }
  //      else if (m_delAckEvent.IsExpired())
  //        {
  //          m_delAckEvent = Simulator::Schedule(m_delAckTimeout, &TcpSocketBase::DelAckTimeout, this);
  //          NS_LOG_LOGIC (this << " scheduled delayed ACK at " << (Simulator::Now () + Simulator::GetDelayLeft (m_delAckEvent)).GetSeconds ());
  //        }
      }
  }



  // Notify app to receive if necessary
  if (expectedSSN < m_rxBuffer.NextRxSequence())
    { // NextRxSeq advanced, we have something to send to the app
      if (!m_shutdownRecv)
        {
          // rename into RecvFromSubflow RecvData ?
          // NotifyMetaOfRcvdData
//          GetMeta()->Ŕcv( this);

          // TODO should not be called for now
          // TODO should say if it needs to DATAACK ?
//          NotifyDataRecv();
           GetMeta()->OnSubflowRecv( this );
           sendAck = true;
        }
      // Handle exceptions
      if (m_closeNotified)
        {
          NS_LOG_WARN ("Why TCP " << this << " got data after close notification?");
        }
      // If we received FIN before and now completed all "holes" in rx buffer,
      // invoke peer close procedure
      if (m_rxBuffer.Finished() && (tcpHeader.GetFlags() & TcpHeader::FIN) == 0)
        {
          DoPeerClose();
        }
    }

    // For now we always sent an ack
    // TODO should increase
//    dss->SetDataAck( GetMeta()->m_rxBuffer.NextRxSequence().GetValue() );
    // should be always true hack to allow compilation
    if(sendAck) {
//      answerHeader.AppendOption(dss);
      GetMeta()->AppendDataAck(answerHeader);
      SendEmptyPacket(answerHeader);
    }

  // TODO handle out of order case look at parent's member.


  // TODO pass subflow id to the function
  // TODO if that acknowledges a full mapping then transfer it to  the metasock
//  if( m_rxBuffer.Extract() )
//  {
//    m_rxBuffer.Extract()
//
//
////  GetMeta()->ReceivedData(p, const TcpHeader& mptcpHeader);
//  }
  // TODO see what we can free in our TxBuffer

}

// TODO unsure ?
uint32_t
MpTcpSubFlow::UnAckDataCount()
{
  NS_LOG_FUNCTION (this);
//  return GetMeta()->UnAckDataCount();
  return TcpSocketBase::UnAckDataCount();
}

// TODO unsure ?
uint32_t
MpTcpSubFlow::BytesInFlight()
{
  NS_LOG_FUNCTION (this);
  return TcpSocketBase::BytesInFlight();
}

// TODO unsure ?
uint32_t
MpTcpSubFlow::AvailableWindow()
{
  NS_LOG_FUNCTION (this);

  return TcpSocketBase::AvailableWindow();
//  GetMeta()->AvailableWindow();
}

// TODO unsure ?
uint32_t
MpTcpSubFlow::Window (void)
{
  NS_LOG_FUNCTION (this);
  return std::min (m_rWnd.Get (), m_cWnd.Get ());
//  return GetMeta()->Window();
}

uint16_t
MpTcpSubFlow::AdvertisedWindowSize(void)
{
  NS_LOG_DEBUG(this);
  return GetMeta()->AdvertisedWindowSize();
}

void
MpTcpSubFlow::ClosingOnEmpty(TcpHeader& header)
{
  /* TODO the question is: is that ever called ?
  */
  NS_LOG_FUNCTION(this << "mattator");

    header.SetFlags( header.GetFlags() | TcpHeader::FIN);
    // flags |= TcpHeader::FIN;
    if (m_state == ESTABLISHED)
    { // On active close: I am the first one to send FIN
      NS_LOG_INFO ("ESTABLISHED -> FIN_WAIT_1");
      m_state = FIN_WAIT_1;
      // TODO get DSS, if none
//      Ptr<TcpOptionMpTcpDSS> dss;
//
//      //! TODO add GetOrCreateMpTcpOption member
//      if(!GetMpTcpOption(header, dss))
//      {
//        // !
//        dss = Create<TcpOptionMpTcpDSS>();
//
//      }
//      dss->SetDataFin(true);
//      header.AppendOption(dss);

    }
    else if (m_state == CLOSE_WAIT)
    {
      // On passive close: Peer sent me FIN already
      NS_LOG_INFO ("CLOSE_WAIT -> LAST_ACK");
      m_state = LAST_ACK;

    }

    GetMeta()->OnSubflowClosing(this);
}

//! TODO call directly parent
void
MpTcpSubFlow::ParseDSS(Ptr<Packet> p, const TcpHeader& header,Ptr<TcpOptionMpTcpDSS> dss)
{
  //!
  NS_ASSERT(dss);
  GetMeta()->ProcessDSS(header, dss, Ptr<MpTcpSubFlow>(this));

//  uint8_t flags = dss->GetFlags();
//
//  // Look for mapping
//  if( flags & TcpOptionMpTcpDSS::DSNMappingPresent )
//  {
//    if(dss->IsInfiniteMapping()) {
//      NS_FATAL_ERROR("Infinite mapping detected. Unsupported !");
//    }
//    else if(dss->DataFinMappingOnly()){
//      //!
//      NS_LOG_LOGIC("Received DATAFIN mapping only");
//
//    }
//    // Maps actual data
//    else
//    {
//      //!
////   TODO here we should generate the actual mapping, converts to 64 if it were 32 bits etc....
////      //!
////      if(flags & TcpOptionMpTcpDSS::DSNOfEightBytes)
////      {
////        NS_FATAL_ERROR("Not supported");
////      }
//      //! the mapping generated here is 32bits only
//      AddPeerMapping(dss->GetMapping());
//    }
//  }
//
//  // looks for Data ACK
//  if(flags & TcpOptionMpTcpDSS::DataAckPresent)
//  {
//    if(flags & TcpOptionMpTcpDSS::DataAckOf8Bytes)
//    {
//      NS_FATAL_ERROR("Not supported");
//    }
//    else
//    {
//      // TODO pass the info to the meta
//      //
//
//    }
//
//
//  }

  //!
//  if( flags & TcpOptionMpTcpDSS::DataFin)
//  {
//    //! depending on the state
//    NS_LOG_DEBUG("Peer wants to close the connection");
//    GetMeta()->OnDataFin( SequenceNumber32 (dss->GetDataFinDSN() ),this);
////    GetMeta()->PeerClose();
//  }

}



/*
Upon ack receival we need to act depending on if it's new or not
-if it's new it may allow us to discard a mapping
-otherwise notify meta of duplicate

this is called
*/
void
MpTcpSubFlow::ReceivedAck(Ptr<Packet> p, const TcpHeader& header)
{
  NS_LOG_FUNCTION (this << header);

  // if packet size > 0 then it will call ReceivedData
  TcpSocketBase::ReceivedAck(p, header );

}

// TODO remove
bool
MpTcpSubFlow::AddPeerMapping(const MpTcpMapping& mapping)
{
  //! TODO check if there is already such a mapping?
  // check in meta ? if it supervises everything ?
  NS_LOG_FUNCTION(this << mapping);
  NS_ASSERT(m_RxMappings.AddMappingEnforceSSN( mapping ) ==0 );
  m_RxMappings.Dump();
  return true;
}

//void
//MpTcpSubFlow::CwndTracer(uint32_t oldval, uint32_t newval)
//{
//  //NS_LOG_UNCOND("Subflow "<< m_routeId <<": Moving cwnd from " << oldval << " to " << newval);
//  cwndTracer.push_back(make_pair(Simulator::Now().GetSeconds(), newval));
//}

//void
//MpTcpSubFlow::SetFinSequence(const SequenceNumber32& s)
//{
//  NS_LOG_FUNCTION (this);
//  m_gotFin = true;
//  m_finSeq = s;
//  if (RxSeqNumber == m_finSeq.GetValue())
//    ++RxSeqNumber;
//}


} // end of ns3
