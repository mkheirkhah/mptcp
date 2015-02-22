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
#include <algorithm>
#include <openssl/sha.h>

NS_LOG_COMPONENT_DEFINE("MpTcpSubflow");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED(MpTcpSubflow);

TypeId
MpTcpSubflow::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::MpTcpSubflow")
      .SetParent<TcpSocketBase>()
//      .AddConstructor<MpTcpSubflow>()
      // TODO should be inherited
      .AddTraceSource("CongestionWindow",
          "The congestion control window to trace.",
           MakeTraceSourceAccessor(&MpTcpSubflow::m_cWnd))
      .AddTraceSource("SSThreshold",
          "The Slow Start Threshold.",
           MakeTraceSourceAccessor(&MpTcpSubflow::m_ssThresh))
    ;
  return tid;
}





TypeId
MpTcpSubflow::GetInstanceTypeId(void) const
{
  return GetTypeId();
}

//bool
void
MpTcpSubflow::SetMeta(Ptr<MpTcpSocketBase> metaSocket)
{
  NS_ASSERT(metaSocket);
  NS_ASSERT(m_state == CLOSED);
  NS_LOG_FUNCTION(this);
  m_metaSocket = metaSocket;

  // kinda hackish
//  m_TxMappings.m_txBuffer = &m_txBuffer;
//  m_RxMappings.m_rxBuffer = &m_rxBuffer;

//  return true;
}

void
MpTcpSubflow::DumpInfo() const
{
      NS_LOG_LOGIC ("MpTcpSubflow " << this << " SendPendingData" <<
//          " w " << w <<
          " rxwin " << m_rWnd <<
          " segsize " << m_segmentSize <<
          " nextTxSeq " << m_nextTxSequence <<
          " highestRxAck " << FirstUnackedSeq() <<
          " pd->Size " << m_txBuffer.Size () <<
          " pd->SFS " << m_txBuffer.SizeFromSequence (m_nextTxSequence)
          );
}

Ptr<TcpSocketBase>
MpTcpSubflow::Fork(void)
{
  // Call CopyObject<> to clone me
//  NS_LOG_ERROR("Not implemented");


  return ForkAsSubflow();
}

//Ptr<MpTcpSubflow>
//MpTcpSubflow::ForkAsSubflow(void)
//{
//  return CopyObject<MpTcpSubflow> (this);
//}

/*
DupAck
RFC 6824
"As discussed earlier, however, an MPTCP
   implementation MUST NOT treat duplicate ACKs with any MPTCP option,
   with the exception of the DSS option, as indications of congestion
   [12], and an MPTCP implementation SHOULD NOT send more than two
   duplicate ACKs in a row for signaling purposes."
*/
void
MpTcpSubflow::DupAck(const TcpHeader& t, uint32_t count)
{
  NS_LOG_LOGIC("DupAck " << count);
//  if( count > 3)
  GetMeta()->OnSubflowDupAck(this);

  NS_LOG_FUNCTION (this << "t " << count);
  if (count == m_retxThresh && !m_inFastRec)
    { // triple duplicate ack triggers fast retransmit (RFC2581, sec.3.2)
      m_ssThresh = std::max (2 * m_segmentSize, BytesInFlight () / 2);
      m_cWnd = m_ssThresh + 3 * m_segmentSize;
      m_inFastRec = true;
      NS_LOG_INFO ("Triple dupack. Entering fast recovery. Reset cwnd to " << m_cWnd << ", ssthresh to " << m_ssThresh);
      DoRetransmit ();
    }
  else if (m_inFastRec)
    { // In fast recovery, inc cwnd for every additional dupack (RFC2581, sec.3.2)
      m_cWnd += m_segmentSize;
      NS_LOG_INFO ("In fast recovery. Increased cwnd to " << m_cWnd);
      SendPendingData (m_connected);
    };
}


// TODO check with parent's
void
MpTcpSubflow::CancelAllTimers()
{
  NS_LOG_FUNCTION(this);
  //(int) sFlowIdx
  m_retxEvent.Cancel();
  m_lastAckEvent.Cancel();
  m_timewaitEvent.Cancel();
  NS_LOG_LOGIC( "CancelAllTimers");
}



void
MpTcpSubflow::SetSSThresh(uint32_t threshold)
{
  // TOODO there is a minimum value decided by meta
  m_ssThresh = threshold;
}


uint32_t
MpTcpSubflow::GetSSThresh(void) const
{
//  return GetMeta()->GetSSThresh();
  return m_ssThresh;
}

/** TODO remve those 2, use the meta's **/
void
MpTcpSubflow::SetInitialCwnd(uint32_t cwnd)
{
  NS_LOG_WARN("NOOP: Use meta socket SetInitialCwnd instead");
//  NS_ABORT_MSG_UNLESS(m_state == CLOSED, "MpTcpsocketBase::SetInitialCwnd() cannot change initial cwnd after connection started.");
//  m_initialCWnd = cwnd;
}

uint32_t
MpTcpSubflow::GetInitialCwnd(void) const
{
  return GetMeta()->GetInitialCwnd();
}






TcpStates_t
MpTcpSubflow::GetState() const
{
  //!
  return m_state;
}


int
MpTcpSubflow::DoConnect()
{
  NS_LOG_FUNCTION (this);

  InitializeCwnd ();

  // A new connection is allowed only if this socket does not have a connection
  if (m_state == CLOSED || m_state == LISTEN || m_state == SYN_SENT || m_state == LAST_ACK || m_state == CLOSE_WAIT)
    { // send a SYN packet and change state into SYN_SENT
      TcpHeader header;
      GenerateEmptyPacketHeader(header,TcpHeader::SYN);

      // code moved inside SendEmptyPacket

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
MpTcpSubflow::Close(void)
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
MpTcpSubflow::MpTcpSubflow(const MpTcpSubflow& sock)
  : TcpSocketBase(sock),
  m_cWnd(sock.m_cWnd),
  m_ssThresh(sock.m_ssThresh),
  m_initialCWnd (sock.m_initialCWnd),
  m_masterSocket(sock.m_masterSocket),
  m_localNonce(sock.m_localNonce)

// , m_remoteToken(sock.m_remoteToken)
// TODO
//    m_retxThresh (sock.m_retxThresh),
//    m_inFastRec (false),
{
  NS_LOG_FUNCTION (this);
  NS_LOG_LOGIC ("Invoked the copy constructor");
}

MpTcpSubflow::MpTcpSubflow(
//Ptr<MpTcpSocketBase> metaSocket
) :
    TcpSocketBase(),
    m_routeId(0),
    m_ssThresh(65535),
    m_initialCWnd(10),
//    m_metaSocket(metaSocket),
    m_backupSubflow(false),
    m_masterSocket(false),
    m_localNonce(0)
{
  NS_LOG_FUNCTION(this);
  m_cnRetries = 3;
  Time est = MilliSeconds(200);
  m_cnTimeout = est;
//  initialSequnceNumber = 0;
  m_retxThresh = 3; // TODO retrieve from meta
  m_inFastRec = false;
//  m_limitedTx = false;
  m_dupAckCount = 0;
//  PktCount = 0;
  m_recover = SequenceNumber32(0);
}

MpTcpSubflow::~MpTcpSubflow()
{
  NS_LOG_FUNCTION(this);
  // TODO cancel times
  //std::list<DSNMapping *>
//  for (MappingList::iterator it = m_mapDSN.begin(); it != m_mapDSN.end(); ++it)
//    {
//      DSNMapping * ptrDSN = *it;
//      delete ptrDSN;
//    }
//  m_mapDSN.clear();
}


/**
TODO maybe override that not to have the callbacks
**/
void
MpTcpSubflow::CloseAndNotify(void)
{
  //TODO
  NS_LOG_FUNCTION_NOARGS();
  TcpSocketBase::CloseAndNotify();
  GetMeta()->OnSubflowClosed( this, false );
}


/**
Maybe we could allow this providing a mapping already exists ?
**/
int
MpTcpSubflow::Send(Ptr<Packet> p, uint32_t flags)
{
  NS_FATAL_ERROR("Use sendmapping instead");
  return 0;
}

//, uint32_t maxSize
// rename globalSeqNb ?

void
MpTcpSubflow::SendEmptyPacket(uint8_t flags)
{
  NS_LOG_FUNCTION_NOARGS();
  TcpSocketBase::SendEmptyPacket(flags);
}


void
MpTcpSubflow::SendEmptyPacket(TcpHeader& header)
{
  NS_LOG_FUNCTION(this << header);

  /*
  TODO here we should parse the flags and append the correct option according to it
  */
  if(m_state != SYN_SENT && m_state != SYN_RCVD)
  {
    GetMeta()->AppendDataAck(header);
  }

  TcpSocketBase::SendEmptyPacket(header);
}

/**
//! GetLength()
this fct asserts when the mapping length is 0 but in fact it can be possible
when there is an infinite mapping

Probleme ici c si j'essaye


**/
int
MpTcpSubflow::SendMapping(Ptr<Packet> p, MpTcpMapping& mapping)
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

//  if(m_txBuffer.Available() < mapping.GetLength())
//  {
//    NS_LOG_ERROR("Too much data to send");
//    return -ERROR_MSGSIZE;
//  }
  NS_LOG_FUNCTION (this << p);
//  NS_ABORT_MSG_IF(flags, "use of flags is not supported in TcpSocketBase::Send()");
  //! & !m_closeOnEmpty
  if (m_state == ESTABLISHED || m_state == SYN_SENT || m_state == CLOSE_WAIT)
    {

      SequenceNumber32 savedTail = m_txBuffer.TailSequence();
      // Store the packet into Tx buffer
      if (!m_txBuffer.Add(p))
        { // TxBuffer overflow, send failed
          NS_LOG_WARN("TX buffer overflow");

          m_errno = ERROR_MSGSIZE;
          return -1;
        }

      //! add succeeded
      NS_LOG_DEBUG(mapping << "Mapped to SSN=" << savedTail);
      mapping.MapToSSN( savedTail );
      NS_ASSERT_MSG(m_TxMappings.AddMapping( mapping  ) == true, "2 mappings overlap");

      // Submit the data to lower layers
      NS_LOG_LOGIC ("txBufSize=" << m_txBuffer.Size () << " state " << TcpStateName[m_state]);
      if (m_state == ESTABLISHED || m_state == CLOSE_WAIT)
        {
          NS_LOG_DEBUG("m_nextTxSequence [" << m_nextTxSequence << "]");
          // Try to send the data out
          SendPendingData(m_connected);
        }
      return p->GetSize();
    }
  else
    { // Connection not established yet
      m_errno = ERROR_NOTCONN;
      return -1; // Send failure
    }

    return 0;
  // In fact this must be mapped to the last unmapped value
  // NS_LOG_UNCOND("before mapping to ssn m_nextTxSequence [" << m_nextTxSequence << "]");

// First UnmappedSSN
//  m_mappings.rbegin()->TailSSN() + 1
// TODO map just in time ? how does the kernel ?


  // TODO je viens de le changer, on doit assigner le SSN ici
//  NS_ASSERT_MSG(m_TxMappings.AddMappingLooseSSN( mapping  ) >= 0, "2 mappings overlap");
//  NS_ASSERT_MSG(m_TxMappings.AddMapping( mapping  ) >= 0, "2 mappings overlap");
//
//  //}
//  NS_LOG_DEBUG("mapped updated: " << mapping);
//
//  int res = TcpSocketBase::Send(p,0);
//
//  NS_ASSERT(ret >= 0);

//  return res;
}



uint32_t
MpTcpSubflow::SendDataPacket(SequenceNumber32 seq, uint32_t maxSize, bool withAck)
{
  //!
//  NS_LOG_FUNCTION (this << "seq" << seq << "with max size " << maxSize << "and ack"<< withAck);  //NS_LOG_INFO("SendDataPacket -> SeqNb: " << seq);
  TcpHeader header;

  GenerateEmptyPacketHeader(header, withAck ? TcpHeader::ACK : 0);

  return SendDataPacket( header, seq, maxSize);
}

//uint32_t
//MpTcpSubflow::SendDataPacket(TcpHeader& header, const SequenceNumber32& ssn, uint32_t maxSize)
//{
//
//}


  /* We don't automatically embed mappings since we want the possibility to create mapping spanning over several segments


//   here, it should already have been put in the packet, we just check
//  that the

*/

// pass as const ref
void
MpTcpSubflow::SendPacket(TcpHeader header, Ptr<Packet> p)
{
  MpTcpMapping mapping;

  SequenceNumber32 ssnHead = header.GetSequenceNumber();
//  uint32_t p->GetSize()
  SequenceNumber32 ssnTail = ssnHead + SequenceNumber32(p->GetSize());

//  uint32_t coveredLen = 0;
  /**
  TODO move that to SendPacket

  In this loop, we make sure we don't send data for which there is no
  Tx mapping. A packet may be spanned over
   Packets may contain data described by several mappings
  */
  while(ssnHead < ssnTail)
  {
    NS_LOG_DEBUG("Looking for mapping that overlaps with ssn " << ssnHead);

    // TODO je viens de le changer
//    NS_ASSERT_MSG(m_TxMappings.FindOverlappingMapping(ssnHead, ssnTail - ssnHead, mapping), "Sent data not covered by mappings");
    NS_ASSERT_MSG( m_TxMappings.GetMappingForSSN(ssnHead, mapping), "Sent data not covered by mappings");
//    ssnTail =
//    NS_ASSERT_MSG(mapping.HeadSSN() <= ssnHead, "Mapping can only start");

    ssnHead = mapping.TailSSN() + SequenceNumber32(1);
    NS_LOG_DEBUG("mapping " << mapping << " covers it");

  }

  TcpSocketBase::SendPacket(header,p);
}

/**
**/
uint32_t
MpTcpSubflow::SendDataPacket(TcpHeader& header, const SequenceNumber32& ssnHead, uint32_t length)
{
  NS_LOG_FUNCTION(this << "Sending packet starting at SSN [" << ssnHead.GetValue() << "] with len=" << length);


  MpTcpMapping mapping;

  bool result = m_TxMappings.GetMappingForSSN(ssnHead, mapping);
  if(!result)
  {
    m_TxMappings.Dump();
    NS_FATAL_ERROR("Could not find mapping associated to ssn");
  }

  Ptr<TcpOptionMpTcpDSS> dsnOption = Create<TcpOptionMpTcpDSS>();
  // TODO don't send  mapping for every subsequent packet
  dsnOption->SetMapping(mapping);



//  NS_ASSERT( dsnOption->GetMapping().HeadSSN() )
  header.AppendOption(dsnOption);


  //! We put a dack in every segment 'coz wi r crazy YOUHOU
  GetMeta()->AppendDataAck( header );

  // Here we set the maxsize to the size of the mapping
  return TcpSocketBase::SendDataPacket(header, ssnHead, mapping.GetLength());
}


/*
behavior should be the same as in TcpSocketBase
TODO check if m_cWnd is

*/
void
MpTcpSubflow::Retransmit(void)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_LOGIC (this << " ReTxTimeout Expired at time " << Simulator::Now ().GetSeconds ()
  << "Exiting Fast recovery  (previously set to " << m_inFastRec << ")");
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




  m_rtt->IncreaseMultiplier ();             // Double the next RTO
  DoRetransmit ();                          // Retransmit the packet

//  TcpSocketBase::Retransmit();

//  NS_FATAL_ERROR("TODO retransmit");
  // pass on mapping


}


void
MpTcpSubflow::DoRetransmit()
{
  // TODO maybe this call should go to DoRetransmit
  GetMeta()->OnSubflowRetransmit(this);

  // TODO this can't work, we need to regenerate the DSS and embed it
//  TcpSocketBase::DoRetransmit();

  NS_LOG_FUNCTION (this);
  // Retransmit SYN packet
  if (m_state == SYN_SENT)
    {
      if (m_cnCount > 0)
        {
          NS_FATAL_ERROR("Not implemented yet");
          SendEmptyPacket(TcpHeader::SYN);
        }
      else
        {
          NotifyConnectionFailed();
        }
      return;
    }
  // Retransmit non-data packet: Only if in FIN_WAIT_1 or CLOSING state
  if (m_txBuffer.Size() == 0)
    {
      if (m_state == FIN_WAIT_1 || m_state == CLOSING)
        {
          NS_FATAL_ERROR("Not implemented yet");
          // Must have lost FIN, re-send
          SendEmptyPacket(TcpHeader::FIN);
        }
      return;
    }
  // Retransmit a data packet: Call SendDataPacket
  NS_LOG_LOGIC ("TcpSocketBase " << this << " retxing seq " << FirstUnackedSeq());


  /**
  We want to send mappings only
  **/
  MpTcpMapping mapping;
  if(!m_TxMappings.GetMappingForSSN(FirstUnackedSeq(), mapping))
//  if(!m_RxMappings.TranslateSSNtoDSN(headSSN, dsn))
  {
    m_TxMappings.Dump();
    NS_FATAL_ERROR("Could not associate a mapping to ssn [" << FirstUnackedSeq() << "]. Should be impossible");
  }

  // TODO maybe we could set an option to tell SendDataPacket to trim the packet
  // normally here m_nextTxSequence has been set to firstUna
  uint32_t sz = SendDataPacket(FirstUnackedSeq(), mapping.GetLength(), true);
  // In case of RTO, advance m_nextTxSequence
  m_nextTxSequence = std::max(m_nextTxSequence.Get(), FirstUnackedSeq() + sz);
  //reTxTrack.push_back(std::make_pair(Simulator::Now().GetSeconds(), ns3::TcpNewReno::cWnd));
}

/**
Received a packet upon LISTEN state.
En fait il n'y a pas vraiment de ProcessListen :s si ?
TODO remove that one, it should never be called ?
*/
void
MpTcpSubflow::ProcessListen(Ptr<Packet> packet, const TcpHeader& tcpHeader, const Address& fromAddress, const Address& toAddress)
{
  NS_LOG_FUNCTION (this << tcpHeader);

  NS_FATAL_ERROR("This function should never be called, shoud it ?!");

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
  // TODO should be moved to
  if (!NotifyConnectionRequest(fromAddress))
    {
      return;
    }

  NS_LOG_LOGIC("Updating receive window" << tcpHeader.GetWindowSize());
  GetMeta()->SetRemoteWindow(tcpHeader.GetWindowSize());

  // Clone the socket, simulate fork
//  Ptr<MpTcpSubflow> newSock = Fork();
  Ptr<MpTcpSubflow> newSock = ForkAsSubflow();
  NS_LOG_LOGIC ("Cloned a TcpSocketBase " << newSock);
  // TODO TcpSocketBase::
  Simulator::ScheduleNow(
      &MpTcpSubflow::CompleteFork,
      newSock,
      packet,
      tcpHeader,
      fromAddress,
      toAddress
      );
}

Ptr<MpTcpSocketBase>
MpTcpSubflow::GetMeta() const
{
  NS_ASSERT(m_metaSocket);
  //!
  return m_metaSocket;
}

/*
It is also encouraged to
   reduce the timeouts (Maximum Segment Life) on subflows at end hosts.
Move TCP to Time_Wait state and schedule a transition to Closed state
*/
void
MpTcpSubflow::TimeWait()
{
  NS_LOG_INFO (TcpStateName[m_state] << " -> TIME_WAIT");
  m_state = TIME_WAIT;
  CancelAllTimers();
  // Move from TIME_WAIT to CLOSED after 2*MSL. Max segment lifetime is 2 min
  // according to RFC793, p.28
  m_timewaitEvent = Simulator::Schedule(Seconds( m_msl), &MpTcpSubflow::CloseAndNotify, this);
}

void
MpTcpSubflow::ProcessEstablished(Ptr<Packet> packet, const TcpHeader& header)
{
//  Ptr<TcpOptionMpTcpDSS> dss;
//
//  //! TODO in the long term, I should rather loop over options and assign a callback ?
//  if(GetMpTcpOption(header, dss))
//  {
//    ParseDSS(packet,header,dss);
//  }

  TcpSocketBase::ProcessEstablished(packet,header);
}

/**
I ended up duplicating this code to update the meta r_Wnd, which would have been hackish otherwise

**/
void
MpTcpSubflow::DoForwardUp(Ptr<Packet> packet, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface> incomingInterface)
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

  GetMeta()->ProcessMpTcpOptions(tcpHeader, this);

  //NS_LOG_INFO("After cuttingHeader: " << packet->GetSize());
  // Update Rx window size, i.e. the flow control window
//  TODO this will be done in meta
//  if (m_rWnd.Get() == 0 && tcpHeader.GetWindowSize() != 0)
//    { // persist probes end
//      NS_LOG_LOGIC (this << " Leaving zerowindow persist state");
//      m_persistEvent.Cancel();
//    }

//  m_rWnd = tcpHeader.GetWindowSize();
//  GetMeta()->m_rWnd = tcpHeader.GetWindowSize();

  /*  Update of receive window:

  If we are in master socket, in SYN_SENT or SYN_RCVD state then the connection should not be qualified
  as an mptcp connection yet, so we are allowed to save the receive window.
  When the connection qualifies as MPTCP, we copy the receive window value into the meta.

  As soon as the connection qualifies as an MPTCP connection, then there is only one possible way to update
  the receiver window, as explained in http://www.rfc-editor.org/rfc/rfc6824.txt :
      "The sender remembers receiver window advertisements from the
     receiver.  It should only update its local receive window values when
     the largest sequence number allowed (i.e., DATA_ACK + receive window)
     increases, on the receipt of a DATA_ACK. "
  */
  if(IsMaster() && (m_state == SYN_SENT || m_state == SYN_RCVD) ) {
      NS_LOG_LOGIC("Connection does not qualify as MPTCP yet so we can update receive window");
//      GetMeta()->SetRemoteWindow(tcpHeader.GetWindowSize());
        m_rWnd = tcpHeader.GetWindowSize();
  }



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
MpTcpSubflow::ProcessClosing(Ptr<Packet> packet, const TcpHeader& tcpHeader)
{
  NS_LOG_FUNCTION (this << tcpHeader);

//  ProcessOptions()

  return TcpSocketBase::ProcessClosing(packet,tcpHeader);
}

/** Received a packet upon CLOSE_WAIT, FIN_WAIT_1, or FIN_WAIT_2 states */
void
MpTcpSubflow::ProcessWait(Ptr<Packet> packet, const TcpHeader& tcpHeader)
{
  NS_LOG_FUNCTION (this << tcpHeader);


  TcpSocketBase::ProcessWait(packet,tcpHeader);
}

/** Deallocate the end point and cancel all the timers */
void
MpTcpSubflow::DeallocateEndPoint(void)
{
  if (m_endPoint != 0)
    {
      m_endPoint->SetDestroyCallback(MakeNullCallback<void>());

      /* TODO we should not deallocate the endpoint as long as either the meta or this subflow
      is alive !
      */
      if(!IsMaster() ) {
        m_tcp->DeAllocate(m_endPoint);
      }
      m_endPoint = 0;

      Ptr<TcpSocketBase> tmp( (TcpSocketBase*)this);
      Ptr<TcpSocketBase> tmp3(this);
      TcpSocketBase* tmp2 = (TcpSocketBase*)this;
      std::vector<Ptr<TcpSocketBase> >::iterator it = std::find(
            m_tcp->m_sockets.begin(), m_tcp->m_sockets.end(),
            tmp2
            );
      if (it != m_tcp->m_sockets.end())
        {
          m_tcp->m_sockets.erase(it);
        }
      CancelAllTimers();
    }
//  if (m_endPoint6 != 0)
//    {
//      m_endPoint6->SetDestroyCallback(MakeNullCallback<void>());
//      m_tcp->DeAllocate(m_endPoint6);
//      m_endPoint6 = 0;
//      std::vector<Ptr<TcpSocketBase> >::iterator it = std::find(m_tcp->m_sockets.begin(), m_tcp->m_sockets.end(), this);
//      if (it != m_tcp->m_sockets.end())
//        {
//          m_tcp->m_sockets.erase(it);
//        }
//      CancelAllTimers();
//    }
}


void
MpTcpSubflow::CompleteFork(Ptr<Packet> p, const TcpHeader& h, const Address& fromAddress, const Address& toAddress)
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

//    m_tcp->m_sockets.push_back(this);

//  if(IsMaster())
//  {
//
//    NS_LOG_LOGIC("Is master, setting endpoint token");
//
//  }

  // Change the cloned socket from LISTEN state to SYN_RCVD
  NS_LOG_INFO ( TcpStateName[m_state] << " -> SYN_RCVD");
  m_state = SYN_RCVD;
  m_cnCount = m_cnRetries;

  InitializeCwnd();

  SetupCallback();

  // TODO make it so that m_txBuffer becomes useless (it is used only to assign
  // SSN <-> DSN mappings
//  m_TxMappings.m_txBuffer = &m_txBuffer;
//  m_RxMappings.m_rxBuffer = &m_rxBuffer;

  // Set the sequence number and send SYN+ACK (ok)
  m_rxBuffer.SetNextRxSequence(h.GetSequenceNumber() + SequenceNumber32(1));



  TcpHeader answerHeader;
  GenerateEmptyPacketHeader(answerHeader, TcpHeader::SYN | TcpHeader::ACK );



  AppendMpTcp3WHSOption(answerHeader);

//  NS_ASSERT( answerHeader.HasOption(TcpOption::P))
  SendEmptyPacket(answerHeader);
}

Ptr<MpTcpPathIdManager>
MpTcpSubflow::GetIdManager()
{
  return GetMeta()->m_remotePathIdManager;
}


void
MpTcpSubflow::InitializeCwnd (void)
{
  NS_LOG_LOGIC(this << "InitialCWnd:" << m_initialCWnd << " SegmentSize:" << m_segmentSize);
  /*
   * Initialize congestion window, default to 1 MSS (RFC2001, sec.1) and must
   * not be larger than 2 MSS (RFC2581, sec.3.1). Both m_initiaCWnd and
   * m_segmentSize are set by the attribute system in ns3::TcpSocket.
   */
  m_cWnd = GetInitialCwnd() * GetSegSize();
  NS_LOG_DEBUG("m_cWnd set to " << m_cWnd);
}


/**
Apparently this function is never called for now
**/
void
MpTcpSubflow::ConnectionSucceeded(void)
{

  NS_LOG_LOGIC(this << "Connection succeeded");
  m_connected = true;
//  GetMeta()->OnSubflowEstablishment(this);
//  TcpSocketBase::ConnectionSucceeded();
}

/** Received a packet upon SYN_SENT */
void
MpTcpSubflow::ProcessSynSent(Ptr<Packet> packet, const TcpHeader& tcpHeader)
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

      NS_LOG_INFO("Received a SYN/ACK as answer");

//      Simulator::ScheduleNow(&MpTcpSubflow::ConnectionSucceeded, this);

      uint8_t addressId = 0;

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

        addressId = join->GetAddressId();
        // TODO Here we should check the tokens
//        uint8_t buf[20] =
//        opt3->GetTruncatedHmac();
      }

      m_retxEvent.Cancel();
      m_rxBuffer.SetNextRxSequence(tcpHeader.GetSequenceNumber() + SequenceNumber32(1));
      m_highTxMark = ++m_nextTxSequence;
      SetTxHead(m_nextTxSequence);

      // TODO support IPv6
      GetIdManager()->AddRemoteAddr(addressId, m_endPoint->GetPeerAddress(), m_endPoint->GetPeerPort() );

      TcpHeader answerHeader;
      GenerateEmptyPacketHeader(answerHeader, TcpHeader::ACK);
      AppendMpTcp3WHSOption(answerHeader);

      NS_LOG_INFO ("SYN_SENT -> ESTABLISHED");
      m_state = ESTABLISHED;

      // TODO send ConnectionSucceeded or NotifyNewConnectionCreated ?
//      GetMeta()->OnSubflowEstablishment(this);
//      m_connected = true;


//      NS_LOG_LOGIC("Updating receive window");
//      GetMeta()->SetRemoteWindow(tcpHeader.GetWindowSize());



      // TODO here we send a packet  with wrong seq number
      // and another ack will be emitted just after
      SendEmptyPacket(answerHeader);

//      NS_LOG_UNCOND("m_nextTxSequence [" << m_nextTxSequence << "]");

      // TODO check we can send rightaway data ?
      SendPendingData(m_connected);

//      NS_LOG_UNCOND("m_nextTxSequence [" << m_nextTxSequence << "]");

      // Always respond to first data packet to speed up the connection.
      // Remove to get the behaviour of old NS-3 code.
      m_delAckCount = m_delAckMaxCount;
//      initialSeqNb = tcpHeader.GetAckNumber().GetValue();
//      NS_LOG_INFO("initialSeqNb: " << initialSeqNb);
    }
  else
    {
      NS_LOG_WARN("Unexpected case");

      // Other in-sequence input
      if (tcpflags != TcpHeader::RST)
        { // When (1) rx of FIN+ACK; (2) rx of FIN; (3) rx of bad flags
          NS_LOG_LOGIC ("Illegal flag " << TcpHeaderFlagsToString(tcpflags) << " received. Reset packet is sent.");
          SendRST();
        }
      CloseAndNotify();
    }
}


//void
//MpTcpSubflow::SendEmptyPacket(TcpHeader& header)
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
MpTcpSubflow::AppendMpTcp3WHSOption(TcpHeader& hdr) const
{
  //NS_ASSERT(m_state == SYN_SENT || m_state == SYN_RCVD);
  NS_LOG_FUNCTION(this << hdr);

  if( IsMaster() )
  {
    //! Use an MP_CAPABLE option
    Ptr<TcpOptionMpTcpCapable> mpc =  CreateObject<TcpOptionMpTcpCapable>();
    switch(hdr.GetFlags())
    {
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
//          uint32_t token = 0;
//          uint64_t idsn = 0;
//          int result = 0;
//          result =
//          MpTcpSocketBase::GenerateTokenForKey( MPTCP_SHA1, GetMeta()->GetRemoteKey(), token, idsn );

          join->SetPeerToken(GetMeta()->m_peerToken);
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
          //! TODO request from idmanager an id
          static uint8_t id = 0;
          // TODO
          NS_LOG_WARN("IDs are incremental, there is no real logic behind it yet");
  //        id = GetIdManager()->GetLocalAddrId( InetSocketAddress(m_endPoint->GetLocalAddress(),m_endPoint->GetLocalPort()) );
          join->SetAddressId( id++ );
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


int
MpTcpSubflow::Listen(void)
{
  NS_FATAL_ERROR("This should never be called. The meta will make the subflow pass from LISTEN to ESTABLISHED.");
}

void
MpTcpSubflow::NotifySend (uint32_t spaceAvailable)
{
  GetMeta()->NotifySend(spaceAvailable);
}

// TODO and normally I should wait for a fourth ack
void
MpTcpSubflow::ProcessSynRcvd(Ptr<Packet> packet, const TcpHeader& tcpHeader, const Address& fromAddress,
    const Address& toAddress)
{
  //!
  NS_LOG_FUNCTION (this << tcpHeader);




  // Extract the flags. PSH and URG are not honoured.
  uint8_t tcpflags = tcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG);

  //! TODO replace by FirstUnack
  if (tcpflags == 0 || (tcpflags == TcpHeader::ACK && m_nextTxSequence + SequenceNumber32(1) == tcpHeader.GetAckNumber()))
    { // If it is bare data, accept it and move to ESTABLISHED state. This is
      // possibly due to ACK lost in 3WHS. If in-sequence ACK is received, the
      // handshake is completed nicely.

      m_connected = true;
      m_retxEvent.Cancel();
      m_highTxMark = ++m_nextTxSequence;
      SetTxHead(m_nextTxSequence);

//      NS_LOG_LOGIC("Updating receive window");
//      GetMeta()->SetRemoteWindow(tcpHeader.GetWindowSize());

//0.07s 0 0.07 [node 0: ] MpTcpSubflow:ProcessSynRcvd(0x1f1cc20, 4420 > 50000 [ ACK ] Seq=1 Ack=1 Win=65535
//ns3::TcpOptionMpTcpMain(MP_JOIN: [Ack] with hash [TODO]) ns3::TcpOptionMpTcpMain( MP_DSS: Acknowledges [1680] ))
      // Expecting ack
      Ptr<TcpOptionMpTcpCapable> mp_capable;
      Ptr<TcpOptionMpTcpJoin>    mp_join;
      if(GetMpTcpOption(tcpHeader, mp_capable))
      {
        NS_LOG_INFO("Received a MP_CAPABLE");
        NS_ASSERT_MSG( IsMaster(), "Makes no sense to receive an MP_CAPABLE if we are not the master subflow");
      }
      else if(GetMpTcpOption(tcpHeader, mp_join))
      {
        NS_LOG_INFO("Received a MP_JOIN");
        NS_ASSERT_MSG( !IsMaster(), "Makes no sense to receive an MP_JOIN if we are the master");

      }
      else
      {
        NS_FATAL_ERROR("We should have received either an MP_JOIN or MP_CAPABLE. Fallback to TCP is not supported.");
      }
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

      NS_LOG_INFO ( "SYN_RCVD -> ESTABLISHED");
      // TODO we should check for the mptcp capable option
      m_state = ESTABLISHED;

      // Always respond to first data packet to speed up the connection.
      // Remove to get the behaviour of old NS-3 code.
      m_delAckCount = m_delAckMaxCount;
      ReceivedAck(packet, tcpHeader);

      // TODO this may be remvoed otherwise it will be
//      GetMeta()->OnSubflowEstablishment(this);

//      NotifyNewConnectionCreated(this, fromAddress);
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
          SetTxHead(m_nextTxSequence);
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
MpTcpSubflow::SendPendingData(bool withAck)
{
  //!
  NS_LOG_FUNCTION(this);
  return TcpSocketBase::SendPendingData(withAck);
}


/**
TODO m_masterSocket should not be necessary
*/
bool
MpTcpSubflow::IsMaster() const
{
  NS_ASSERT(GetMeta());

  return m_masterSocket;
  // TODO it will never return true
//  TcpStates_t metaState = GetMeta()->GetState();
//  return (metaState == SYN_RCVD
//      || metaState == SYN_SENT
//    || m_endPoint == GetMeta()->m_endPoint
//); // This is master subsock, its endpoint is the same as connection endpoint.
  // is that enough ?
//  return (m_metaSocket->m_subflows.size() == 1);
}


bool
MpTcpSubflow::BackupSubflow() const
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
MpTcpSubflow::AdvertiseAddress(Ipv4Address addr, uint16_t port)
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
MpTcpSubflow::StopAdvertisingAddress(Ipv4Address address)
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




//void
//MpTcpSubflow::StartTracing( std::string traced)
//{
//  //NS_LOG_UNCOND("("<< m_routeId << ") MpTcpSubflow -> starting tracing of: "<< traced);
//  TraceConnectWithoutContext(traced, MakeCallback(&MpTcpSubflow::CwndTracer, this)); //"CongestionWindow"
//}


void
MpTcpSubflow::ReTxTimeout()
{
  NS_LOG_LOGIC("MpTcpSubflow ReTxTimeout expired !");
  TcpSocketBase::ReTxTimeout();
}



/*
   The sender MUST keep data in its send buffer as long as the data has
   not been acknowledged at both connection level and on all subflows on
   which it has been sent.

For now assume
Called from NewAck, this
SequenceNumber32 const& ack,
*/
bool
MpTcpSubflow::DiscardAtMostOneTxMapping(SequenceNumber32 const& firstUnackedMeta, MpTcpMapping& mapping)
//MpTcpSubflow::DiscardTxMappingsUpTo(SequenceNumber32 const& dack, SequenceNumber32 const& ack)
{
  NS_LOG_DEBUG("Removing mappings with DSN <" << firstUnackedMeta
          << " and SSN <" << FirstUnackedSeq()
          );

//  while(true) {

  SequenceNumber32 headSSN = m_txBuffer.HeadSequence();


  //  MpTcpMapping mapping;
  // m_state == FIN_WAIT_1 &&
  if(headSSN >= FirstUnackedSeq())
  {
    NS_LOG_DEBUG("Subflow tx Buffer already empty");
    return false;
  }
  else if(!m_TxMappings.GetMappingForSSN(headSSN, mapping))
  {
    m_TxMappings.Dump();
    NS_LOG_ERROR("Could not associate a tx mapping to ssn [" << headSSN << "]. Should be impossible");
//    NS_FATAL_ERROR("Could not associate a tx mapping to ssn [" << headSSN << "]. Should be impossible");
    return false;
  }

  if(mapping.TailDSN() < firstUnackedMeta && mapping.TailSSN() < FirstUnackedSeq())
  {
    NS_LOG_DEBUG("mapping can be discarded");
    NS_ASSERT(m_TxMappings.DiscardMapping(mapping));
    m_txBuffer.DiscardUpTo(mapping.TailSSN() + SequenceNumber32(1));
    return true;
  }

//  }
  return false;
}




uint32_t
MpTcpSubflow::GetTxAvailable() const
{
  //!
  return TcpSocketBase::GetTxAvailable();
}

/**
TODO check with its parent equivalent, may miss a few features
Receipt of new packet, put into Rx buffer

SlowStart and fast recovery remains untouched in MPTCP.
The reaction should be different depending on if we handle NR-SACK or not
*/
void
MpTcpSubflow::NewAck(SequenceNumber32 const& ack)
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
      NS_LOG_INFO ("Exiting fast recovery. Reset cwnd to " << m_cWnd);
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
      m_retxEvent = Simulator::Schedule(m_rto, &MpTcpSubflow::ReTxTimeout, this);
    }

  if (m_rWnd.Get() == 0 && m_persistEvent.IsExpired())
    { // Zero window: Enter persist state to send 1 byte to probe
      NS_LOG_LOGIC (this << "Enter zerowindow persist state");NS_LOG_LOGIC (this << "Cancelled ReTxTimeout event which was set to expire at " <<
          (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
      m_retxEvent.Cancel();
      NS_LOG_LOGIC ("Schedule persist timeout at time " <<
          Simulator::Now ().GetSeconds () << " to expire at time " <<
          (Simulator::Now () + m_persistTimeout).GetSeconds ());
      m_persistEvent = Simulator::Schedule(m_persistTimeout, &MpTcpSubflow::PersistTimeout, this);
      NS_ASSERT(m_persistTimeout == Simulator::GetDelayLeft (m_persistEvent));
    }

  // Note the highest ACK and tell app to send more
  NS_LOG_LOGIC ("TCP " << this << " NewAck " << ack <<
      " numberAck " << (ack - FirstUnackedSeq())); // Number bytes ack'ed


  m_firstTxUnack = std::min(ack, m_txBuffer.TailSequence());

  // TODO: get mapping associated with that Ack and
  // TODO could && m_state != FIN_WAIT_1
  // TODO I believe we could change that into something else
  if(!m_TxMappings.GetMappingForSSN( SequenceNumber32(ack-1), mapping) ) {

    NS_LOG_WARN("Late ack ! Mapping likely to have been discared already. Dumping Tx Mappings:");
    m_TxMappings.Dump();
  }
  else {
    // TODO check if all mappings below that are acked before removing them
    //    m_txBuffer.DiscardUpTo(ack);

    /** TODO here we have to update the nextTxBuffer
    but we can discard only if the full mapping was acknowledged
    la c completement con. A corriger
    */
//    if(m_nextTxSequence > mapping.TailSSN()) {
//
//      m_txBuffer.DiscardUpTo(m_nextTxSequence);
//    }
//      std::distance(s.begin(), s.lower_bound(x))
    // #error

    /**
    Before removing data from txbuffer, it must have been acked at both subflow
    and connection level.
    Here we go through the list of TxMappings
    min(ack,dataack
    **/
//    m_TxMappings.DiscardMappingsUpToDSN()


  }


  GetMeta()->OnSubflowNewAck(this);
// TODO I should call


  if (GetTxAvailable() > 0)
    {
      // Ok, va appeler la meta
      NotifySend(GetTxAvailable());
    }

  if (ack > m_nextTxSequence)
    {
//      if(m_state == FIN_WAIT_1 || m_state == CLOSING) {
//
//      }
//      NS_LOG_DEBUG("Advancing m_nextTxSequence from " << m_nextTxSequence  << " to " << ack);
      m_nextTxSequence = std::min(ack, m_txBuffer.TailSequence()); // If advanced
    }

  if (m_txBuffer.Size() == 0 && m_state != FIN_WAIT_1 && m_state != CLOSING)
    {
      // No retransmit timer if no data to retransmit
      NS_LOG_WARN (this << "TxBuffer empty. Cancelled ReTxTimeout event which was set to expire at " <<
          (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
      m_retxEvent.Cancel();
      return;
    }

  if (m_txBuffer.Size() == 0)
    {
      NS_LOG_DEBUG("No tx buffer");
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
//MpTcpSubflow::DiscardTxMappingsUpToDSN(SequenceNumber32 seq)
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
MpTcpSubflow::RecvFrom(uint32_t maxSize, uint32_t flags, Address &fromAddress)
{
  NS_FATAL_ERROR("Disabled in MPTCP. Use ");
  return 0;
}

Ptr<Packet>
MpTcpSubflow::Recv(uint32_t maxSize, uint32_t flags)
{
  //!
  NS_FATAL_ERROR("Disabled in MPTCP. Use ");
  return 0;
}

Ptr<Packet>
MpTcpSubflow::Recv(void)
{
  //!
  NS_FATAL_ERROR("Disabled in MPTCP. Use ");
  return 0;
}


//bool
//MpTcpSubflow::TranslateSSNtoDSN(SequenceNumber32 ssn,SequenceNumber32 &dsn)
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

/**
this is private
**/
Ptr<Packet>
MpTcpSubflow::ExtractAtMostOneMapping(uint32_t maxSize, bool only_full_mapping, SequenceNumber32& headDSN)
{
  NS_LOG_DEBUG(this << " maxSize="<< maxSize);
  MpTcpMapping mapping;
  Ptr<Packet> p = Create<Packet>();

  if(!GetRxAvailable()) {
    NS_LOG_LOGIC("Nothing to extract");
    return p;
  }

  // as in linux, we extract in order
  SequenceNumber32 headSSN = m_rxBuffer.HeadSequence();

//  NS_LOG_LOGIC("Extracting from SSN [" << headSSN << "]");
  //SequenceNumber32 headDSN;


   if(!m_RxMappings.GetMappingForSSN(headSSN, mapping))
//  if(!m_RxMappings.TranslateSSNtoDSN(headSSN, dsn))
  {
    m_RxMappings.Dump();
    NS_FATAL_ERROR("Could not associate a mapping to ssn [" << headSSN << "]. Should be impossible");
  }
  NS_LOG_DEBUG("Extracting mapping " << mapping);

  headDSN = mapping.HeadDSN();

  if(only_full_mapping) {

    if(mapping.GetLength() > maxSize) {
      NS_LOG_DEBUG("Not enough space available to extract the full mapping");
      return p;
    }

    if(m_rxBuffer.Available() < mapping.GetLength()) {
      NS_LOG_DEBUG("Mapping not fully received yet");
      return p;
    }


  }

  // Extract at most one mapping
  maxSize = std::min(maxSize, (uint32_t)mapping.GetLength());

  NS_LOG_DEBUG("Extracting at most " << maxSize << " bytes ");
  p = m_rxBuffer.Extract( maxSize );

//  m_RxMappings.DiscardMappingsUpToDSN( headDSN);
  // Not included

  // TODO seulement supprimer ce que l'on a extrait !
  SequenceNumber32 extractedTail = headSSN + p->GetSize() - 1;

  NS_LOG_DEBUG("ExtractedTail=" << extractedTail << " to compare with " << mapping.TailSSN());

  NS_ASSERT_MSG( extractedTail <= mapping.TailSSN(), "Can not extract more than the size of the mapping");

  if(extractedTail < mapping.TailSSN() )
  {
    NS_ASSERT_MSG(!only_full_mapping, "The only extracted size possible should be the one of the mapping");
    // only if data extracted covers full mapping we can remove the mapping

  }
  else {
    m_RxMappings.DiscardMapping(mapping);
  }
//  m_RxMappings.DiscardMappingsUpToSN( mapping.TailDSN() + SequenceNumber32(1), mapping.TailSSN());
  return p;
}

/*
This loops over the RxBuffer, extracting mapping one after mapping.

sf->
*/
#if 0
Ptr<Packet>
MpTcpSubflow::RecvWithMapping(uint32_t maxSize, bool only_full_mapping, SequenceNumber32 &dsn)
{
  NS_LOG_FUNCTION(this << "maxSize="<< maxSize);
  NS_FATAL_ERROR("Use ExtractAtMostOneMapping instead");
//  Ptr<Packet> p;

//
////  if (m_rxBuffer.Size() == 0 && m_state == CLOSE_WAIT)
//  if (m_state == CLOSE_WAIT)
//    {
//      NS_LOG_ERROR("CLOSE_WAIT");
      return Create<Packet>(); // Send EOF on connection close
//    }
//
//
//  return ExtractAtMostOneMapping();
}
#endif




//void
//MpTcpSubflow::SetupTracing(const std::string prefix)
//{
//
//}


/**
TODO here I should look for an associated mapping.

ProcessEstablished

If there is not, then I discard the stuff
std::ostream& ns3::operator<<(std::ostream&,const ns3::TcpOptionMptcpMain&)

TODO I should also notify the meta, maybe with an enum saying if it's new data/old etc...
*/
void
MpTcpSubflow::ReceivedData(Ptr<Packet> p, const TcpHeader& tcpHeader)
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


//  OutOfRange
  // If cannot find an adequate mapping, then it should [check RFC]
  if(!m_RxMappings.GetMappingForSSN(tcpHeader.GetSequenceNumber(), mapping) )
  {

    m_RxMappings.Dump();
    NS_FATAL_ERROR("Could not find mapping associated ");
    return;
  }

  // Put into Rx buffer
  SequenceNumber32 expectedSSN = m_rxBuffer.NextRxSequence();
  if (!m_rxBuffer.Add(p, tcpHeader))
    { // Insert failed: No data or RX buffer full
      NS_LOG_WARN("Insert failed, No data (" << p->GetSize() << ") ?"
          // Size() returns the actual buffer occupancy
//          << "or RX buffer full (Available:" << m_rxBuffer.Available()
//          << " Occupancy=" << m_rxBuffer.Size()
//          << " OOOSize=" << m_rxBuffer.OutOfOrder ()
//          << " Maxbuffsize=" << m_rxBuffer.MaxBufferSize() << ")"
//          << " or already buffered"
          );
      m_rxBuffer.Dump();

//      dss->SetDataAck( GetMeta()->m_rxBuffer.NextRxSequence().GetValue() );
      // TODO rather use a goto
      TcpHeader answerHeader;
      GenerateEmptyPacketHeader(answerHeader, TcpHeader::ACK);
      GetMeta()->AppendDataAck( answerHeader );
      SendEmptyPacket(answerHeader);
      return;
    }

  // Size() = Get the actual buffer occupancy
  if (m_rxBuffer.Size() > m_rxBuffer.Available() /* Out of order packets exist in buffer */
    || m_rxBuffer.NextRxSequence() > expectedSSN + p->GetSize() /* or we filled a gap */
    )
    { // A gap exists in the buffer, or we filled a gap: Always ACK
      sendAck = true;
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




  // Notify app to receive if necessary
  if (expectedSSN < m_rxBuffer.NextRxSequence())
    { // NextRxSeq advanced, we have something to send to the app
      if (!m_shutdownRecv)
        {
          // todo maybe retrieve return valu: should we send an ack ?
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

    // should be always true hack to allow compilation
    if(sendAck) {
      TcpHeader answerHeader;
      GenerateEmptyPacketHeader(answerHeader, TcpHeader::ACK);
      GetMeta()->AppendDataAck(answerHeader);
      SendEmptyPacket(answerHeader);
    }

  // TODO handle out of order case look at parent's member.
  // TODO pass subflow id to the function
  // TODO if that acknowledges a full mapping then transfer it to  the metasock
}

/* TODO unsure ?

*/
uint32_t
MpTcpSubflow::UnAckDataCount()
{
  NS_LOG_FUNCTION (this);
//  return GetMeta()->UnAckDataCount();
  return TcpSocketBase::UnAckDataCount();
}

// TODO unsure ?
uint32_t
MpTcpSubflow::BytesInFlight()
{
  NS_LOG_FUNCTION (this);
  return TcpSocketBase::BytesInFlight();
}

/* TODO unsure ?
*/
uint32_t
MpTcpSubflow::AvailableWindow()
{
  NS_LOG_FUNCTION (this);

  return TcpSocketBase::AvailableWindow();
//  GetMeta()->AvailableWindow();
}

/* this should be ok
*/
uint32_t
MpTcpSubflow::Window (void)
{
  NS_LOG_FUNCTION (this);
  return std::min ( RemoteWindow(), m_cWnd.Get ());
//  return GetMeta()->Window();
}

uint32_t
MpTcpSubflow::RemoteWindow()
{
  NS_LOG_FUNCTION (this);
  return GetMeta()->RemoteWindow();
}

// Ok
uint16_t
MpTcpSubflow::AdvertisedWindowSize(void)
{
  NS_LOG_DEBUG(this);
  return GetMeta()->AdvertisedWindowSize();
}

/*
   Receive Window:  The receive window in the TCP header indicates the
      amount of free buffer space for the whole data-level connection
      (as opposed to for this subflow) that is available at the
      receiver.  This is the same semantics as regular TCP, but to
      maintain these semantics the receive window must be interpreted at
      the sender as relative to the sequence number given in the
      DATA_ACK rather than the subflow ACK in the TCP header.  In this
      way, the original flow control role is preserved.  Note that some
      middleboxes may change the receive window, and so a host SHOULD
      use the maximum value of those recently seen on the constituent
      subflows for the connection-level receive window, and also needs
      to maintain a subflow-level window for subflow-level processing.



Because of this, an implementation MUST NOT use the RCV.WND
   field of a TCP segment at the connection level if it does not also
   carry a DSS option with a Data ACK field.
*/
void
MpTcpSubflow::SetRemoteWindow(uint32_t win_size)
{
  NS_FATAL_ERROR("This function should never be called. Only meta can update remote window");
//  NS_LOG_FUNCTION(win_size);
//  MpTcpSubflow::GetMeta()->SetRemoteWindow()
//  TcpSocketBase::SetRemoteWindow(win_size);
}


void
MpTcpSubflow::ClosingOnEmpty(TcpHeader& header)
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
MpTcpSubflow::ParseDSS(Ptr<Packet> p, const TcpHeader& header,Ptr<TcpOptionMpTcpDSS> dss)
{
  //!
//  NS_FATAL_ERROR("TO REMOVE. Use meta->ProcessDSS")
  NS_ASSERT(dss);
  GetMeta()->ProcessDSS(header, dss, Ptr<MpTcpSubflow>(this));

}



/*
Upon ack receival we need to act depending on if it's new or not
-if it's new it may allow us to discard a mapping
-otherwise notify meta of duplicate

this is called
*/
void
MpTcpSubflow::ReceivedAck(Ptr<Packet> p, const TcpHeader& header)
{
  NS_LOG_FUNCTION (this << header);

  // if packet size > 0 then it will call ReceivedData
  TcpSocketBase::ReceivedAck(p, header );

}

// TODO remove
bool
MpTcpSubflow::AddPeerMapping(const MpTcpMapping& mapping)
{
  NS_LOG_FUNCTION(this << mapping);

  // MATT
  NS_ASSERT(m_RxMappings.AddMapping( mapping ));
//  m_RxMappings.Dump();
  return true;
}

} // end of ns3
