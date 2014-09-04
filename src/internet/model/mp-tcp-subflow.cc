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
  if (m_node) { std::clog << Simulator::Now ().GetSeconds () << " [node " << m_node->GetId () << "] "; }


#include <iostream>
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

NS_LOG_COMPONENT_DEFINE("MpTcpSubflow");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED(MpTcpSubFlow);

TypeId
MpTcpSubFlow::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::MpTcpSubFlow")
      .SetParent<TcpSocketBase>()
      .AddConstructor<MpTcpSubFlow>()
      // TODO should be inherited
//      .AddTraceSource("cWindow",
//          "The congestion control window to trace.",
//           MakeTraceSourceAccessor(&MpTcpSubFlow::m_cWnd))
    ;
  return tid;
}


TypeId
MpTcpSubFlow::GetInstanceTypeId(void) const
{
  return GetTypeId();
}

//bool
void
MpTcpSubFlow::SetMeta(Ptr<MpTcpSocketBase> metaSocket)
{
  NS_ASSERT(metaSocket);
  NS_ASSERT(m_state == CLOSED);
  NS_LOG_FUNCTION(this);
  m_metaSocket = metaSocket;
//  return true;
}

Ptr<TcpSocketBase>
MpTcpSubFlow::Fork(void)
{
  // Call CopyObject<> to clone me
//  NS_LOG_ERROR("Not implemented");


  return ForkAsSubflow();
}

Ptr<MpTcpSubFlow>
MpTcpSubFlow::ForkAsSubflow(void)
{
  return CopyObject<MpTcpSubFlow> (this);
}


void
MpTcpSubFlow::DupAck(const TcpHeader& t, uint32_t count)
{
  NS_LOG_DEBUG("DupAck ignored as specified in RFC");
//  if( count > 3)

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
uint32_t
MpTcpSubFlow::GetLocalToken() const
{
//  NS_LOG_ERROR("Not implemented yet");
  // TODO
  return GetMeta()->GetLocalKey() >> 32 ;
}

uint32_t
MpTcpSubFlow::GetRemoteToken() const
{
//  NS_LOG_ERROR("Not implemented yet");
  return GetMeta()->GetLocalKey() >> 32 ;

}




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
  m_localNonce(sock.m_localNonce),
  m_remoteToken(sock.m_remoteToken)
  // TODO
//    m_initialCWnd (sock.m_initialCWnd),
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
    m_ssThresh(65535),  // retrieve from meta CC set in parent's ?
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
//  m_metaSocket->CloseSubflow( m_routeId );
  TcpSocketBase::CloseAndNotify();
}


/**
Maybe we could allow this providing a mapping already exists ?
**/
int
MpTcpSubFlow::Send(Ptr<Packet> p, uint32_t flags)
{
  NS_ASSERT_MSG(false,"Use sendmapping instead");
  return 0;
}

//, uint32_t maxSize
// rename globalSeqNb ?
int
MpTcpSubFlow::SendMapping(Ptr<Packet> p, MpTcpMapping& mapping)
{
  NS_LOG_FUNCTION (this << mapping);
  NS_ASSERT_MSG(mapping.GetDataLevelLength() != 0,"You should fill the mapping" );
  // backup its value because send will change it
  //SequenceNumber32 nextTxSeq = m_nextTxSequence;

  // Check m_txBuffer can handle it otherwise it will get refused

    // Everything went fine
  //if(res >= 0)
  //{*
  // TODO in fact there could be an overlap between recorded mappings and the current one
  // so the following check is not enough. To change later
  if(m_txBuffer.Available() < mapping.GetDataLevelLength())
  {
    NS_LOG_ERROR("Too much data to send");
    return -ERROR_MSGSIZE;
  }


    //MpTcpMapping mapping;
    //mapping.Configure( mptcpSeq, p->GetSize()  );
    mapping.MapToSSN( m_nextTxSequence );

    // record mapping TODO check if it does not already exist
    // TODO GetMappingForDSN
    // GetMappingForSSN
  //GetMappingForSegment(m_TxMappings,)
    m_TxMappings.insert( mapping  );

  //}


  int res = TcpSocketBase::Send(p,0);



  return res;
}


#if 0
void
MpTcpSubFlow::GenerateDataPacketHeader(TcpHeader& header, SequenceNumber32 seq, uint32_t maxSize, bool withAck)
//TcpSocketBase::SendDataPacket(SequenceNumber32 seq, uint32_t maxSize, bool withAck)
{
  NS_LOG_FUNCTION (this << seq << maxSize << withAck);  //NS_LOG_INFO("SendDataPacket -> SeqNb: " << seq);
  Ptr<Packet> p = m_txBuffer.CopyFromSequence(maxSize, seq);
  uint32_t sz = p->GetSize(); // Size of packet
  uint8_t flags = withAck ? TcpHeader::ACK : 0;
  uint32_t remainingData = m_txBuffer.SizeFromSequence(seq + SequenceNumber32(sz));

//  TcpHeader header;
  header.SetFlags(flags);
  header.SetSequenceNumber(seq);
  header.SetAckNumber(m_rxBuffer.NextRxSequence());
  if (m_endPoint)
    {
      header.SetSourcePort(m_endPoint->GetLocalPort());
      header.SetDestinationPort(m_endPoint->GetPeerPort());
    }
  else
    {
      header.SetSourcePort(m_endPoint6->GetLocalPort());
      header.SetDestinationPort(m_endPoint6->GetPeerPort());
    }
  header.SetWindowSize(AdvertisedWindowSize());

}
#endif

// split into 2 functions 1 to GenerateHeaders, other one to add options
// ajouter une fct DoSend
uint32_t
MpTcpSubFlow::SendDataPacket(TcpHeader header, SequenceNumber32 seq, uint32_t maxSize)
{
  NS_LOG_FUNCTION(this);

  MpTcpMapping mapping;
  bool result = GetMappingForSegment( m_TxMappings, seq, mapping);
  NS_ASSERT(result == true);

//  // Add list to ListErrorModel object
//  Ptr<ListErrorModel> rem = CreateObject<ListErrorModel>();
//  rem->SetList(sampleList);

  // Add options afterwards if first packet of the mapping
  if(mapping.GetSSN() == seq  )
  {
    // Add DSN option
    NS_LOG_DEBUG("Adding DSN option");
    Ptr<TcpOptionMpTcpDSS> dsnOption = Create<TcpOptionMpTcpDSS>();
    dsnOption->SetMapping( mapping );
    header.AppendOption( dsnOption );
  }


  return TcpSocketBase::SendDataPacket(header,seq,maxSize);



  #if 0
  NS_LOG_FUNCTION (this << withAck);
  Ptr<Packet> p = m_txBuffer.CopyFromSequence(maxSize, seq);
  uint32_t packetSize = p->GetSize();

  DSNMapping * ptrDSN = 0;
  bool guard = false; // true if timeout occured
//  SequenceNumber32(sFlow->TxSeqNumber)
  /*
   * If timeout happens then TxSeqNumber would be shifted down to the seqNb after highestAck,
   * but maxSeqNb would be still related to maxSeqNb ever sent.
   * Thus we can conclude that when maxSeqNb is bigger than TxSeqNumber -1, we are in timeout has occurred.
   * So we have to send packet from subflowBuffer (m_mapDSN) instead of connection buffer (m_sendingBuffer),
   * In other situations maxSeqNb should be equal to TxSeqNumber -1.
   * Boolean 'guard' become true if timeOut is occurred!!
   */
   // As long as mappings are handled per packet, no need to even register them ?

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
              NS_LOG_ERROR(Simulator::Now().GetSeconds()
                          <<" Oooops- maxSeqNb: " << sFlow->maxSeqNb
                          << " TxSeqNb: " << sFlow->TxSeqNumber
                          << " FastRecovery: "
                          << sFlow->m_inFastRec
                          << " SegNb: " << ptrDSN->subflowSeqNumber
                );
              NS_LOG_WARN("Ooops continue packetSize: " << packetSize
                            << " this is from stored sent segment of number: " << cunt
                );
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
   uint32_t remainingData = m_txBuffer.SizeFromSequence (seq + SequenceNumber32 (packetSize));
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
  header.SetSequenceNumber( seq );
  header.SetAckNumber( m_rxBuffer.NextRxSequence() );
  header.SetSourcePort( m_endPoint->GetLocalPort() );
  header.SetDestinationPort( m_endPoint->GetPeerPort() );
  header.SetWindowSize(AdvertisedWindowSize());

//  if (!guard)
    { // If packet is made from m_sendingBuffer, then we got to add the packet and its info to subflow's m_mapDSN.
//      AddDSNMapping(sFlowIdx, nextTxSequence, packetSize, sFlow->TxSeqNumber, sFlow->RxSeqNumber, p->Copy());
      // if packet is made from m_sendingBuffer, then we use nextTxSequence to OptDSN
      // dataSeq that's why we need a mapping
      header.AddOptDSN(OPT_DSN, seq, packetSize, seq );
    }
//  else
//    { // if packet is made from subflow's Buffer (already sent packets), that packet's dataSeqNumber should be added here!
//      header.AddOptDSN(OPT_DSN, ptrDSN->dataSeqNumber, (uint16_t) packetSize, sFlow->TxSeqNumber);
//      NS_ASSERT(packetSize == ptrDSN->dataLevelLength);
//    }

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
  m_metaSocket->SetReTxTimeout(m_routeId);
  NS_LOG_LOGIC ("Send packet via TcpL4Protocol with flags 0x" << std::hex << static_cast<uint32_t> (flags) << std::dec);

  // simulating loss of acknoledgement in the sender side
//  calculateTotalCWND();
  // This time, we'll explicitly create the error model we want
  // MATT for now don't use any error model
  #if 0
  Ptr<ListErrorModel> rem = CreateObject<ListErrorModel>();
  rem->SetList(sampleList);
  getQueuePkt(sFlow->sAddr);
  if (rem->IsCorrupt(p))
    { // {ranVar < rate => Packet drop...}
      PacketDrop.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd.Get()));
//      uint32_t tmp =
//      (((sFlow->TxSeqNumber + packetSize) - sFlow->initialSequnceNumber) / sFlow->GetSegSize()) % mod
//      ;
//      sFlow->DROP.push_back(make_pair(Simulator::Now().GetSeconds(), tmp));
    }
  else
    {
    #endif

      m_tcp->SendPacket(p, header, m_endPoint->GetLocalAddress(), m_endPoint->GetPeerAddress(), m_endPoint->GetBoundNetDevice() );

//      if (!guard)
//        PktCount++;
//      uint32_t tmp = (((sFlow->TxSeqNumber + packetSize) - sFlow->initialSequnceNumber) / sFlow->GetSegSize()) % mod;
//      sFlow->DATA.push_back(make_pair(Simulator::Now().GetSeconds(), tmp));
//    }

    NS_LOG_WARN(Simulator::Now().GetSeconds() << " ["<< GetNode()->GetId()<< "] SendDataPacket->  " << header <<" dSize: " << packetSize<< " sFlow: " << m_routeId);

  // Do some updates.....
  rtt->SentSeq(SequenceNumber32(sFlow->TxSeqNumber), packetSize); // Notify the RTT of a data packet sent
  TxSeqNumber += packetSize; // Update subflow's nextSeqNum to send.
  maxSeqNb = std::max(sFlow->maxSeqNb, sFlow->TxSeqNumber - 1);
//  if (!guard)
//    {
//      nextTxSequence += packetSize;  // Update connection sequence number
//    }

  NS_LOG_INFO( "("<< (int) sFlowIdx<< ") DataPacket -----> "
        << header
//        << "  " << m_localAddress << ":" << m_localPort
//        << "->" << m_remoteAddress << ":" << m_remotePort
        );

  return packetSize;
//  if (guard)
//    return 0;
//  else
//    return packetSize;
  #endif
}


// TODO inspect
void
MpTcpSubFlow::Retransmit(void)
{
  TcpSocketBase::Retransmit();

  // pass on mapping
  GetMeta()->OnSubflowRetransmit( this );

  // TODO change window ?
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
  Ptr<MpTcpSubFlow> newSock = CopyObject<MpTcpSubFlow>(this);
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
MpTcpSubFlow::DoForwardUp(Ptr<Packet> packet, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface> incomingInterface)
{
  NS_LOG_FUNCTION(this);
  TcpSocketBase::DoForwardUp(packet,header,port,incomingInterface);
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

  SetupCallback();

  // Set the sequence number and send SYN+ACK
  m_rxBuffer.SetNextRxSequence(h.GetSequenceNumber() + SequenceNumber32(1));

  TcpHeader answerHeader;
  GenerateEmptyPacketHeader( answerHeader, TcpHeader::SYN | TcpHeader::ACK );

  m_masterSocket = true;  //!< Only for the master socket is completeFork called
  if( IsMaster() )
  {
    Ptr<TcpOptionMpTcpCapable> mpc = CreateObject<TcpOptionMpTcpCapable>();
    mpc->SetSenderKey( GetMeta()->GetLocalKey() );
    answerHeader.AppendOption( mpc );
    NS_LOG_INFO ("CompleteFork: appended MP_CAPABLE option");
  }
  else
  {
    Ptr<TcpOptionMpTcpJoin> join = CreateObject<TcpOptionMpTcpJoin>();
    join->SetState(TcpOptionMpTcpJoin::Ack);
    //! TODO request from meta its id
    uint8_t id = 0;
    id = GetIdManager()->GetLocalAddrId( InetSocketAddress(m_endPoint->GetLocalAddress(),m_endPoint->GetLocalPort()) );
    join->SetAddressId( id );
    join->SetTruncatedHmac(2);
    join->SetNonce(3);

    answerHeader.AppendOption( join );

    NS_LOG_INFO ("CompleteFork: appended MP_JOIN option");
  }

//  NS_ASSERT( answerHeader.HasOption(TcpOption::P))
  SendEmptyPacket(answerHeader);
}

Ptr<MpTcpPathIdManager>
MpTcpSubFlow::GetIdManager()
{
  return GetMeta()->m_remotePathIdManager;
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
      NS_ASSERT( tcpHeader.HasOption( TcpOption::MPTCP ) );




      // For now we assume there is only one option of MPTCP kind but there may be several
      // TODO update the SOCIS code to achieve this
      Ptr<TcpOption> option = tcpHeader.GetOption(TcpOption::MPTCP);
      Ptr<TcpOptionMpTcpMain> opt2 = DynamicCast<TcpOptionMpTcpMain>(option);

//    Ptr<TcpOption> answerOption;
      TcpHeader answerHeader;
      GenerateEmptyPacketHeader(answerHeader, TcpHeader::ACK);

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
        NS_ASSERT( opt2->GetSubType() == TcpOptionMpTcpMain::MP_CAPABLE );

        Ptr<TcpOptionMpTcpCapable> mpcRcvd = DynamicCast<TcpOptionMpTcpCapable>(option);
        NS_ASSERT_MSG( mpcRcvd,"Contact ns3 team" );
        NS_LOG_INFO("peer key " << mpcRcvd->GetSenderKey() );

        // Register that key
        GetMeta()->SetPeerKey( mpcRcvd->GetSenderKey() );

        // Create final option
        Ptr<TcpOptionMpTcpCapable> mpc = CreateObject<TcpOptionMpTcpCapable>();
        mpc->SetSenderKey( GetMeta()->GetLocalKey() );
        mpc->SetRemoteKey( GetMeta()->GetRemoteKey() );

        answerHeader.AppendOption( mpc );
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
        // expects MP_JOIN option
        NS_ASSERT( opt2->GetSubType() == TcpOptionMpTcpMain::MP_JOIN );
        Ptr<TcpOptionMpTcpJoin> join = DynamicCast<TcpOptionMpTcpJoin>(option);
        // TODO use GetMpTcpOption()
        // TODO should be less restrictive in case there is a loss
        NS_ASSERT_MSG( join && join->GetState() == TcpOptionMpTcpJoin::SynAck, "the MPTCP join option received is not of the expected 1 out of 3 MP_JOIN types." );

        // Here we should check the tokens
//        uint8_t buf[20] =
//        opt3->GetTruncatedHmac();

        Ptr<TcpOptionMpTcpJoin> joinAck = CreateObject<TcpOptionMpTcpJoin>();
        joinAck->SetState(TcpOptionMpTcpJoin::Ack);
        joinAck->SetTruncatedHmac(0);
        answerHeader.AppendOption( joinAck );
      }

      // TODO support IPv6
      GetIdManager()->AddRemoteAddr(0, m_endPoint->GetPeerAddress(), m_endPoint->GetPeerPort() );


      NS_LOG_INFO ("SYN_SENT -> ESTABLISHED");
      m_state = ESTABLISHED;
      m_connected = true;
      m_retxEvent.Cancel();
      m_rxBuffer.SetNextRxSequence(tcpHeader.GetSequenceNumber() + SequenceNumber32(1));
      m_highTxMark = ++m_nextTxSequence;
      m_txBuffer.SetHeadSequence(m_nextTxSequence);



      SendEmptyPacket(answerHeader);

      // TODO check if that's ok
      fLowStartTime = Simulator::Now().GetSeconds();

      // TODO check we can send rightaway data ?
      SendPendingData(m_connected);


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

//TcpOptionMpTcpJoin::State
void
MpTcpSubFlow::AppendMpTcp3WHSOption(TcpHeader& hdr) const
{
  NS_ASSERT(m_state == SYN_SENT || m_state == SYN_RCVD);

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
        join->SetState(TcpOptionMpTcpJoin::Syn);
        join->SetPeerToken(0);
        join->SetNonce(0);
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
          join->SetTruncatedHmac(424242);
          join->SetNonce(4242);
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
Discard mappings up to ack
*/
void
MpTcpSubFlow::DiscardMappingsUpTo( uint32_t ack)
{
  //TODO remove
  #if 0
  MappingList::iterator current = m_mapDSN.begin();
  MappingList::iterator next = m_mapDSN.begin();
  while (current != m_mapDSN.end())
    {
      ++next;
      DSNMapping *ptrDSN = *current;
      // All segments before ackSeqNum should be removed from the m_mapDSN list.
      // Maybe equal part never run due to if condition above.
      if (ptrDSN->subflowSeqNumber + ptrDSN->dataLevelLength <= ack)
        {
          NS_LOG_WARN("DiscardUp-> SeqNb: " << ptrDSN->subflowSeqNumber << " DSNMappingSize: " << m_mapDSN.size() - 1 << " Subflow(" << (int)m_routeId << ")");
          next = m_mapDSN.erase(current);
          delete ptrDSN;
        }
      current = next;
    }
  #endif
}



bool
MpTcpSubFlow::GetMappingForSegment( const MappingList& l, SequenceNumber32 subflowSeqNb, MpTcpMapping& mapping)
{
  for( MappingList::const_iterator it = l.begin(); it != l.end(); it++ )
  {
    // check seq nb is within the DSN range
    if (
      it->IsInRange( subflowSeqNb )
//    (subflowSeqNb >= it->GetSSN() ) &&
//      (subflowSeqNb < it->GetSSN() + it->GetDataLevelLength())
    )
    {
      mapping = *it;
      return true;
    }
  }

  return false;
}



// TODO check with its parent equivalent, may miss a few features
// Receipt of new packet, put into Rx buffer
void
MpTcpSubFlow::NewAck(SequenceNumber32 const& ack)
{
  NS_LOG_FUNCTION (this << ack);

  MpTcpMapping mapping;

  if(!GetMappingForSegment( m_TxMappings, ack-1, mapping) )
  {
    NS_LOG_DEBUG("Could not find an adequate Tx mapping for ack " << ack);
    // TODO remove that later
//    NS_ASSERT_MSG(false,"No mapping received for that ack nb");
//    SendEmptyPacket(TcpHeader::ACK);
    return;
  }

  TcpSocketBase::NewAck( ack );

  // WRONG  they can be sparse. This should be done by meta
  // DiscardTxMappingsUpToDSN( ack );
  //  Je peux pas le discard tant que
  //  m_txBuffer.DiscardUpTo( ack );


  // TODO check the full mapping is reachable
//  if( m_txBuffer.Available(mapping.GetDSN(), mapping.MaxSequence()))
//  {
//    Packet pkt = m_rxBuffer.Extract(mapping.GetDSN(), mapping.GetDataLevelLength() );
//
//    //! pass on data
//    GetMeta()->ReceivedData( pkt, mapping );
//
//  }

}

void
MpTcpSubFlow::DiscardTxMappingsUpToDSN(SequenceNumber32 seq)
{
  NS_LOG_INFO("Discarding mappings up to " << seq);
  MappingList& l = m_TxMappings;
  for( MappingList::iterator it = l.begin(); it != l.end(); it++ )
  {
    //GetDSN
    if( it->MaxDataSequence() < seq  )
    {
      //it =
//      NS_ASSERT( );
      // TODO check mapping transfer was completed on this subflow
//      if( m_txBuffer.HeadSequence() <  )
//      {
//
//      }
      l.erase(it);
    }
  }
}

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


bool
MpTcpSubFlow::TranslateSSNtoDSN(SequenceNumber32 ssn,SequenceNumber32 &dsn)
{
  // first find if a mapping exists
  MpTcpMapping mapping;
  if(!GetMappingForSegment( m_RxMappings, ssn, mapping) )
  {
    //!
    return false;
  }

  return mapping.TranslateSSNToDSN(ssn,dsn);
}

// use with a maxsize ?
Ptr<Packet>
MpTcpSubFlow::RecvWithMapping(SequenceNumber32 &dsn)
{
  //!
  NS_LOG_FUNCTION(this);
//  Ptr<Packet> p = TcpSocketBase::Recv();

  // I can reuse
  uint32_t maxSize = 3303000;


  //NS_ABORT_MSG_IF(flags, "use of flags is not supported in TcpSocketBase::Recv()");
  if (m_rxBuffer.Size() == 0 && m_state == CLOSE_WAIT)
    {
      return Create<Packet>(); // Send EOF on connection close
    }



  // TODO sthg more rigorous later on
  // should be able to set the DSN
  //////////////////////////////////////////Y//
  /// we want to retrieve the SSN of the first byte that
  /// will be extracted from the TcpRxBuffer
  /// That would do a nice addition to the TcpTxBuffer
  SequenceNumber32 headSSN = m_rxBuffer.NextRxSequence()-1- m_rxBuffer.Available();

  NS_LOG_LOGIC("Extracting from SSN [" << headSSN << "]");
  //SequenceNumber32 headDSN;
  NS_ASSERT_MSG( TranslateSSNtoDSN(headSSN,dsn) == true, "Contact ns3 team");

  Ptr<Packet> outPacket = m_rxBuffer.Extract(maxSize);
  if (outPacket != 0 && outPacket->GetSize() != 0)
    {
      SocketAddressTag tag;
      if (m_endPoint != 0)
        {
          tag.SetAddress(InetSocketAddress(m_endPoint->GetPeerAddress(), m_endPoint->GetPeerPort()));
        }
      else if (m_endPoint6 != 0)
        {
          tag.SetAddress(Inet6SocketAddress(m_endPoint6->GetPeerAddress(), m_endPoint6->GetPeerPort()));
        }
      outPacket->AddPacketTag(tag);
    }
  // AddPacketTag
  return outPacket;
}

//MpTcpSubFlow::TranslateSubflowSeqToDataSeq();

/**
TODO here I should look for an associated mapping. If there is not,
then I discard the stuff
std::ostream& ns3::operator<<(std::ostream&,const ns3::TcpOptionMptcpMain&)
*/
void
MpTcpSubFlow::ReceivedData(Ptr<Packet> p, const TcpHeader& tcpHeader)
{
  NS_LOG_FUNCTION (this << tcpHeader);
  // Following was moved to ReceivedAck sincethis is from there that ReceivedData can
  // be called

  MpTcpMapping mapping;

  TcpHeader answerHeader;
  GenerateEmptyPacketHeader(answerHeader, TcpHeader::ACK);
//  OutOfRange
  // If cannot find an adequate mapping, then it should [check RFC]
  if(!GetMappingForSegment( m_RxMappings, tcpHeader.GetSequenceNumber(), mapping) )
  {
    NS_LOG_DEBUG("Could not find an adequate mapping for");
    // TODO remove that later
    NS_ASSERT_MSG(false,"No mapping received for that ack nb");

    // TODO we should create here a DSS option else it will not be freed at the sender

    //SendEmptyPacket(ackHeader);
    return;
  }

  //TcpHeader ackHeader;
//  GenerateEmptyPacketHeader(ackHeader,TcpHeader::ACK);
  Ptr<TcpOptionMpTcpDSS> dss = CreateObject<TcpOptionMpTcpDSS>();

  // TODO this function sends ACK without the mptcp DSS option .
  //TcpSocketBase::ReceivedData( p, mptcpHeader );

  // This part was copy/pasted from TcpSocketBase
  //NS_LOG_FUNCTION (this << tcpHeader);
  //NS_LOG_LOGIC ("seq " << tcpHeader.GetSequenceNumber () <<
    //  " ack " << tcpHeader.GetAckNumber () <<
      //" pkt size " << p->GetSize () );

  // Put into Rx buffer
  SequenceNumber32 expectedSeq = m_rxBuffer.NextRxSequence();
  if (!m_rxBuffer.Add(p, tcpHeader))
    { // Insert failed: No data or RX buffer full
      NS_LOG_DEBUG("Insert failed, No data or RX buffer full");
      dss->SetDataAck( GetMeta()->m_rxBuffer.NextRxSequence().GetValue() );
      SendEmptyPacket(answerHeader);
      return;
    }
  else
  {
    // we received new data
    // We should pass it to the meta
    GetMeta()->OnSubflowRecv( this );

    if (m_rxBuffer.Size() > m_rxBuffer.Available() || m_rxBuffer.NextRxSequence() > expectedSeq + p->GetSize())
      { // A gap exists in the buffer, or we filled a gap: Always ACK
        // TODO
        dss->SetDataAck(GetMeta()->m_rxBuffer.NextRxSequence().GetValue());
        SendEmptyPacket(answerHeader);
      }
    else
      { // In-sequĶence packet: ACK if delayed ack count allows
        // TODO i removed delayed ack. may reestablish later
  //      if (++m_delAckCount >= m_delAckMaxCount)
  //        {
  //          m_delAckEvent.Cancel();
  //          m_delAckCount = 0;
            dss->SetDataAck(GetMeta()->m_rxBuffer.NextRxSequence().GetValue());
            SendEmptyPacket(answerHeader);
  //        }
  //      else if (m_delAckEvent.IsExpired())
  //        {
  //          m_delAckEvent = Simulator::Schedule(m_delAckTimeout, &TcpSocketBase::DelAckTimeout, this);
  //          NS_LOG_LOGIC (this << " scheduled delayed ACK at " << (Simulator::Now () + Simulator::GetDelayLeft (m_delAckEvent)).GetSeconds ());
  //        }
      }
  }



  // Notify app to receive if necessary
  if (expectedSeq < m_rxBuffer.NextRxSequence())
    { // NextRxSeq advanced, we have something to send to the app
      if (!m_shutdownRecv)
        {
          // rename into RecvFromSubflow RecvData ?
          // NotifyMetaOfRcvdData
          GetMeta()->OnSubflowRecv( this);

          // TODO should not be called for now
          NotifyDataRecv();
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

uint16_t
MpTcpSubFlow::AdvertisedWindowSize(void)
{
  NS_LOG_DEBUG(this);
  return GetMeta()->AdvertisedWindowSize();
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
  //NS_LOG_ERROR("Not implemented. To implement ?");

  // TODO need to check for DSN mappings
//  TcpHeader::TcpOptionList l;
//  header.GetOptions(l);
//  for(TcpHeader::TcpOptionList::const_iterator it = l.begin(); it != l.end(); ++it)
//  {
//    if( (*it)->GetKind() == TcpOption::MPTCP)
//    {
//      Ptr<TcpOptionMpTcpMain> opt = DynamicCast<TcpOptionMpTcpMain>(*it);
//      if(opt->GetSubType() == TcpOptionMpTcpMain::MP_DSS)
//      {
//        //
//         = DynamicCast<TcpOptionMpTcpDSS>(opt);
//        NS_LOG_INFO( dss);

  Ptr<TcpOptionMpTcpDSS> dss;
  if(GetMpTcpOption(header, dss))
  {

    uint8_t flags = dss->GetFlags();

    // Look for mapping
    if( flags & TcpOptionMpTcpDSS::DSNMappingPresent )
    {
      //!
      if(flags & TcpOptionMpTcpDSS::DSNOfEightBytes)
      {
        NS_FATAL_ERROR("Not supported");
      }
      else
      {
        //!
        AddPeerMapping(dss->GetMapping());
      }
    }

    //
    if(flags & TcpOptionMpTcpDSS::DataAckPresent)
    {
      if(flags & TcpOptionMpTcpDSS::DataAckOf8Bytes)
      {
        NS_FATAL_ERROR("Not supported");
      }
      else
      {
        // TODO pass the info to the meta
        //
        GetMeta()->ReceivedAck( SequenceNumber32(dss->GetDataAck()), Ptr<MpTcpSubFlow>(this));
      }
    }
}
//      else {
//          //->GetSubType()
//        NS_LOG_WARN("Strange MPTCP option in packet " << opt );
//      }

  // if packet size > 0 then it will call ReceivedData
  TcpSocketBase::ReceivedAck(p, header );

}

bool
MpTcpSubFlow::AddPeerMapping(const MpTcpMapping& mapping)
{
  //! TODO check if there is already such a mapping?
  // check in meta ? if it supervises everything ?
  NS_LOG_FUNCTION(this << mapping);
  m_RxMappings.insert( mapping );
  return true;
}

void
MpTcpSubFlow::CwndTracer(uint32_t oldval, uint32_t newval)
{
  //NS_LOG_UNCOND("Subflow "<< m_routeId <<": Moving cwnd from " << oldval << " to " << newval);
  cwndTracer.push_back(make_pair(Simulator::Now().GetSeconds(), newval));
}

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
