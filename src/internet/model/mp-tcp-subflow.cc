/*
 * MultiPath-TCP (MPTCP) implementation.
 * Programmed by Morteza Kheirkhah from University of Sussex.
 * Some codes here are modeled from ns3::TCPNewReno implementation.
 * Email: m.kheirkhah@sussex.ac.uk
 */
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
//#include "ns3/ipv4-address.h"

NS_LOG_COMPONENT_DEFINE("MpTcpSubflow");

namespace ns3{

NS_OBJECT_ENSURE_REGISTERED(MpTcpSubFlow);

TypeId
MpTcpSubFlow::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::MpTcpSubFlow")
      .SetParent<TcpSocketBase>()
      .AddTraceSource("cWindow",
          "The congestion control window to trace.",
           MakeTraceSourceAccessor(&MpTcpSubFlow::m_cWnd));
  return tid;
}



Ptr<TcpSocketBase>
MpTcpSubFlow::Fork(void)
{
  // Call CopyObject<> to clone me
//  NS_LOG_ERROR("Not implemented");


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
  return m_metaSocket->GetLocalKey() >> 32 ;
}

uint32_t
MpTcpSubFlow::GetRemoteToken() const
{
//  NS_LOG_ERROR("Not implemented yet");
  return m_metaSocket->GetLocalKey() >> 32 ;

}



// TODO should improve parent's one once SOCIS code gets merged
void
MpTcpSubFlow::SendEmptyPacket(uint8_t flags)
{
  NS_LOG_FUNCTION (this << "yo");
//  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
  Ptr<Packet> p = Create<Packet>();

//  SequenceNumber32 s = SequenceNumber32(m_nextTxSequence.Get() );
  SequenceNumber32 s = m_nextTxSequence ;

  if (m_endPoint == 0)
    {
      NS_FATAL_ERROR("Failed to send empty packet due to null subflow's endpoint");
      NS_LOG_WARN ("Failed to send empty packet due to null subflow's endpoint");
      return;
    }
  if (flags & TcpHeader::FIN)
    {
      flags |= TcpHeader::ACK;
//      m_nextTxSequence.Get()
//      if (maxSeqNb != TxSeqNumber - 1 ) // Potential bug ?  && client)
//        s = maxSeqNb + 1;
    }
  else if (m_state == FIN_WAIT_1 || m_state == LAST_ACK || m_state == CLOSING)
    {
      ++s;
    }

  TcpHeader header;
  uint8_t hlen = 0; // header length ?
  uint8_t olen = 0; // additionnal header length. wait for SOCIS code

  header.SetSourcePort( m_endPoint->GetLocalPort());
  header.SetDestinationPort( m_endPoint->GetPeerPort() );
  header.SetFlags(flags);
  header.SetSequenceNumber(s);
  header.SetAckNumber(SequenceNumber32( m_rxBuffer.NextRxSequence() ));
  header.SetWindowSize(AdvertisedWindowSize());

  bool hasSyn = flags & TcpHeader::SYN;
  bool hasFin = flags & TcpHeader::FIN;
  bool isAck = flags == TcpHeader::ACK;

    // in parent they do   m_rto = m_rtt->RetransmitTimeout();
  Time RTO = rtt->RetransmitTimeout();
  if (hasSyn)
  {
      if (m_cnCount == 0)
      {
          // No more connection retries, give up
          NS_LOG_INFO ("Connection failed.");
          CloseAndNotify();
          return;
      }
      else
      {
        //TODO use ComputeTx ... member
          // Exponential backoff of connection time out
          int backoffCount = 0x1 << (m_cnRetries - m_cnCount);
          RTO = Seconds(m_cnTimeout.GetSeconds() * backoffCount);
          m_cnCount--;
          NS_LOG_UNCOND("("<< (int)m_routeId << ") SendEmptyPacket -> backoffCount: " << backoffCount << " RTO: " << RTO.GetSeconds() << " m_cnTimeout: " << m_cnTimeout.GetSeconds() <<" m_cnCount: "<< m_cnCount);
      }
  }


  if (((m_state == SYN_SENT) || (m_state == SYN_RCVD )))
    {
      TcpOptionMpTcpCapable option;
      header.AppendOption( option );
//      m_localNonce = rand() % 1000 + 1;        // Random Local Token
//      header.AddOptMPC(OPT_MPCAPABLE, m_localNonce); // Adding MP_CAPABLE & Token to TCP option (5 Bytes)
//      olen += 5;
//      m_tcp->m_TokenMap[m_localNonce] = m_endPoint;       //m_tcp->m_TokenMap.insert(std::make_pair(m_localNonce, m_endPoint))

      NS_LOG_INFO("("
//            << (int)sFlow->m_routeId
            << ") SendEmptyPacket -> m_localNonce is mapped to connection endpoint -> "
            << m_localNonce << " -> " << m_endPoint
            << " TokenMapsSize: "<< m_tcp->m_TokenMap.size());

    }
  else

  // if master use MP_CAPABLE
  if (m_state == SYN_SENT && hasSyn && IsMaster() )
    {
      header.AddOptMPC(OPT_MPCAPABLE, GetLocalToken() );       // Adding MP_CAPABLE & Token to TCP option (5 Bytes)
      olen += 5;
    }
  // Otherwise MP_JOIN
  else if (m_state == SYN_SENT && hasSyn && !IsMaster())
    {
//      NS_ASSERT() TODO check for token/ remote nonce  existence
      header.AddOptJOIN(OPT_JOIN, GetRemoteToken(), 0); // last param = addrId
      olen += 6;
    }

  uint8_t plen = (4 - (olen % 4)) % 4;
  olen = (olen + plen) / 4;
  hlen = 5 + olen;
  header.SetLength(hlen);
  header.SetOptionsLength(olen);
  header.SetPaddingLength(plen);

  //m_metaSocket->FindOutputNetDevice(sAddr)
  m_tcp->SendPacket(p, header, m_endPoint->GetLocalAddress() , m_endPoint->GetPeerAddress(), m_endPoint->GetBoundNetDevice() );
  //sFlow->rtt->SentSeq (sFlow->TxSeqNumber, 1);           // notify the RTT

  if (m_retxEvent.IsExpired() && (hasFin || hasSyn) && !isAck)
    { // Retransmit SYN / SYN+ACK / FIN / FIN+ACK to guard against lost
//RTO = rtt->RetransmitTimeout();
//sFlowIdx,
      m_retxEvent = Simulator::Schedule(RTO, &MpTcpSubFlow::SendEmptyPacket, this, flags);
      NS_LOG_INFO ("("
//            <<(int)sFlowIdx <<
            ") SendEmptyPacket -> ReTxTimer set for FIN / FIN+ACK / SYN / SYN+ACK now "
            << Simulator::Now ().GetSeconds () << " Expire at " << (Simulator::Now () + RTO).GetSeconds ()
            << " RTO: " << RTO.GetSeconds());
    }

  //if (!isAck)
  NS_LOG_INFO("("
//          << (int)sFlowIdx
          <<") SendEmptyPacket-> "
          << header <<" Length: "<< (int)header.GetLength());
}



#if 0
int
MpTcpSubFlow::DoConnect()
{

}

int
MpTcpSubFlow::Connect(const Address &address)
{
  InetSocketAddress transport = InetSocketAddress::ConvertFrom(address);
//  dAddr   = transport.GetIpv4(); // MPTCP Connection remoteAddress
//  m_dPort = transport.GetPort(); // MPTCP Connection remotePort

  // Should depend on if it's first or not
  NS_LOG_FUNCTION(this );


  // allocates subflow
//  Ptr<MpTcpSubFlow> sFlow = CreateObject<MpTcpSubFlow>(this);
  // TODO en fait il ne devrait pas y avoir de m_routeId
//  sFlow->m_routeId = (m_subflows.empty()  ? 0 : m_subflows.back()->m_routeId + 1);
//  dAddr = servAddr;    // Assigned subflow destination address
//  m_dPort = servPort;  // Assigned subflow destination port
//  m_remoteAddress = servAddr; // MPTCP Connection's remote address
//  m_remotePort = servPort;    // MPTCP Connection's remote port


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
  m_endPoint->SetPeer( transport.GetIpv4(), transport.GetPort() );

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
    // TODO this might be removed since SetupEndpoint does it
    // Make sure there is an route from source to destination. Source might be set wrongly.
      if (( m_metaSocket->IsThereRoute(m_endPoint->GetLocalAddress(), m_endPoint->GetPeerAddress())) == false)
        {
          NS_LOG_INFO("Connect -> There is no route from " << m_endPoint->GetLocalAddress()
                    << " to " << m_endPoint->GetPeerAddress());
          //m_tcp->DeAllocate(m_endPoint); // this would fire up destroy function...
          return -1;
        }
    }

  // Set up subflow local addrs:port from endpoint
//  sAddr = m_endPoint->GetLocalAddress();
//  sPort = m_endPoint->GetLocalPort();
//  MSS = m_segmentSize;
  cwnd = GetSegSize();  // initial window should depends on ???

  NS_LOG_INFO("Connect -> SegmentSize: " << GetSegSize()  ) ;//
//  NS_LOG_UNCOND("Connect -> SendingBufferSize: " << sendingBuffer->bufMaxSize);

  // This is master subsocket (master subflow) then its endpoint is the same as connection endpoint.
  // Ptet buggy la
//  this->m_endPoint = m_metaSocket->m_endPoint;


  //sFlow->rtt->Reset();
  m_cnCount = m_cnRetries;

//  if (sFlow->state == CLOSED || sFlow->state == LISTEN || sFlow->state == SYN_SENT || sFlow->state == LAST_ACK || sFlow->state == CLOSE_WAIT)
//    { // send a SYN packet and change state into SYN_SENT
  NS_LOG_INFO ("("
//      << (int)sFlow->m_routeId << ") "
      << TcpStateName[state] << " -> SYN_SENT");

//  m_state = SYN_SENT;
//  m_state = SYN_SENT;  // Subflow state should be changed first then SendEmptyPacket...


//  currentSublow = sFlow->m_routeId; // update currentSubflow in case close just after 3WHS.
  // TODO move to tcpsocket base
  NS_LOG_INFO(this << "  MPTCP connection is initiated (Sender): "
//        << sAddr << ":" << sPort << " -> " << dAddr << ":" << m_dPort
        << " m_state: " << TcpStateName[m_state]
        );


  // Copied from tcp-socket-base to modify
  // A new connection is allowed only if this socket does not have a connection
  if (m_state == CLOSED || m_state == LISTEN || m_state == SYN_SENT || m_state == LAST_ACK || m_state == CLOSE_WAIT)
    { // send a SYN packet and change state into SYN_SENT
//      TODO
//      SendEmptyPacket(TcpHeader::SYN);
      SendEmptyPacket( TcpHeader::SYN);
//      SendEmptyPacket(m_routeId, TcpHeader::SYN);
      NS_LOG_INFO (TcpStateName[m_state] << " -> SYN_SENT");
      m_state = SYN_SENT;
    }
  else if (m_state != TIME_WAIT)
    { // In states SYN_RCVD, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, and CLOSING, an connection
      // exists. We send RST, tear down everything, and close this socket.
      SendRST();

      // TODO should notify main
      CloseAndNotify();
    }

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

MpTcpSubFlow::MpTcpSubFlow(Ptr<MpTcpSocketBase> metaSocket
//, bool master
) :
    TcpSocketBase(),
    m_routeId(0),
//    m_state(CLOSED),
//    sAddr(Ipv4Address::GetZero()),
//    sPort(0),
//    dAddr(Ipv4Address::GetZero()),
//    m_dPort(0),
//    oif(0), // outputinterface
    m_ssThresh(65535),  // retrieve from meta CC set in parent's ?
//    m_mapDSN(0),
    m_lastMeasuredRtt(Seconds(0.0)),
     // TODO move out to MpTcpCControl


    m_metaSocket(metaSocket),
    m_backupSubflow(false),
    m_localNonce(0),
    m_remoteToken(0)
{
  NS_ASSERT( m_metaSocket );

//  connected = false;

  // TODO use/create function to generate initial random number seq
//  TxSeqNumber = rand() % 1000;
//  RxSeqNumber = 0;

//  cwnd = 0;

//  maxSeqNb = TxSeqNumber - 1;
//  highestAck = 0;
  rtt = CreateObject<RttMeanDeviation>();
  rtt->Gain(0.1);
  Time estimate;
  estimate = Seconds(1.5);
  rtt->SetCurrentEstimate(estimate);
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

//, uint32_t maxSize
// rename globalSeqNb ?
int
MpTcpSubFlow::SendMapping(Ptr<Packet> p, SequenceNumber32 mptcpSeq)
{
  NS_LOG_FUNCTION (this << p);

  // backup its value because send will change it
  SequenceNumber32 nextTxSeq = m_nextTxSequence;

  int res = TcpSocketBase::Send(p,0);

  // Everything went fine
  if(res >= 0)
  {
    MpTcpMapping mapping;
    mapping.m_dataSeqNumber = mptcpSeq;
    mapping.m_size = p->GetSize();
    mapping.m_subflowSeqNumber = nextTxSeq;
    // record mapping
    m_mappings.push_back( mapping  );
  }


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
MpTcpSubFlow::SendDataPacket(SequenceNumber32 seq, uint32_t maxSize, bool withAck)
{
  MpTcpMapping mapping;
  bool result = GetMappingForSegment(seq, mapping);
  NS_ASSERT(result == true);
  // Generate packet
//  TcpSocketBase::SendDataPacket(seq, maxSize, withAck);



 NS_LOG_FUNCTION (this << seq << maxSize << withAck);  //NS_LOG_INFO("SendDataPacket -> SeqNb: " << seq);
  Ptr<Packet> p = m_txBuffer.CopyFromSequence(maxSize, seq);
  uint32_t sz = p->GetSize(); // Size of packet
  uint8_t flags = withAck ? TcpHeader::ACK : 0;
  uint32_t remainingData = m_txBuffer.SizeFromSequence(seq + SequenceNumber32(sz));
  if (m_closeOnEmpty && (remainingData == 0))
    {
      flags |= TcpHeader::FIN;
      if (m_state == ESTABLISHED)
        { // On active close: I am the first one to send FIN
          NS_LOG_INFO ("ESTABLISHED -> FIN_WAIT_1");
          m_state = FIN_WAIT_1;
        }
      else if (m_state == CLOSE_WAIT)
        { // On passive close: Peer sent me FIN already
          NS_LOG_INFO ("CLOSE_WAIT -> LAST_ACK");
          m_state = LAST_ACK;
        }
    }
  TcpHeader header;
  header.SetFlags(flags);
  header.SetSequenceNumber(seq);
  header.SetAckNumber(m_rxBuffer.NextRxSequence());
//  if (m_endPoint)
//    {
      header.SetSourcePort(m_endPoint->GetLocalPort());
      header.SetDestinationPort(m_endPoint->GetPeerPort());
//    }
//  else
//    {
//      header.SetSourcePort(m_endPoint6->GetLocalPort());
//      header.SetDestinationPort(m_endPoint6->GetPeerPort());
//    }
  header.SetWindowSize(AdvertisedWindowSize());
//  AddOptions(header);
  // TODO schedule retransmissions also via meta
//  if (m_retxEvent.IsExpired())
//    { // Schedule retransmit
//      m_rto = m_rtt->RetransmitTimeout();
//      NS_LOG_LOGIC (this << " SendDataPacket Schedule ReTxTimeout at time " <<
//          Simulator::Now ().GetSeconds () << " to expire at time " <<
//          (Simulator::Now () + m_rto.Get ()).GetSeconds () );
//      m_retxEvent = Simulator::Schedule(m_rto, &TcpSocketBase::ReTxTimeout, this);
//    }NS_LOG_LOGIC ("Send packet via TcpL4Protocol with flags 0x" << std::hex << static_cast<uint32_t> (flags) << std::dec);

//  std::list < uint32_t > sampleList;
//  // 4 drops on 3rd RTT
//  sampleList.push_back(16);
//  sampleList.push_back(20);
//  sampleList.push_back(21);
//
//  // Add list to ListErrorModel object
//  Ptr<ListErrorModel> rem = CreateObject<ListErrorModel>();
//  rem->SetList(sampleList);

  // Add options afterwards if first packet
  if(mapping.m_subflowSeqNumber == seq  )
  {
    // Add DSN option
    header.AddOptDSN(OPT_DSN, mapping.m_dataSeqNumber.GetValue(), mapping.m_size, seq.GetValue() );
  }


  // Packet should be drop
  if (IsCorrupt(p))
    {
      uint32_t tmp = (((seq.GetValue() + sz) - initialSeqNb) / m_segmentSize) % mod;
      DROP.push_back(std::make_pair(Simulator::Now().GetSeconds(), tmp));
    }
  // Packet should be sent
  else
    {
      if (m_endPoint)
        {
          m_tcp->SendPacket(p, header, m_endPoint->GetLocalAddress(), m_endPoint->GetPeerAddress(), m_boundnetdevice);
          uint32_t tmp = (((seq.GetValue() + sz) - initialSeqNb) / m_segmentSize) % mod;
          DATA.push_back(std::make_pair(Simulator::Now().GetSeconds(), tmp));
        }
      else
        {
          m_tcp->SendPacket(p, header, m_endPoint6->GetLocalAddress(), m_endPoint6->GetPeerAddress(), m_boundnetdevice);
        }
    }
  m_rtt->SentSeq(seq, sz);       // notify the RTT
  // Notify the application of the data being sent unless this is a retransmit
  if (seq == m_nextTxSequence)
    {
//      Simulator::ScheduleNow(&TcpSocketBase::NotifyDataSent, this, sz);
    }
  // Update highTxMark
  m_highTxMark = std::max(seq + sz, m_highTxMark.Get());
  NS_LOG_DEBUG("DataPacket -----> " << header);
  return sz;



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
  m_metaSocket->OnSubflowRetransmit( this );

  // TODO change window ?
}

/*
This function is useless as prototyped in TcpSocketBase :(
*/
#if 0
bool
MpTcpSubFlow::ReadOptions(Ptr<Packet> pkt, const TcpHeader& mptcpHeader)
{
  NS_LOG_FUNCTION(this << mptcpHeader);

  std::vector<TcpOptions*> mp_options = mptcpHeader.GetOptions();
  uint8_t flags = mptcpHeader.GetFlags();
  TcpOptions *opt;
  bool hasSyn = flags & TcpHeader::SYN;
  for (uint32_t j = 0; j < mp_options.size(); j++)
  {
    // TODO if the option belongs to MPTCP then notify the metasocket or inspect here ?
      opt = mp_options[j];
      if ((opt->optName == OPT_MPCAPABLE) && hasSyn)
      {
        //TODO check not connected yet
        NS_ASSERT_MSG( (m_state == LISTEN) , "This could be a bug please report it to our GitHub page");
        NS_ASSERT_MSG( !m_metaSocket->IsMpTcpEnabled(), "This could be a bug please report it to our GitHub page");

        // SYN+ACK would be send later on by ProcessSynRcvd(...)
        m_metaSocket->SetRemoteKey( ((OptMultipathCapable *) opt)->senderToken  );

      }
  }
  return true; // This should return true otherwise Forwardup() would retrun too.
}
#endif


bool
MpTcpSubFlow::IsMaster() const
{
  NS_ASSERT(m_metaSocket);

  // TODO
  return (m_endPoint == m_metaSocket->m_endPoint); // This is master subsock, its endpoint is the same as connection endpoint.

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
  NS_ASSERT(m_metaSocket);

  // TODO check subflow is established !!
  uint8_t addrId = m_metaSocket->AddLocalAddr(addr);


  // Change the MPTCP send state to MP_ADDADDR
//      MpTcpAddressInfo * addrInfo;
  Ptr<Packet> pkt = Create<Packet>();

  TcpHeader header;
  header.SetFlags(TcpHeader::ACK);
  //SequenceNumber32(m_txNextSequence)
  header.SetSequenceNumber( m_nextTxSequence);
  header.SetAckNumber( m_rxBuffer.NextRxSequence() );
  header.SetSourcePort( m_endPoint->GetLocalPort() ); // m_endPoint->GetLocalPort()
  header.SetDestinationPort( m_endPoint->GetPeerPort() );
  uint8_t hlen = 0;
  uint8_t olen = 0;


//      IPv4Address;;ConvertFrom ( addr );

  header.AddOptADDR(OPT_ADDR, addrId, Ipv4Address::ConvertFrom ( addr ) );
  olen += 6;

  uint8_t plen = (4 - (olen % 4)) % 4;
  header.SetWindowSize(AdvertisedWindowSize());
  olen = (olen + plen) / 4;
  hlen = 5 + olen;
  header.SetLength(hlen);
  header.SetOptionsLength(olen);
  header.SetPaddingLength(plen);


  m_tcp->SendPacket(pkt, header, m_endPoint->GetLocalAddress(), m_endPoint->GetPeerAddress());
  // we 've got to rely on

//      this->SendPacket(pkt, header, m_localAddress, m_remoteAddress, FindOutputNetDevice(m_localAddress) );
  NS_LOG_INFO("Advertise  Addresses-> "<< header);
}


bool
MpTcpSubFlow::StopAdvertisingAddress(Ipv4Address address)
{
  // TODO factor some code with AdvertiseAddress ?
  // TODO check subflow is established !!
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
  header.SetFlags(TcpHeader::ACK);
  header.SetSequenceNumber( m_nextTxSequence );    // SequenceNumber32(TxSeqNumber)
  header.SetAckNumber( m_rxBuffer.NextRxSequence() );
  header.SetSourcePort( m_endPoint->GetLocalPort() ); // m_endPoint->GetLocalPort()
  header.SetDestinationPort ( m_endPoint->GetPeerPort() );
  uint8_t hlen = 0;
  uint8_t olen = 0;


//      IPv4Address;;ConvertFrom ( addr );

  header.AddOptREMADR(OPT_REMADR, addrId );
  olen += 6;

  uint8_t plen = (4 - (olen % 4)) % 4;
  header.SetWindowSize(AdvertisedWindowSize());
  olen = (olen + plen) / 4;
  hlen = 5 + olen;
  header.SetLength(hlen);
  header.SetOptionsLength(olen);
  header.SetPaddingLength(plen);


  m_tcp->SendPacket(pkt, header, m_endPoint->GetLocalAddress(), m_endPoint->GetPeerAddress());
  // we 've got to rely on

//      this->SendPacket(pkt, header, m_localAddress, m_remoteAddress, FindOutputNetDevice(m_localAddress) );
  NS_LOG_INFO("Advertise  Addresses-> "<< header);
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
MpTcpSubFlow::GetMappingForSegment( SequenceNumber32 subflowSeqNb, MpTcpMapping& mapping)
{
  for( MappingList::iterator it = m_mappings.begin(); it != m_mappings.end(); it++ )
  {
    // check seq nb is within the DSN range
    if ( (subflowSeqNb >= it->m_subflowSeqNumber ) &&
      (subflowSeqNb < it->m_subflowSeqNumber + it->m_size)
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
MpTcpSubFlow::ReceivedData(Ptr<Packet> p, const TcpHeader& mptcpHeader)
{
  NS_LOG_FUNCTION (this << mptcpHeader);

    // Put into Rx buffer
//  SequenceNumber32 expectedSeq = m_rxBuffer.NextRxSequence();
  if (!m_rxBuffer.Add(p, mptcpHeader))
    { // Insert failed: No data or RX buffer full
      SendEmptyPacket(TcpHeader::ACK);
      return;
    }

  // TODO pass subflow id to the function
//  m_metaSocket->ReceivedData(Ptr<Packet> p, const TcpHeader& mptcpHeader);

  // TODO see what we can free in our TxBuffer

  std::vector<TcpOptions*> options = mptcpHeader.GetOptions();
  TcpOptions* opt;
//  bool stored = true;

  MpTcpMapping mapping;

  if( GetMappingForSegment( mptcpHeader.GetSequenceNumber(), mapping) )
  {

  }

  // loop through options to find DSN option
  for (uint32_t i = 0; i < options.size(); i++)
    {
      opt = options[i];

      // DSN mapping
      if (opt->optName == OPT_DSN)
      {
          // TODO call a bit of the fct here TcpTxBuffer
//          OptDataSeqMapping* optDSN = (OptDataSeqMapping*) opt;


      }

    } // end of 'for'

          #if 0
          if (optDSN->subflowSeqNumber == RxSeqNumber)
            {
              // if in order DSN
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
                  RxSeqNumber += amountRead;
                  // Do we need to increment highest ACK??
                  //sFlow->highestAck = std::max(highestAck, (mptcpHeader.GetAckNumber()).GetValue() - 1);
                  nextRxSequence += amountRead;
                  ReadUnOrderedData();
                  if (expectedSeq < RxSeqNumber)
                    {
                      NotifyDataRecv();
                    }
                  SendEmptyPacket(sFlowIdx, TcpHeader::ACK);
                  // If we received FIN before and now completed all "holes" in rx buffer, invoke peer close
//                  if (Finished() && (mptcpHeader.GetFlags() & TcpHeader::FIN) == 0)
                  if (Finished() && (mptcpHeader.GetFlags() & TcpHeader::FIN) == 0)
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
                      RxSeqNumber += optDSN->dataLevelLength;
                      highestAck = std::max(highestAck, (mptcpHeader.GetAckNumber()).GetValue() - 1);
                    }
                  SendEmptyPacket(sFlowIdx, TcpHeader::ACK);
                }
              else
                {
                  NS_ASSERT(3!=3);
                  NS_LOG_WARN(this << "Data received is duplicated in DataSeq Lavel so it has been rejected!");
                  SendEmptyPacket(TcpHeader::ACK);
                }
            }
          else if (optDSN->subflowSeqNumber > RxSeqNumber)
            { // There is a gap in subflowSeqNumber
              // This condition might occures when a packet get drop...
              stored = StoreUnOrderedData(
                  new DSNMapping(sFlowIdx, optDSN->dataSeqNumber, optDSN->dataLevelLength, optDSN->subflowSeqNumber,
                      mptcpHeader.GetAckNumber().GetValue(), p));
              if (stored)
                {
                  SendEmptyPacket(TcpHeader::ACK); // Since there is a gap in subflow level then we ask for it!
                }
              else
                {
                  NS_LOG_ERROR("Data failed to be stored in unOrderedBuffer SegNb: " << optDSN->subflowSeqNumber);
                  SendEmptyPacket(TcpHeader::ACK);
                }
            }
          else if (optDSN->subflowSeqNumber < RxSeqNumber)
            { // Received subflowSeqNumer is smaller than subflow expected RxSeqNumber
              NS_LOG_INFO("Data received is duplicated in Subflow Layer so it has been rejected! subflowSeq: " << optDSN->subflowSeqNumber << " dataSeq: " << optDSN->dataSeqNumber);
              SendEmptyPacket(TcpHeader::ACK);  // Ask for expected subflow sequnce number.
            }
          else
            NS_ASSERT(3!=3);
        }
    } // end of 'for'
    #endif
}

uint16_t
MpTcpSubFlow::AdvertisedWindowSize(void)
{
  return m_metaSocket->AdvertisedWindowSize();
}


void
MpTcpSubFlow::ReceivedAck(Ptr<Packet>, const TcpHeader&)
{

}


void
MpTcpSubFlow::CwndTracer(uint32_t oldval, uint32_t newval)
{
  //NS_LOG_UNCOND("Subflow "<< m_routeId <<": Moving cwnd from " << oldval << " to " << newval);
  cwndTracer.push_back(make_pair(Simulator::Now().GetSeconds(), newval));
}

// subflow should know his mapping
//void
//MpTcpSubFlow::AddDSNMapping(
//  uint8_t sFlowIdx,
//    uint64_t dSeqNum, uint16_t dLvlLen, uint32_t sflowSeqNum, uint32_t ack,
//    Ptr<Packet> pkt)
//{
//  NS_LOG_FUNCTION_NOARGS();
//  m_mapDSN.push_back(new DSNMapping(sFlowIdx, dSeqNum, dLvlLen, sflowSeqNum, ack, pkt));
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

//DSNMapping *
//MpTcpSubFlow::GetunAckPkt()
//{
//  NS_LOG_FUNCTION(this);
//  DSNMapping * ptrDSN = 0;
//  for (list<DSNMapping *>::iterator it = m_mapDSN.begin(); it != m_mapDSN.end(); ++it)
//    {
//      DSNMapping * ptr = *it;
//      if (ptr->subflowSeqNumber == highestAck + 1)
//        {
//          ptrDSN = ptr;
//          break;
//        }
//    }
//  return ptrDSN;
//}
}
