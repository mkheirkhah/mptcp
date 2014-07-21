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
           MakeTraceSourceAccessor(&MpTcpSubFlow::cwnd));
  return tid;
}



Ptr<TcpSocketBase>
MpTcpSubFlow::Fork(void)
{
  // Call CopyObject<> to clone me
  NS_LOG_ERROR("Not implemented");


  return CopyObject<MpTcpSubFlow> (this);
}

void
MpTcpSubFlow::DupAck(const TcpHeader& t, uint32_t count)
{
  NS_LOG_DEBUG("DupAck ignored as specified in RFC");
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


uint32_t
MpTcpSubFlow::GetLocalToken() const
{
  return m_localToken;
}

uint32_t
MpTcpSubFlow::GetRemoteToken() const
{
  return m_remoteToken;
}

// TODO should improve parent's one once SOCIS code gets merged
void
MpTcpSubFlow::SendEmptyPacket(uint8_t flags)
{
  NS_LOG_FUNCTION (this << "yo");
//  Ptr<MpTcpSubFlow> sFlow = m_subflows[sFlowIdx];
  Ptr<Packet> p = Create<Packet>();

  SequenceNumber32 s = SequenceNumber32(TxSeqNumber);

  if (m_endPoint == 0)
    {
      NS_FATAL_ERROR("Failed to send empty packet due to null subflow's endpoint");
      NS_LOG_WARN ("Failed to send empty packet due to null subflow's endpoint");
      return;
    }
  if (flags & TcpHeader::FIN)
    {
      //flags |= TcpHeader::ACK;
      if (maxSeqNb != TxSeqNumber - 1 ) // Potential bug ?  && client)
        s = maxSeqNb + 1;
    }
  else if (m_state == FIN_WAIT_1 || m_state == LAST_ACK || m_state == CLOSING)
    {
      ++s;
    }

  TcpHeader header;
  uint8_t hlen = 0;
  uint8_t olen = 0;

  header.SetSourcePort(sPort);
  header.SetDestinationPort(m_dPort);
  header.SetFlags(flags);
  header.SetSequenceNumber(s);
  header.SetAckNumber(SequenceNumber32(RxSeqNumber));
  header.SetWindowSize(AdvertisedWindowSize());

  bool hasSyn = flags & TcpHeader::SYN;
  bool hasFin = flags & TcpHeader::FIN;
  bool isAck = flags == TcpHeader::ACK;

  Time RTO = rtt->RetransmitTimeout();
  if (hasSyn)
    {
      if (m_cnCount == 0)
        { // No more connection retries, give up
          NS_LOG_INFO ("Connection failed.");
          // TODO
          m_metaSocket->CloseAndNotify(m_routeId);
          return;
      }
      else
        { // Exponential backoff of connection time out
          int backoffCount = 0x1 << (m_cnRetries - m_cnCount);
          RTO = Seconds(cnTimeout.GetSeconds() * backoffCount);
          m_cnCount--;
          NS_LOG_UNCOND("("<< (int)m_routeId<< ") SendEmptyPacket -> backoffCount: " << backoffCount << " RTO: " << RTO.GetSeconds() << " cnTimeout: " << cnTimeout.GetSeconds() <<" m_cnCount: "<< m_cnCount);
        }
    }

  if (((m_state == SYN_SENT) || (m_state == SYN_RCVD && m_metaSocket->IsMpTcpEnabled() ))
    //&& mpSendState == MP_NONE

    )
    {
//      mpSendState = MP_MPC;                  // This state means MP_MPC is sent
      m_localToken = rand() % 1000 + 1;        // Random Local Token
      header.AddOptMPC(OPT_MPCAPABLE, m_localToken); // Adding MP_CAPABLE & Token to TCP option (5 Bytes)
      olen += 5;
      m_tcp->m_TokenMap[m_localToken] = m_endPoint;       //m_tcp->m_TokenMap.insert(std::make_pair(m_localToken, m_endPoint))
      NS_LOG_INFO("("
//            << (int)sFlow->m_routeId
            << ") SendEmptyPacket -> m_localToken is mapped to connection endpoint -> "
            << m_localToken << " -> " << m_endPoint
            << " TokenMapsSize: "<< m_tcp->m_TokenMap.size());

    }
  else if (m_state == SYN_SENT && hasSyn && IsMaster() )
    {
      header.AddOptMPC(OPT_MPCAPABLE, GetLocalToken() );       // Adding MP_CAPABLE & Token to TCP option (5 Bytes)
      olen += 5;
    }
  else if (m_state == SYN_SENT && hasSyn && !IsMaster())
    {
      header.AddOptJOIN(OPT_JOIN, GetRemoteToken(), 0); // addID should be zero?
      olen += 6;
    }

  uint8_t plen = (4 - (olen % 4)) % 4;
  olen = (olen + plen) / 4;
  hlen = 5 + olen;
  header.SetLength(hlen);
  header.SetOptionsLength(olen);
  header.SetPaddingLength(plen);

  m_tcp->SendPacket(p, header, sAddr, dAddr, m_metaSocket->FindOutputNetDevice(sAddr));
  //sFlow->rtt->SentSeq (sFlow->TxSeqNumber, 1);           // notify the RTT

  if (retxEvent.IsExpired() && (hasFin || hasSyn) && !isAck)
    { // Retransmit SYN / SYN+ACK / FIN / FIN+ACK to guard against lost
//RTO = rtt->RetransmitTimeout();
//sFlowIdx,
      retxEvent = Simulator::Schedule(RTO, &MpTcpSubFlow::SendEmptyPacket, this, flags);
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



// TODO check with
int
MpTcpSubFlow::Connect(const Address &address)
{
  InetSocketAddress transport = InetSocketAddress::ConvertFrom(address);
  dAddr   = transport.GetIpv4(); // MPTCP Connection remoteAddress
  m_dPort = transport.GetPort(); // MPTCP Connection remotePort

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
  m_endPoint->SetPeer(dAddr, m_dPort);

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
          NS_LOG_INFO("Connect -> There is no route from " << m_endPoint->GetLocalAddress() << " to " << m_endPoint->GetPeerAddress());
          //m_tcp->DeAllocate(m_endPoint); // this would fire up destroy function...
          return -1;
        }
    }

  // Set up subflow local addrs:port from endpoint
  sAddr = m_endPoint->GetLocalAddress();
  sPort = m_endPoint->GetLocalPort();
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
  NS_LOG_INFO(this << "  MPTCP connection is initiated (Sender): " << sAddr << ":" << sPort << " -> " << dAddr << ":" << m_dPort << " m_state: " << TcpStateName[m_state]);


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


// Does this constructor even make sense ? no ? to remove ?
MpTcpSubFlow::MpTcpSubFlow(const MpTcpSubFlow& sock)
  : TcpSocketBase(sock),
//  m_cWnd(sock.m_cWnd),
  m_ssThresh(sock.m_ssThresh),
  m_localToken(sock.m_localToken),
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
    state(CLOSED),
    sAddr(Ipv4Address::GetZero()),
    sPort(0),
    dAddr(Ipv4Address::GetZero()),
    m_dPort(0),
    oif(0),
    m_ssThresh(65535),
    m_mapDSN(0),
    m_lastMeasuredRtt(Seconds(0.0)),
     // TODO move out to MpTcpCControl


    m_metaSocket(metaSocket),
    m_localToken(0),
    m_remoteToken(0)
{
  NS_ASSERT( m_metaSocket );

//  connected = false;

  // TODO use/create function to generate initial random number seq
  TxSeqNumber = rand() % 1000;
  RxSeqNumber = 0;
  bandwidth = 0;
  cwnd = 0;

  maxSeqNb = TxSeqNumber - 1;
  highestAck = 0;
  rtt = CreateObject<RttMeanDeviation>();
  rtt->Gain(0.1);
  Time estimate;
  estimate = Seconds(1.5);
  rtt->SetCurrentEstimate(estimate);
  m_cnRetries = 3;
  Time est = MilliSeconds(200);
  cnTimeout = est;
  initialSequnceNumber = 0;
  m_retxThresh = 3;
  m_inFastRec = false;
  m_limitedTx = false;
  m_dupAckCount = 0;
  PktCount = 0;
  m_recover = SequenceNumber32(0);
  m_gotFin = false;
}

MpTcpSubFlow::~MpTcpSubFlow()
{
  m_endPoint = 0;
  m_routeId = 0;
  sAddr = Ipv4Address::GetZero();
  oif = 0;
  state = CLOSED;
  bandwidth = 0;
  cwnd = 0;
  maxSeqNb = 0;
  highestAck = 0;
  for (std::list<DSNMapping *>::iterator it = m_mapDSN.begin(); it != m_mapDSN.end(); ++it)
    {
      DSNMapping * ptrDSN = *it;
      delete ptrDSN;
    }
  m_mapDSN.clear();
}


bool
MpTcpSubFlow::IsMaster() const
{
  NS_ASSERT(m_metaSocket);

  // is that enough ?
  return (m_metaSocket->m_subflows.size() == 1);
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

      // there is at least one subflow
//      Ptr<MpTcpSubFlow> sFlow = subflows[0];
//      NS_ASSERT(sFlow!=0);

      // Change the MPTCP send state to MP_ADDADDR
//      mpSendState = MP_ADDADDR;
//      MpTcpAddressInfo * addrInfo;
      Ptr<Packet> pkt = Create<Packet>();

      TcpHeader header;
      header.SetFlags(TcpHeader::ACK);
//      header.SetSequenceNumber(SequenceNumber32(sFlow->TxSeqNumber));
      header.SetSequenceNumber(SequenceNumber32(TxSeqNumber));
//      header.SetAckNumber(SequenceNumber32(sFlow->RxSeqNumber));
      header.SetAckNumber(SequenceNumber32(RxSeqNumber));

//      header.SetSourcePort(sPort); // m_endPoint->GetLocalPort()
      header.SetSourcePort( m_endPoint->GetLocalPort() ); // m_endPoint->GetLocalPort()
      header.SetDestinationPort(m_dPort);
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
MpTcpSubFlow::Finished(void)
{
  return (m_gotFin && m_finSeq.GetValue() < RxSeqNumber);
}

void
MpTcpSubFlow::StartTracing(string traced)
{
  //NS_LOG_UNCOND("("<< m_routeId << ") MpTcpSubFlow -> starting tracing of: "<< traced);
  TraceConnectWithoutContext(traced, MakeCallback(&MpTcpSubFlow::CwndTracer, this)); //"CongestionWindow"
}

void
MpTcpSubFlow::CwndTracer(uint32_t oldval, uint32_t newval)
{
  //NS_LOG_UNCOND("Subflow "<< m_routeId <<": Moving cwnd from " << oldval << " to " << newval);
  cwndTracer.push_back(make_pair(Simulator::Now().GetSeconds(), newval));
}

void
MpTcpSubFlow::AddDSNMapping(uint8_t sFlowIdx, uint64_t dSeqNum, uint16_t dLvlLen, uint32_t sflowSeqNum, uint32_t ack,
    Ptr<Packet> pkt)
{
  NS_LOG_FUNCTION_NOARGS();
  m_mapDSN.push_back(new DSNMapping(sFlowIdx, dSeqNum, dLvlLen, sflowSeqNum, ack, pkt));
}

void
MpTcpSubFlow::SetFinSequence(const SequenceNumber32& s)
{
  NS_LOG_FUNCTION (this);
  m_gotFin = true;
  m_finSeq = s;
  if (RxSeqNumber == m_finSeq.GetValue())
    ++RxSeqNumber;
}

DSNMapping *
MpTcpSubFlow::GetunAckPkt()
{
  NS_LOG_FUNCTION(this);
  DSNMapping * ptrDSN = 0;
  for (list<DSNMapping *>::iterator it = m_mapDSN.begin(); it != m_mapDSN.end(); ++it)
    {
      DSNMapping * ptr = *it;
      if (ptr->subflowSeqNumber == highestAck + 1)
        {
          ptrDSN = ptr;
          break;
        }
    }
  return ptrDSN;
}
}
