/*
 * MultiPath-TCP (MPTCP) implementation.
 * Programmed by Morteza Kheirkhah from University of Sussex.
 * Some codes here are modeled from ns3::TCPNewReno implementation.
 * Email: m.kheirkhah@sussex.ac.uk
 */
#undef NS_LOG_APPEND_CONTEXT
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
#include "ns3/mp-tcp-id-manager-impl.h"
#include "ns3/tcp-option-mptcp.h"
#include "ns3/callback.h"
#include "ns3/trace-helper.h"
#include <openssl/sha.h>

NS_LOG_COMPONENT_DEFINE("MpTcpSocketBase");

#define LOOP_THROUGH_SUBFLOWS(sflow)  for(SubflowList::iterator sflow = 0; sflow != m_subflows.end(); ++sflow)

using namespace std;


namespace ns3
{

void
dumpNextTxSequence(Ptr<OutputStreamWrapper> stream, std::string context, SequenceNumber32 oldSeq, SequenceNumber32 newSeq)
{
  //<< context <<
//  if (context == "NextTxSequence")

  *stream->GetStream() << Simulator::Now() << "," << oldSeq << "," << newSeq << "\n";
}


void
dumpUint32(Ptr<OutputStreamWrapper> stream, std::string context, uint32_t oldVal, uint32_t newVal) {

//  NS_LOG_UNCOND("Context " << context << "oldVal=" << oldVal << "newVal=" << newVal);

  *stream->GetStream() << Simulator::Now() << "," << oldVal << "," << newVal << "\n";
}


void
dumpTcpState(Ptr<OutputStreamWrapper> stream, std::string context, TcpStates_t oldVal, TcpStates_t newVal) {
  // TODO rely
  *stream->GetStream() << Simulator::Now()
                      << "," << TcpSocket::TcpStateName[oldVal]
                      << "," << TcpSocket::TcpStateName[newVal]
                      << "\n";
}



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
//      .AddAttribute("Subflows", "The list of subflows associated to this protocol.",
//          ObjectVectorValue(),
//          MakeObjectVectorAccessor(&MpTcpSocketBase::m_subflows),
//          MakeObjectVectorChecker<MpTcpSocketBase>())
        .AddTraceSource("CongestionWindow",
          "Congestion window at mptcp level",
          MakeTraceSourceAccessor(&MpTcpSocketBase::m_cWnd)
        )


    ;
  return tid;
}


static const char* containerNames[MpTcpSocketBase::Maximum][20] = {
  "Established",
  "Others",
  "Closing",
  "Maximum"

};


MpTcpSocketBase::MpTcpSocketBase(const MpTcpSocketBase& sock) :
  TcpSocketBase(sock),
  m_mpEnabled(sock.m_mpEnabled),
  m_initialCWnd(sock.m_initialCWnd),
  m_server(sock.m_server), //! true, if I am forked
  m_localKey(sock.m_localKey),
  m_localToken(sock.m_localToken),
  m_peerKey(sock.m_peerKey),
  m_peerToken(sock.m_peerToken),
  m_doChecksum(sock.m_doChecksum)
{
  m_remotePathIdManager = Create<MpTcpPathIdManagerImpl>();
  m_scheduler = Create<MpTcpSchedulerRoundRobin>();
  m_scheduler->SetMeta(this);

  //! TODO here I should generate a new Key
}


// TODO implement a copy constructor
MpTcpSocketBase::MpTcpSocketBase() :
  TcpSocketBase(),
  m_mpEnabled(false),
  m_initialCWnd(20), // TODO reset to 1
  m_server(true),
  m_localKey(0),
  m_localToken(0),
  m_peerKey(0),
  m_peerToken(0),
  m_doChecksum(false)
{
  NS_LOG_FUNCTION(this);

  //not considered as an Object
  m_remotePathIdManager = Create<MpTcpPathIdManagerImpl>();
  m_scheduler = Create<MpTcpSchedulerRoundRobin>();
  m_scheduler->SetMeta(this);


  mod = 60; // ??

  // TODO should be generated either on connect or fork, not here ?
  m_localKey = GenerateKey();

}


MpTcpSocketBase::~MpTcpSocketBase(void)
{
  NS_LOG_FUNCTION(this);
  m_node = 0;

  if( m_scheduler )
  {

  }
  /*
   * Upon Bind, an Ipv4Endpoint is allocated and set to m_endPoint, and
   * DestroyCallback is set to TcpSocketBase::Destroy. If we called
   * m_tcp->DeAllocate, it will destroy its Ipv4EndpointDemux::DeAllocate,
   * which in turn destroys my m_endPoint, and in turn invokes
   * TcpSocketBase::Destroy to nullify m_node, m_endPoint, and m_tcp.
   */
//  if (m_endPoint != 0)
//    {
//      NS_ASSERT(m_tcp != 0);
//      m_tcp->DeAllocate(m_endPoint);
//      NS_ASSERT(m_endPoint == 0);
//    }
//  m_tcp = 0;
//  CancelAllSubflowTimers();
//  NS_LOG_INFO(Simulator::Now().GetSeconds() << " ["<< this << "] ~MpTcpSocketBase ->" << m_tcp );
}

uint64_t
MpTcpSocketBase::GetLocalKey() const
{
  return m_localKey;
}

//int
// uint64_t& remoteKey
uint64_t
MpTcpSocketBase::GetRemoteKey() const
{
  // TODO restablished
  //NS_ASSERT_MSG( IsConnected(),"Can't get the remote key before establishing a connection" );
//  {
    //remoteKey =
  return m_peerKey;
//    return 0;
  //}
  //return -ERROR_INVAL;
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


bool
MpTcpSocketBase::DoChecksum() const
{
  return false;
}

std::vector<MpTcpSubFlow>::size_type
MpTcpSocketBase::GetNActiveSubflows() const
{
  return m_subflows[Established].size();
}

  //std::vector<MpTcpSubFlow>::size_ uint8
Ptr<MpTcpSubFlow>
MpTcpSocketBase::GetSubflow(uint8_t id)
{
  NS_ASSERT_MSG(id < m_subflows[Established].size(), "Trying to get an unexisting subflow");
  return m_subflows[Established][id];
}




// TODO GetLocalAddr


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
  NS_LOG_FUNCTION(this);
}


void
MpTcpSocketBase::SetPeerKey(uint64_t remoteKey)
{
//  NS_ASSERT( m_peerKey == 0);
//  NS_ASSERT( m_state != CLOSED);
//(uint64_t)
  uint64_t idsn = 0;
  m_peerKey = remoteKey;

  // not  sure yet. Wait to see if SYN/ACK is acked
  m_mpEnabled = true;
  NS_LOG_DEBUG("Peer key set to " << m_peerKey);



  //! TODO generate remote token/IDSN
  MpTcpSocketBase::GenerateTokenForKey(MPTCP_SHA1,m_peerKey,m_peerToken,idsn);
  m_rxBuffer.SetNextRxSequence( SequenceNumber32( (uint32_t)idsn )); // + 1 ?
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
      NS_LOG_LOGIC("Received TCP flags " << tcpflags << " while listening");
      return;
    }

  // TODO  check for MP option

  // For now we assume there is only one option of MPTCP kind but there may be several
  // TODO update the SOCIS code to achieve this
  Ptr<TcpOption> option = mptcpHeader.GetOption(TcpOption::MPTCP);
  Ptr<TcpOptionMpTcpMain> opt2 = DynamicCast<TcpOptionMpTcpMain>(option);


  // Expect an MP_CAPABLE option
  NS_ASSERT_MSG( opt2->GetSubType() == TcpOptionMpTcpMain::MP_CAPABLE, "MPTCP sockets can only connect to MPTCP sockets. There is no fallback implemented yet." );


  // Call socket's notify function to let the server app know we got a SYN
  // If the server app refuses the connection, do nothing
  if (!NotifyConnectionRequest(fromAddress))
  {
    NS_LOG_ERROR("Server refuse the incoming connection!");
    return;
  }



  // simulate fork. The MP_CAPABLe option will be checked in completeFork
  Ptr<MpTcpSocketBase> newSock = ForkAsMeta();
  // NS_LOG_DEBUG ("Clone new MpTcpSocketBase new connection. ListenerSocket " << this << " AcceptedSocket "<< newSock);
  Simulator::ScheduleNow(&MpTcpSocketBase::CompleteFork, newSock, packet, mptcpHeader, fromAddress, toAddress);
}


/**
TODO if without option create a NewReno
**/
void
MpTcpSocketBase::CompleteFork(Ptr<Packet> p, const TcpHeader& mptcpHeader, const Address& fromAddress, const Address& toAddress)
{
  NS_LOG_FUNCTION(this);

  // Get port and address from peer (connecting host)

  // That should not be the case
//  NS_ASSERT(InetSocketAddress::ConvertFrom(toAddress).GetIpv4() == m_endPoint->GetLocalAddress());
//  NS_ASSERT(InetSocketAddress::ConvertFrom(toAddress).GetPort() == m_endPoint->GetLocalPort());
//
//  NS_ASSERT(InetSocketAddress::ConvertFrom(fromAddress).GetIpv4() == m_endPoint->GetPeerAddress());
//  NS_ASSERT(InetSocketAddress::ConvertFrom(fromAddress).GetPort() == m_endPoint->GetPeerPort());

//  Ptr<TcpOption> option = mptcpHeader.GetOption(TcpOption::MPTCP);
//  Ptr<TcpOptionMpTcpMain> opt2 = DynamicCast<TcpOptionMpTcpMain>(option);

  Ptr<TcpOptionMpTcpCapable> mpc;
//   = DynamicCast<TcpOptionMpTcpCapable>(option);

  NS_ASSERT( GetMpTcpOption(mptcpHeader, mpc) );

  m_server = true;
      // Aussi le from address
//      subflow->

  NS_LOG_INFO("peer key " << mpc->GetSenderKey() );

  // Register keys
  SetPeerKey( mpc->GetSenderKey() );



  // got moved to constructor
//  m_localKey = GenerateKey();
//  uint64_t idsn = 0;
//  GenerateTokenForKey( MPTCP_SHA1, m_localKey, m_localToken, idsn );
//
//  /**
//  /!\ seq nb must be 64 bits for mptcp but that would mean rewriting lots of code so
//
//  **/


  // We only setup destroy callback for MPTCP connection's endPoints, not on subflows endpoints.
  SetupCallback();

  m_tcp->m_sockets.push_back(this);

  // Create new master subflow (master subsock) and assign its endpoint to the connection endpoint
  Ptr<MpTcpSubFlow> sFlow = CreateSubflow(true);



  m_state = SYN_RCVD; // Think of updating it
  NS_LOG_INFO(this << " LISTEN -> SYN_RCVD");
  NS_ASSERT_MSG(sFlow,"Contact ns3 team");


  // We deallocate the endpoint so that the subflow can reallocate it


  // upon subflow destruction this m_endpoint should be .
//  m_endPoint = 0;
  m_endPoint6 = 0;

//  NS_ASSERT( GetNActiveSubflows() == 0);
//  m_subflows.clear();
  m_subflows[Others].push_back( sFlow );

  Simulator::ScheduleNow(&MpTcpSubFlow::CompleteFork, sFlow, p, mptcpHeader, fromAddress, toAddress);

//  Simulator::ScheduleNow(&MpTcpSocketBase:: , this, fromAddress);
  m_connected = true;
  NotifyNewConnectionCreated(this,fromAddress);
  // As this connection is established, the socket is available to send data now
  if (GetTxAvailable() > 0)
  {
    NotifySend(GetTxAvailable());
  }
  // Update currentSubflow in case close just after 3WHS.
//  NS_LOG_UNCOND("CompleteFork -> receivingBufferSize: " << m_recvingBuffer->bufMaxSize);
  NS_LOG_INFO(this << "  MPTCP connection is initiated (Receiver): ");
}


 // in fact it just calls SendPendingData()
int
MpTcpSocketBase::Send(Ptr<Packet> p, uint32_t flags)
{
  NS_LOG_FUNCTION(this);

  //! This will check for established state
  return TcpSocketBase::Send(p,flags);
}


// Schedule-friendly wrapper for Socket::NotifyConnectionSucceeded()



void
MpTcpSocketBase::CancelAllSubflowTimers(void)
{
  NS_LOG_FUNCTION_NOARGS();

  // TODO use iterator
//  for (uint32_t i = 0; i < m_subflows.size(); i++)
//    {
//      Ptr<MpTcpSubFlow> sFlow = m_subflows[i];
//      if (sFlow->m_state != CLOSED)
//        {
//          sFlow->CancelAllTimers();
//          NS_LOG_INFO("CancelAllSubflowTimers() -> Subflow:" << i);
//        }
//    }
}


// Receipt of new packet, put into Rx buffer
// TODO should be called from subflows only
void
MpTcpSocketBase::ReceivedData(Ptr<Packet> p, const TcpHeader& mptcpHeader)
{
  // Just override parent's
  // Does nothing
  NS_FATAL_ERROR("Disabled");
}


/** Process the newly received ACK */
//, uint32_t dack
void
MpTcpSocketBase::AppendDataAck(TcpHeader& hdr) const
{
  NS_LOG_FUNCTION(this);

  Ptr<TcpOptionMpTcpDSS> dss;
  GetOrCreateMpTcpOption(hdr, dss);
//  Ptr<TcpOptionMpTcpDSS> dss;
//  if(!GetMpTcpOption(hdr,dss)) {
//    dss = TcpOptionMpTcpMain::CreateMpTcpOption(TcpOptionMpTcpMain::MP_DSS);
//  }

  NS_ASSERT( (dss->GetFlags() & TcpOptionMpTcpDSS::DataAckPresent) == 0);

//   = CreateObject<TcpOptionMpTcpDSS>();
  uint32_t dack = m_rxBuffer.NextRxSequence().GetValue();
  dss->SetDataAck( dack );

  // TODO check the option is not in the header already
//  NS_ASSERT_MSG( hdr.GetOption()GetOp)


}


// TODO rename into DSS
void
MpTcpSocketBase::ProcessDSS(Ptr<TcpOptionMpTcpDSS> dss
                             , Ptr<MpTcpSubFlow> sf
                             )
{
  NS_LOG_FUNCTION ( this << "Received ack " << dss << " from subflow " << sf);

  switch(m_state) {

    case ESTABLISHED:
      ProcessDSSEstablished(dss,sf);
      break;

//    case LAST_ACK:
//    case CLOSING:
//      ProcessDSSClosing(dss,sf);
//      break;
    case FIN_WAIT_1:
    case FIN_WAIT_2:
    case CLOSE_WAIT:
    case LAST_ACK:
    case CLOSING:
      // do nothing just wait for subflows to be closed
      ProcessDSSWait(dss,sf);
      break;
    case TIME_WAIT:
      // do nothing
      break;

    case LISTEN:
    case SYN_RCVD:
    case SYN_SENT:
    default:
      NS_LOG_INFO("Unhandled case");
      break;
  };

  // If there is any data piggybacked, store it into m_rxBuffer
//  if (packet->GetSize() > 0)
//    {
//      ReceivedData(packet, tcpHeader);
//    }
//  #endif

}


void
MpTcpSocketBase::DupAck( SequenceNumber32 ack,Ptr<MpTcpSubFlow> sf)
{
  //!
  NS_LOG_INFO("Duplicate ACK, TODO");
}


void
MpTcpSocketBase::ReceivedAck(Ptr<Packet> packet, const TcpHeader& mptcpHeader)
{
  NS_FATAL_ERROR("Disabled");
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
//  NS_LOG_FUNCTION (this << "Should do nothing" << maxSize << withAck);
  NS_FATAL_ERROR("Disabled");
  // Disabled
  return 0;
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
  return ForkAsMeta();
//  CopyObject<MpTcpSocketBase>(this);
}

/** Cut cwnd and enter fast recovery mode upon triple dupack TODO ?*/



void
MpTcpSocketBase::DupAck(const TcpHeader& t, uint32_t count)
{
  NS_ASSERT_MSG(false,"Should never be called");
}
//...........................................................................................


/** Inherit from Socket class: Get the max number of bytes an app can read */
uint32_t
MpTcpSocketBase::GetRxAvailable(void) const
{
  NS_LOG_FUNCTION (this);
  return m_rxBuffer.Available();
}



void
MpTcpSocketBase::OnSubflowClosed( Ptr<MpTcpSubFlow> sf)
{
  NS_LOG_INFO("Subflow closed");
  //! TODO it should remove itself from the list of subflows and when 0 are active
  // it should call CloseAndNotify ?
}



//Ptr<Socket> sock
//SequenceNumber32 dataSeq,
/**
TODO the decision to ack is unclear with this structure.
May return a bool to let subflow know if it should return a ack ?
it would leave the possibility for meta to send ack on another subflow

NotifySend(
**/
void
MpTcpSocketBase::OnSubflowRecv( Ptr<MpTcpSubFlow> sf )
{
  //!
  NS_LOG_FUNCTION(this << "Received data from " << sf);

  NS_ASSERT(IsConnected());
//  Ptr<MpTcpSubFlow> sf = DynamicCast<MpTcpSubFlow>(sock);

  //while (sock->GetRxAvailable () > 0 && m_currentSourceRxBytes < m_totalBytes)
  //{
//  uint32_t toRead = std::min (m_sourceReadSize, sock->GetRxAvailable () );
  //Ptr<Packet> p = sock->Recv (toRead, 0);
  SequenceNumber32 dsn;
  SequenceNumber32 expectedDSN = m_rxBuffer.NextRxSequence();

  Ptr<Packet> p;

  uint32_t canRead = m_rxBuffer.MaxBufferSize() - m_rxBuffer.Size();
  NS_LOG_INFO("Rcv buf max size [" << GetRcvBufSize() << "]");
  NS_LOG_INFO("Can read [" << canRead << "]");
  while( (canRead > 0) && (sf->GetRxAvailable() > 0) )
  {
    NS_LOG_INFO("sf->GetRxAvailable [" << sf->GetRxAvailable() << "]");

    p = sf->RecvWithMapping ( canRead, dsn);

    // Pb here, htis will be extracted but will not be saved into the main buffer
    // TODO check for dsn ?
    if( p->GetSize() )
    {
      NS_LOG_DEBUG("Amount read from data not empty => " << p->GetSize()  );

      if (!m_rxBuffer.Add(p, dsn))
        { // Insert failed: No data or RX buffer full
    //      SendEmptyPacket(TcpHeader::ACK);
          NS_LOG_ERROR("This should not happen !! DSN might be wrong ?! ");
          return;
        }
      if (m_rxBuffer.Size() > m_rxBuffer.Available() || m_rxBuffer.NextRxSequence() > expectedDSN + p->GetSize())
        { // A gap exists in the buffer, or we filled a gap: Always ACK
    //      SendEmptyPacket(TcpHeader::ACK);
          NS_LOG_DEBUG ("Look into !");
        }
      else
        {
          // TODO should restablish delayed acks ?
            NS_LOG_DEBUG ("Delayed acks disabled");
            // This sh
            sf->SendEmptyPacket(TcpHeader::ACK);
          // We've disabled Delayed ack  on this socket ?
          // In-sequence packet: ACK if delayed ack count allows
    //      if (++m_delAckCount >= m_delAckMaxCount)
    //        {
    //          m_delAckEvent.Cancel();
    //          m_delAckCount = 0;
    //          SendEmptyPacket(TcpHeader::ACK);
    //        }
    //      else if (m_delAckEvent.IsExpired())
    //        {
    //          m_delAckEvent = Simulator::Schedule(m_delAckTimeout, &TcpSocketBase::DelAckTimeout, this);
    //          NS_LOG_LOGIC (this << " scheduled delayed ACK at " << (Simulator::Now () + Simulator::GetDelayLeft (m_delAckEvent)).GetSeconds ());
    //        }
        }
    }
  }

  if (p == 0 )
  {
    if(sf->GetErrno () != Socket::ERROR_NOTERROR)
    {
      NS_FATAL_ERROR ("error");
    }
    else
    {
      NS_LOG_DEBUG ("Empty packet extracted");
      return;
    }
  }

  // TODO
  // Now we should add this data to the local buffer and notify
//  m_rxBuffer.Add(p,dsn);

  // Put into Rx buffer

  // Notify app to receive if necessary
  NS_LOG_DEBUG("expectedSeq " << expectedDSN << " vs NextRxSequence " << m_rxBuffer.NextRxSequence() );

  if (expectedDSN < m_rxBuffer.NextRxSequence())
    {
      NS_LOG_LOGIC("The Rxbuffer advanced");

      // NextRxSeq advanced, we have something to send to the app
      if (!m_shutdownRecv)
        {
          //<< m_receivedData
          NS_LOG_LOGIC("Notify data Rcvd" );
          NotifyDataRecv();

          // discards  old mappings
          sf->m_RxMappings.DiscardMappingsUpToDSN( m_rxBuffer.NextRxSequence() - 1 );
        }
      // Handle exceptions
      if (m_closeNotified)
        {
          NS_LOG_WARN ("Why TCP " << this << " got data after close notification?");
        }
      // If we received FIN before and now completed all "holes" in rx buffer,
      // invoke peer close procedure
      // TODO this should be handled cautiously. TO reenable later with the correct
      // MPTCP syntax
//      if (m_rxBuffer.Finished() && (tcpHeader.GetFlags() & TcpHeader::FIN) == 0)
//        {
//          DoPeerClose();
//        }
    }

}


// TODO rename ? CreateAndAdd? Add ? Start ? Initiate
//int
Ptr<MpTcpSubFlow>
MpTcpSocketBase::CreateSubflow(bool masterSocket)
{
//  NS_ASSERT_MSG(
//  InetSocketAddress::IsMatchingType(_srcAddr),
//  InetSocketAddress srcAddr = InetSocketAddress::ConvertFrom(_srcAddr);

//  bool masterSocket = false;
  // TODO could replaced that by the number of established subflows
  // rename getSubflow by
  if( IsConnected() )
  {
    if(!IsMpTcpEnabled())
    {
      NS_LOG_ERROR("Remote host does not seem MPTCP compliant so impossible to create additionnal subflows");
//      return -ERROR_INVAL;
      return 0;
    }
  }
  //else if( GetNActiveSubflows() > 0 )
  else if( m_state == SYN_SENT || m_state == SYN_RCVD)
  {
    // throw an assert here instead ?
    NS_LOG_ERROR("Already attempting to establish a connection");
//    return -ERROR_INVAL;
    return 0;
  }
  else if(m_state == TIME_WAIT || m_state == CLOSE_WAIT || m_state == CLOSING)
  {
//    NS_LOG_UNCOND ( "How did I arrive here ?");
    NS_LOG_ERROR("Can't create subflow ");

  }

  Ptr<Socket> sock = m_tcp->CreateSocket( MpTcpSubFlow::GetTypeId() );

  Ptr<MpTcpSubFlow> sFlow = DynamicCast<MpTcpSubFlow>(sock);
  // So that we know when the connection gets established
  //sFlow->SetConnectCallback( MakeCallback (&MpTcpSocketBase::OnSubflowEstablishment, Ptr<MpTcpSocketBase>(this) ) );
  sFlow->SetMeta(this);
  sFlow->m_masterSocket = masterSocket;
  sFlow->SetInitialCwnd( GetInitialCwnd() );
  NS_ASSERT_MSG( sFlow, "Contact ns3 team");

  // can't use that because we need the associated ssn to deduce the DSN
  //sFlow->SetRecvCallback (MakeCallback (&MpTcpSocketBase::OnSubflowRecv, this));

  // TODO find associated device and bind to it
//  sFlow->BindToNetDevice (this->FindOutputNetDevice() )
//  if(!sFlow->Connect( dstAddr) )
//  {
//    NS_LOG_ERROR("Could not connect subflow");
//    return 0;
//  }

  NS_LOG_INFO ( "subflow " << sFlow << " associated with node " << sFlow->m_node);
//  m_subflows.push_back( sFlow );

  // TODO set id of the Flow
  // It's
//  static routeId
//  sFlow->m_routeId = m_subflows.size() - 1;
  // Should not be needed since bind register socket
//  m_tcp->m_sockets.push_back(this); // called after a bind or in a completeFork
  return sFlow;
}


/**
I ended up duplicating this code to update the meta r_Wnd,
which would have been hackish otherwise

**/
void
MpTcpSocketBase::DoForwardUp(Ptr<Packet> packet, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface> incomingInterface)
{
  NS_LOG_FUNCTION(this);
  TcpSocketBase::DoForwardUp(packet,header,port,incomingInterface);

}


/**
Need to override parent's otherwise it allocates an endpoint to the meta socket
and upon connection , the tcp subflow can't allocate
*/
int
MpTcpSocketBase::Connect(const Address & toAddress)
{
  NS_LOG_FUNCTION(this);

  // TODO may have to set m_server to false here

  if( IsConnected() )
  {
    NS_LOG_WARN("Trying to connect meta while already connected");
    return -ERROR_ISCONN; // INVAL ?
  }

  //! TODO should generate a key
  if (m_state == CLOSED || m_state == LISTEN || m_state == SYN_SENT || m_state == LAST_ACK || m_state == CLOSE_WAIT)
    {
      m_server = false;

      Ptr<MpTcpSubFlow> sFlow = CreateSubflow(true);


      // This function will allocate a new one
      int ret = sFlow->Connect(toAddress);

      if(ret != 0)
      {
        NS_LOG_ERROR("Could not connect but why ? TODO destroy subflow");
        // TODO destroy
        return ret;
      }
      // NS_LOG_INFO ("looks like successful connection");
//      m_endPoint = sFlow->m_endPoint;
//      m_endPoint6 = sFlow->m_endPoint6;

      m_subflows[Others].push_back( sFlow );

//      NS_ASSERT( );
//      SendEmptyPacket(TcpHeader::SYN);
      NS_LOG_INFO (TcpStateName[m_state] << " -> SYN_SENT");
      m_state = SYN_SENT;

      return ret;
    }
  else if (m_state != TIME_WAIT)
    { // In states SYN_RCVD, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, and CLOSING, an connection
      // exists. We send RST, tear down everything, and close this socket.
      // TODO
//      SendRST();
//      CloseAndNotify();
      NS_LOG_UNCOND("Time wait");
      return -ERROR_ADDRINUSE;
    }

  return DoConnect();
}

/** This function closes the endpoint completely. Called upon RST_TX action. */
void
MpTcpSocketBase::SendRST(void)
{
  NS_FATAL_ERROR("TO REMOVE");
}

void
MpTcpSocketBase::SendFastClose(Ptr<MpTcpSubFlow> sf)
{
  NS_LOG_FUNCTION (this);
//  NS_FATAL_ERROR("TODO");
  // TODO: send an MPTCP_fail
   TcpHeader header;
//   Ptr<MpTcpSubFlow> sf = GetSubflow(0);
  sf->GenerateEmptyPacketHeader(header,TcpHeader::RST);
  Ptr<TcpOptionMpTcpFastClose> opt= Create<TcpOptionMpTcpFastClose>();

  opt->SetPeerKey( GetRemoteKey() );

  sf->SendEmptyPacket(header);

  //! Enter TimeWait ?
//  NotifyErrorClose();
  TimeWait();
//  DeallocateEndPoint();
}


int
MpTcpSocketBase::DoConnect(void)
{
  NS_LOG_FUNCTION (this << "Disabled");
//DeAllocate
//  if(IsConnected()) {
//    NS_LOG_WARN(this << " is already connected");
//    return -1;
//  }
  #if 0
  // A new connection is allowed only if this socket does not have a connection
  // TODO is this check enough for multiple subflows ?
  if (m_state == CLOSED || m_state == LISTEN || m_state == SYN_SENT || m_state == LAST_ACK || m_state == CLOSE_WAIT)
    {
      // send a SYN packet and change state into SYN_SENT
      Ptr<MpTcpSubFlow> sFlow = CreateSubflow(
            InetSocketAddress(m_endPoint->GetLocalAddress(), m_endPoint->GetLocalPort())
          );
      // We should not bind

      // This function will allocate a new one
      int ret = sFlow->Connect(
                InetSocketAddress( m_endPoint->GetPeerAddress(), m_endPoint->GetPeerPort() )
                  );

      if(ret != 0)
      {
        NS_LOG_ERROR("Could not connect but why ? TODO destroy subflow");
        // TODO destroy
        return ret;
      }
      NS_LOG_INFO ("");
      m_endPoint = sFlow->m_endPoint;
      m_endPoint6 = sFlow->m_endPoint6;
//      NS_ASSERT( );
//      SendEmptyPacket(TcpHeader::SYN);
//      NS_LOG_INFO (TcpStateName[m_state] << " -> SYN_SENT");
      m_state = SYN_SENT;
    }
  else if (m_state != TIME_WAIT)
    { // In states SYN_RCVD, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, and CLOSING, an connection
      // exists. We send RST, tear down everything, and close this socket.
      // TODO
//      SendRST();
//      CloseAndNotify();
      NS_LOG_UNCOND("Time wait");
    }

  #endif
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

void
MpTcpSocketBase::ConnectionSucceeded(void)
{
  NS_LOG_FUNCTION(this);
   m_connected = true;
   TcpSocketBase::ConnectionSucceeded();
}

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



//int
//MpTcpSocketBase::Connect(const Address &address)
//{
//  NS_LOG_FUNCTION ( this << address );
//  // this should call our own DoConnect
//  return TcpSocketBase::Connect(address);
//}


/** Inherited from Socket class: Bind socket to an end-point in MpTcpL4Protocol */
int
MpTcpSocketBase::Bind()
{
  NS_LOG_FUNCTION (this);
  m_server = true;
  m_endPoint = m_tcp->Allocate();  // Create endPoint with ephemeralPort
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
  return TcpSocketBase::SetupCallback();
}

/** Inherit from socket class: Bind socket (with specific address) to an end-point in TcpL4Protocol */
int
MpTcpSocketBase::Bind(const Address &address)
{
  NS_LOG_FUNCTION (this<<address);
  m_server = true;
  return TcpSocketBase::Bind(address);
}



// CAREFUL, note that here it's SequenceNumber64
//void
//MpTcpSocketBase::NewAck(SequenceNumber64 const& dataLevelSeq)
//{
//  //!
//
//}

  /*
 Notably, it is only DATA_ACKed once all
   data has been successfully received at the connection level.  Note,
   therefore, that a DATA_FIN is decoupled from a subflow FIN.  It is
   only permissible to combine these signals on one subflow if there is
   no data outstanding on other subflows. */
void
MpTcpSocketBase::PeerClose( SequenceNumber32 dsn, Ptr<MpTcpSubFlow> sf)
{
  NS_LOG_LOGIC(this << "Datafin with seq " << dsn);


//  SequenceNumber32 dsn = SequenceNumber32 (dss->GetDataFinDSN() );
  if( dsn < m_rxBuffer.NextRxSequence() || m_rxBuffer.MaxRxSequence() < dsn) {

    NS_LOG_INFO("dsn " << dsn << " out of expected range [ " << m_rxBuffer.NextRxSequence()  << " - " << m_rxBuffer.MaxRxSequence() << " ]" );
    return ;
  }


  // For any case, remember the FIN position in rx buffer first
  //! +1 because the datafin doesn't count as payload
  // TODO rename mapping into GetDataMapping
//  NS_LOG_LOGIC("Setting FIN sequence to " << dss->GetMapping().TailDSN());
  m_rxBuffer.SetFinSequence(dsn);

  // Return if FIN is out of sequence, otherwise move to CLOSE_WAIT state by DoPeerClose
  if (!m_rxBuffer.Finished())
  {
    NS_LOG_WARN("Out of range");
    return;
  }

//  NS_LOG_LOGIC ("Accepted DATA FIN at seq " << tcpHeader.GetSequenceNumber () + SequenceNumber32 (p->GetSize ()));

  // Simultaneous close: Application invoked Close() when we are processing this FIN packet
  TcpStates_t old_state = m_state;
  switch(m_state) {
    case FIN_WAIT_1:
      m_state = CLOSING;
      break;

    case FIN_WAIT_2:
      // will go into timewait later
      break;

    case ESTABLISHED:
      m_state = CLOSE_WAIT;
      break;

    default:
      NS_FATAL_ERROR("Should not be here");
      break;
  };

  NS_LOG_INFO(TcpStateName[old_state] << " -> " << TcpStateName[m_state]);


//  if (m_state == FIN_WAIT_1 || m_state == FIN_WAIT_2 || m_state == ESTABLISHED)
//    {
//      NS_LOG_INFO ("FIN_WAIT_1 -> CLOSING");
//      m_state = CLOSING;

      // TODO should send dataACK
      TcpHeader header;
      AppendDataAck(header);
      sf->GenerateEmptyPacketHeader(header,TcpHeader::ACK);
      //!
      sf->SendEmptyPacket(header);
//      return;
//    }

    if(old_state == FIN_WAIT_2) {
      TimeWait();
    }
//  switch(m_state) {
//
//
//    default:
//      break;
//  };
//   DoPeerClose();
}

void
MpTcpSocketBase::OnInfiniteMapping(Ptr<TcpOptionMpTcpDSS> dss,Ptr<MpTcpSubFlow> sf)
{
  NS_FATAL_ERROR("Infinite mapping not implemented");
}

// TODO call 64bits  version ?
// It should know from which subflow it comes from
void
MpTcpSocketBase::NewAck(SequenceNumber32 const& dsn)
{
  NS_LOG_FUNCTION(this << " new dataack=[" <<  dsn << "]");

  // TODO
//  switch(m_state) {
//
//  };


  // update tx buffer
  // TODO if I call this, it crashes because on the MpTcpBase client, there is no endpoint configured
  // so it tries to connect to IPv6 node
//  TcpSocketBase::NewAck( seq  );

  // Retrieve the highest m_txBuffer

  // Is done at subflow lvl alread
  // should be done from here for all subflows since
  // a same mapping could have been attributed to for allo
  // BUT can't be discarded if not acklowdged at subflow level so...
//  sf->DiscardTxMappingsUpToDSN( m_txBuffer.HeadSequence() );
//    in that fct
//  discard

//  NS_LOG_FUNCTION (this << dsn);

// TODO reestablish
//  if (m_state != SYN_RCVD)
//    { // Set RTO unless the ACK is received in SYN_RCVD state
//      NS_LOG_LOGIC (this << " Cancelled ReTxTimeout event which was set to expire at " <<
//          (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
//      m_retxEvent.Cancel();
//      // On recieving a "New" ack we restart retransmission timer .. RFC 2988
//      m_rto = m_rtt->RetransmitTimeout();
//      NS_LOG_LOGIC (this << " Schedule ReTxTimeout at time " <<
//          Simulator::Now ().GetSeconds () << " to expire at time " <<
//          (Simulator::Now () + m_rto.Get ()).GetSeconds ());
//      m_retxEvent = Simulator::Schedule(m_rto, &MpTcpSocketBase::ReTxTimeout, this);
//    }

  // TODO update m_rWnd
//  m_rWnd.Get() == 0
  if (m_rWnd.Get() == 0 && m_persistEvent.IsExpired())
    { // Zero window: Enter persist state to send 1 byte to probe
      NS_LOG_LOGIC (this << "Enter zerowindow persist state");NS_LOG_LOGIC (this << "Cancelled ReTxTimeout event which was set to expire at " <<
          (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
      m_retxEvent.Cancel();
      NS_LOG_LOGIC ("Schedule persist timeout at time " <<
          Simulator::Now ().GetSeconds () << " to expire at time " <<
          (Simulator::Now () + m_persistTimeout).GetSeconds ());
      m_persistEvent = Simulator::Schedule(m_persistTimeout, &MpTcpSocketBase::PersistTimeout, this);
      NS_ASSERT(m_persistTimeout == Simulator::GetDelayLeft (m_persistEvent));
    }
//    #endif
  // Note the highest ACK and tell app to send more
  NS_LOG_LOGIC ("TCP " << this << " NewAck " << dsn <<
      " numberAck " << (dsn - m_txBuffer.HeadSequence ())); // Number bytes ack'ed



// TODO i should remove data at some point
  m_txBuffer.DiscardUpTo(dsn);


  // TODO that should be triggered !!! it should ask the meta for data rather !
  if (GetTxAvailable() > 0)
    {
      NS_LOG_INFO("Tx available");
      NotifySend(GetTxAvailable());
    }

  if (dsn > m_nextTxSequence)
    {
      m_nextTxSequence = dsn; // If advanced
    }


  // m_txFueer
  if (m_txBuffer.Size() == 0 && m_state != FIN_WAIT_1 && m_state != CLOSING)
    { // No retransmit timer if no data to retransmit
      NS_LOG_WARN (this << " Cancelled ReTxTimeout event which was set to expire at " <<
          (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
      m_retxEvent.Cancel();
      return;
    }

  // Partie que j'ai ajoutée to help closing the connection
  // maybe remove some of it
  if (m_txBuffer.Size() == 0)
    {
      // In case we m_RxBuffer m_rxBuffer.Finished()
      // m_highTxMark + SequenceNumber32(1)
      if(m_state == FIN_WAIT_1 && m_txBuffer.Size() == 0 &&  (dsn == m_txBuffer.HeadSequence() + SequenceNumber32(1) ) ) {

        NS_LOG_LOGIC("FIN_WAIT_1 -> FIN_WAIT_2 ");
        m_state=FIN_WAIT_2;
        TcpHeader header;

        GetSubflow(0)->GenerateEmptyPacketHeader(header, TcpHeader::ACK);
        AppendDataAck(header);
        GetSubflow(0)->SendEmptyPacket(header);
        //!

      }
//      else if (m_state == FIN_WAIT_2) {
////        Send DACK for DFIN
//        NS_LOG_INFO("FIN_WAIT_2 test");
//        CloseAllSubflows();
//      }
//      else if (m_state == FIN_WAIT_1) {
//        //!
//      }


      throughput = 10000000 * 8 / (Simulator::Now().GetSeconds() - fLowStartTime);
      NS_LOG_UNCOND("goodput -> " << throughput / 1000000 << " Mbps {Tx Buffer is now empty}  P-AckHits:" << pAckHit);
      return;
    }
  // in case it freed some space in cwnd, try to send more data
  SendPendingData(m_connected);
}

// Send 1-byte data to probe for the window size at the receiver when
// the local knowledge tells that the receiver has zero window size
// C.f.: RFC793 p.42, RFC1112 sec.4.2.2.17
void
MpTcpSocketBase::PersistTimeout()
{
  NS_LOG_LOGIC ("PersistTimeout expired at " << Simulator::Now ().GetSeconds ());
  NS_FATAL_ERROR("TODO");
}

/**
 * Sending data via subflows with available window size.
 * Todo somehow rename to dispatch
 */
bool
MpTcpSocketBase::SendPendingData(bool withAck)
{
  NS_LOG_FUNCTION(this << "Sending data");

//  MappingList mappings;
  //start/size
  int nbMappingsDispatched = 0; // mimic nbPackets in TcpSocketBase::SendPendingData

  MappingVector mappings;
  //mappings.reserve( GetNActiveSubflows() );
  //
  m_scheduler->GenerateMappings(mappings);



//  NS_ASSERT_MSG( mappings.size() == GetNActiveSubflows(), "The number of mappings should be equal to the nb of already established subflows" );

  NS_LOG_DEBUG("generated [" << mappings.size() << "] mappings");
  // TODO dump mappings ?
  // Loop through mappings and send Data
//  for(int i = 0; i < (int)GetNActiveSubflows() ; i++ )
  for(MappingVector::iterator it(mappings.begin()); it  != mappings.end(); it++ )
  {


    Ptr<MpTcpSubFlow> sf = GetSubflow(it->first);
    MpTcpMapping& mapping = it->second;
//    Retrieve data  Rename SendMappedData
    //SequenceNumber32 dataSeq = mappings[i].first;
    //uint16_t mappingSize = mappings[i].second;

    NS_LOG_DEBUG("Sending mapping "<< mapping << " on subflow #" << it->first);

    //sf->AddMapping();
    int ret = sf->SendMapping(m_txBuffer.CopyFromSequence(mapping.GetLength(), mapping.HeadDSN()), mapping);


    if( ret < 0)
    {
      // TODO dump the mappings ?
      NS_FATAL_ERROR("Could not send mapping. The generated mappings");
    }

    // if successfully sent,
    nbMappingsDispatched++;

    // TODO ensure mappings always work
//    NS_ASSERT(ret > 0);
    bool sentPacket = sf->SendPendingData();
    NS_LOG_DEBUG("Packet sent ? >> " << sentPacket );
//      uint32_t s = std::min(w, m_segmentSize);  // Send no more than window
//      uint32_t sz = SendDataPacket(m_nextTxSequence, s, withAck);
//      nPacketsSent++;                             // Count sent this loop
//      NS_LOG_DEBUG("m_nextTxSequence [" << m_nextTxSequence << "]");
//      m_nextTxSequence += sz;                     // Advance next tx sequence

  // TODO here update the m_nextTxSequence only if it is in order
      // Maybe the max is unneeded; I put it here
    if( mapping.HeadDSN() <= m_nextTxSequence && mapping.TailDSN() >= m_nextTxSequence) {
      m_nextTxSequence = mapping.TailDSN() + 1;
      m_highTxMark = std::max( m_highTxMark.Get(), mapping.TailDSN());
    }
//      m_nextTxSequence = std::max(m_nextTxSequence.Get(), mapping.TailDSN() + 1);



//      NS_LOG_DEBUG("m_nextTxSequence [" << m_nextTxSequence << "]");
//    }NS_LOG_LOGIC ("SendPendingData sent " << nPacketsSent << " packets");
  }

//  m_closeOnEmpty

  uint32_t remainingData = m_txBuffer.SizeFromSequence(m_nextTxSequence );

  if (m_closeOnEmpty && (remainingData == 0))
    {
      TcpHeader header;

      ClosingOnEmpty(header);

    }

//  NS_LOG_LOGIC ("Dispatched " << nPacketsSent << " mappings");
  return nbMappingsDispatched > 0;
}

int
MpTcpSocketBase::Listen(void)
{
  NS_LOG_FUNCTION (this);
  return TcpSocketBase::Listen();

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
  NS_LOG_FUNCTION (this);
//  NS_FATAL_ERROR("TODO");
  NS_LOG_ERROR("TODO");

  TcpSocketBase::Retransmit();
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

void
MpTcpSocketBase::ReTxTimeout()
{
  NS_LOG_FUNCTION(this);
  return TcpSocketBase::ReTxTimeout();
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

void
MpTcpSocketBase::GenerateTokenForKey( mptcp_crypto_t alg, uint64_t key, uint32_t& token, uint64_t& idsn)
{
  NS_ASSERT_MSG(alg == MPTCP_SHA1, "Only sha1 hmac currently supported (and standardised !)");

  const int DIGEST_SIZE_IN_BYTES = SHA_DIGEST_LENGTH; //20

  const int KEY_SIZE_IN_BYTES = 8;
//  const int TOKEN_SIZE_IN_BYTES = 4;
  Buffer keyBuff, digestBuf;
  keyBuff.AddAtStart(KEY_SIZE_IN_BYTES);
  digestBuf.AddAtStart(DIGEST_SIZE_IN_BYTES);

  Buffer::Iterator it = keyBuff.Begin();
  it.WriteHtonU64(key);

//  uint32_t result = 0;
//  unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
  uint8_t digest[DIGEST_SIZE_IN_BYTES];
//  const uint8_t* test = (const uint8_t*)&key;
  // Convert to network order
  // computes hash of KEY_SIZE_IN_BYTES bytes in keyBuff
// TODO according to openssl doc (https://www.openssl.org/docs/crypto/EVP_DigestInit.html#)
// we should use  EVP_MD_CTX *mdctx; instead of sha1
	SHA1( keyBuff.PeekData(), KEY_SIZE_IN_BYTES, digest);

	Buffer::Iterator it_digest = digestBuf.Begin();
	it_digest.Write( digest , DIGEST_SIZE_IN_BYTES ); // strlen( (const char*)digest)
	it_digest = digestBuf.Begin();
  token = it_digest.ReadNtohU32();
  it_digest.Next( 8 );

  idsn = it_digest.ReadNtohU64();

}

//int
//MpTcpSocketBase::GenerateToken(uint32_t& token) const
//{
//  // if connection not established yet then we've got not key to generate the token
//  if( IsConnected() )
//  {
//    // TODO hash keys
//    token = 2;
//    return 0;
//  }
//
//  return -ERROR_NOTCONN;
//}




uint64_t
MpTcpSocketBase::GenerateKey()
{
  // TODO rather use NS3 random generator
  NS_ASSERT_MSG( m_localKey == 0, "Key already generated");

  //! arbitrary function, TODO replace with ns3 random gneerator
  m_localKey = (rand() % 1000 + 1);

  uint64_t idsn = 0;
  GenerateTokenForKey( MPTCP_SHA1, m_localKey, m_localToken, idsn );

  /**

  /!\ seq nb must be 64 bits for mptcp but that would mean rewriting lots of code so

  TODO add a SetInitialSeqNb member into TcpSocketBase
  **/
  m_nextTxSequence = (uint32_t)idsn;
  m_txBuffer.SetHeadSequence(m_nextTxSequence);
  m_highTxMark = m_nextTxSequence;


  return m_localKey;
}



//void
//MpTcpSocketBase::GetIdManager()
//{
//  NS_ASSERT(m_remotePathIdManager);
//  return m_remotePathIdManager;
//}

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

void
MpTcpSocketBase::MoveSubflow(Ptr<MpTcpSubFlow> subflow, mptcp_container_t from, mptcp_container_t to)
{


  NS_LOG_DEBUG("Moving subflow " << subflow << " from " << containerNames[from] << " to " << containerNames[to]);

  SubflowList::iterator it = std::find(m_subflows[from].begin(),m_subflows[from].end(), subflow );
  NS_ASSERT(it != m_subflows[from].end() ); //! the subflow must exist
  m_subflows[to].push_back(*it);

  //! TODO it should call the meta
  //! SetSendCallback (Callback<void, Ptr<Socket>, uint32_t> sendCb)
//  subflow->SetSendCallback();

  m_subflows[from].erase(it);
}

void
MpTcpSocketBase::OnSubflowEstablishment(Ptr<MpTcpSubFlow> subflow)
{
  NS_LOG_FUNCTION(this << subflow);
  //Ptr<MpTcpSubFlow> subflow = DynamicCast<MpTcpSubFlow>(sock);

  NS_ASSERT_MSG(subflow,"Contact ns3 team");
  if(subflow->IsMaster())
  {
    //<< (m_server) ? "server" : "client"
    NS_LOG_INFO("Master subflow established, moving meta(server:" << m_server << ") from " << TcpStateName[m_state] << "to ESTABLISHED state");
    m_state = ESTABLISHED;


    // TODO relay connection establishement to sthg else ?
    // TODO  should move
    // NS_LOG_INFO("Moving from temporary to active");
    // will set m_connected to true;
//    NotifyNewConnectionCreated

    // TODO move that to the SYN_RCVD
    if(! m_server)
    {
      // If client
      NS_LOG_DEBUG("I am client, am I ?");
      Simulator::ScheduleNow(&MpTcpSocketBase::ConnectionSucceeded, this);
    }
  }



  //[subflow->m_positionInVector] = ;
  MoveSubflow(subflow, Others, Established);

  // For now, there is no subflow deletion so this should be good enough, else it will crash
  std::stringstream os;
  os << m_tracePrefix << "subflow" <<  m_subflows[Established].size();
  //
  subflow->SetupMetaTracing(os.str());

  // TODO setup callbacks


  // In all cases we should move the subflow from
  //Ptr<Socket> sock
}


void
MpTcpSocketBase::SetupMetaTracing(std::string prefix)
{
//  f.open(filename, std::ofstream::out | std::ofstream::trunc);
  m_tracePrefix = prefix + "/";

  prefix = m_tracePrefix + "/meta";
  AsciiTraceHelper asciiTraceHelper;
  Ptr<OutputStreamWrapper> streamNextTx = asciiTraceHelper.CreateFileStream (prefix+"_nextTx.csv");
  Ptr<OutputStreamWrapper> streamHighest = asciiTraceHelper.CreateFileStream (prefix+"_highest.csv");
  Ptr<OutputStreamWrapper> streamRxAvailable = asciiTraceHelper.CreateFileStream (prefix+"_RxAvailable.csv");
  Ptr<OutputStreamWrapper> streamRxTotal = asciiTraceHelper.CreateFileStream (prefix+"_RxTotal.csv");
  Ptr<OutputStreamWrapper> streamTx = asciiTraceHelper.CreateFileStream (prefix+"_Tx.csv");
  Ptr<OutputStreamWrapper> streamStates = asciiTraceHelper.CreateFileStream (prefix+"_states.csv");
  Ptr<OutputStreamWrapper> streamCwnd = asciiTraceHelper.CreateFileStream (prefix+"_cwin.csv");

  *streamNextTx->GetStream() << "Time,oldNextTxSequence,newNextTxSequence\n";
  *streamHighest->GetStream() << "Time,oldHighestSequence,newHighestSequence\n";
  *streamRxAvailable->GetStream() << "Time,oldRxAvailable,newRxAvailable\n";
  *streamRxTotal->GetStream() << "Time,oldRxTotal,newRxTotal\n";
  *streamTx->GetStream() << "Time,oldTx,newTx\n";
  *streamCwnd->GetStream() << "Time,oldCwnd,newCwnd\n";
  *streamStates->GetStream() << "Time,oldState,newState\n";

//  , HighestSequence, RWND\n";

//  NS_ASSERT(f.is_open());

  // TODO je devrais etre capable de voir les CongestionWindow + tailles de buffer/ Out of order
//  CongestionWindow
  Ptr<MpTcpSocketBase> sock(this);
  sock->TraceConnect ("NextTxSequence", "NextTxSequence", MakeBoundCallback(&dumpNextTxSequence, streamNextTx) );
  sock->TraceConnect ("HighestSequence", "HighestSequence", MakeBoundCallback(&dumpNextTxSequence, streamHighest) );
  sock->TraceConnect ("CongestionWindow", "CongestionWindow", MakeBoundCallback(&dumpUint32, streamCwnd) );
  sock->TraceConnect ("State", "State", MakeBoundCallback(&dumpTcpState, streamStates) );

//  Ptr<MpTcpSocketBase> sock2 = DynamicCast<MpTcpSocketBase>(sock);
  sock->m_rxBuffer.TraceConnect ("RxTotal", "RxTotal", MakeBoundCallback(&dumpNextTxSequence, streamRxTotal) );
  sock->m_rxBuffer.TraceConnect ("RxAvailable", "RxAvailable", MakeBoundCallback(&dumpNextTxSequence, streamRxAvailable) );
  sock->m_txBuffer.TraceConnect ("UnackSequence", "UnackSequence", MakeBoundCallback(&dumpNextTxSequence, streamTx) );
//  sock->TraceConnect ("RWND", "RWND", MakeBoundCallback(&dumpUint32), stream);
}


void
MpTcpSocketBase::OnSubflowClosing(Ptr<MpTcpSubFlow> sf)
{
  NS_LOG_LOGIC("Subflow has gone into state [" << TcpStateName[sf->m_state] );


  /* if this is the last active subflow

  */
  //FIN_WAIT_1
  switch( sf->m_state)
  {
    case FIN_WAIT_1:
    case CLOSE_WAIT:
    case LAST_ACK:
    default:
      break;
  };


  MoveSubflow(sf,Established,Closing);
  //      #TODO I need to Ack the DataFin in (DoPeerCLose)
}


void
MpTcpSocketBase::OnSubflowDupack(Ptr<MpTcpSubFlow> sf, MpTcpMapping mapping)
{
  NS_LOG_LOGIC("Subflow Dupack TODO");
}

void
MpTcpSocketBase::OnSubflowRetransmit(Ptr<MpTcpSubFlow> sf)
{
  NS_LOG_LOGIC("Subflow retransmit");
}


// renvoie m_highTxMark.Get() - m_txBuffer.HeadSequence(); should be ok even
// if bytes may not really be in flight but rather in subflows buffer
uint32_t
MpTcpSocketBase::BytesInFlight()
{
  NS_LOG_FUNCTION(this);
  return TcpSocketBase::BytesInFlight();

  #if 0
  uint32_t total = 0;

  for( SubflowList::const_iterator it = m_subflows[Established].begin(); it != m_subflows[Established].end(); it++ )
  {
    total += (*it)->BytesInFlight();
  }
  #endif
}

//uint32_t
//TcpSocketBase::UnAckDataCount()
// TODO buggy ?
uint16_t
MpTcpSocketBase::AdvertisedWindowSize()
{
  NS_LOG_FUNCTION(this);
  return TcpSocketBase::AdvertisedWindowSize();
//  NS_LOG_DEBUG("Advertised Window size of " << value );
//  return value;
}

uint32_t
MpTcpSocketBase::Window()
{
  NS_LOG_FUNCTION (this);

  //std::min, m_cWnd.Get() )
  uint32_t totalcWnd = CalculateTotalCWND();
    NS_LOG_LOGIC("remoteWin " << m_rWnd.Get() << ", totalCongWin:" << totalcWnd);
//  return std::min(m_rWnd.Get(), totalcWnd);
  return m_rWnd.Get();
}


uint32_t
MpTcpSocketBase::AvailableWindow()
{
  NS_LOG_FUNCTION (this);
  uint32_t unack = UnAckDataCount(); // Number of outstanding bytes
  uint32_t win = Window(); // Number of bytes allowed to be outstanding
  NS_LOG_LOGIC ("UnAckCount=" << unack << ", Win=" << win);
  return (win < unack) ? 0 : (win - unack);
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
      NS_LOG_WARN(": ("<< (int)sFlowIdx <<") -> " << freeCWND << " => 0" << " MSS: " << sFlow->GetSegSize() );
      return 0;
    }
  else
    {
      NS_LOG_WARN(": ("<< (int)sFlowIdx <<") -> " << freeCWND );
      return freeCWND;
    }
}
#endif

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
      NS_LOG_WARN ("DupAck-> FastRecovery. Increase cwnd by one MSS, from " << cwnd <<" -> " << sFlow->cwnd << " : " << (sFlowIdx));

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



void
MpTcpSocketBase::ClosingOnEmpty(TcpHeader& header)
{
  /* TODO the question is: is that ever called ?
  */
  NS_LOG_INFO("closing on empty called");
  //      GenerateEmptyPacketHeader(header);
// sets the datafin
//    header.SetFlags( header.GetFlags() | TcpHeader::FIN);
//    // flags |= TcpHeader::FIN;
//    if (m_state == ESTABLISHED)
//    { // On active close: I am the first one to send FIN
//      NS_LOG_INFO ("ESTABLISHED -> FIN_WAIT_1");
//      m_state = FIN_WAIT_1;
//      // TODO get DSS, if none
//      Ptr<TcpOptionMpTcpDSS> dss;
//
//      //! TODO add GetOrCreate member
//      if(!GetMpTcpOption(header, dss))
//      {
//        // !
//        dss = Create<TcpOptionMpTcpDSS>();
//
//      }
//      dss->SetDataFin(true);
//      header.AppendOption(dss);
//
//    }
//    else if (m_state == CLOSE_WAIT)
//    { // On passive close: Peer sent me FIN already
//      NS_LOG_INFO ("CLOSE_WAIT -> LAST_ACK");
//      m_state = LAST_ACK;
//    }
}


/** Inherit from Socket class: Kill this socket and signal the peer (if any) */
int
MpTcpSocketBase::Close(void)
{
  NS_LOG_FUNCTION (this);
  // First we check to see if there is any unread rx data
  // Bug number 426 claims we should send reset in this case.
// TODO reestablish ?
  if (m_rxBuffer.Size() != 0)
  {
    NS_FATAL_ERROR("TODO rxbuffer != 0");
      SendRST();
      return 0;
  }

  uint32_t remainingData = m_txBuffer.SizeFromSequence(m_nextTxSequence);


  NS_LOG_UNCOND("Call to close: Remaining data =" << remainingData );

  if (remainingData > 0)
  {

    // App close with pending data must wait until all data transmitted
    if (m_closeOnEmpty == false)
    {
      m_closeOnEmpty = true;
      NS_LOG_INFO ("Socket " << this << " deferring close, state " << TcpStateName[m_state]);
    }
    return 0;
  }




  //!
  return DoClose();
}

void
MpTcpSocketBase::CloseAllSubflows()
{
  NS_LOG_FUNCTION(this << "Closing all subflows");
  NS_ASSERT( m_state == FIN_WAIT_2 || m_state == CLOSING || m_state == CLOSE_WAIT);

  for(int i = 0; i < Closing; ++i) {
//    Established
    NS_LOG_INFO("Closing all subflows in state " << containerNames [i]);
    for( SubflowList::const_iterator it = m_subflows[i].begin(); it != m_subflows[i].end(); it++ )
    {
        Ptr<MpTcpSubFlow> sf = *it;
        sf->Close();
    }
  }
}


void
MpTcpSocketBase::ProcessDSSEstablished( Ptr<TcpOptionMpTcpDSS> dss, Ptr<MpTcpSubFlow> sf)
{
  NS_LOG_FUNCTION (this << dss << " from " << sf);

//  #if 0
//  uint32_t ack = (tcpHeader.GetAckNumber()).GetValue();
//  uint32_t tmp = ((ack - initialSeqNb) / m_segmentSize) % mod;
//  ACK.push_back(std::make_pair(Simulator::Now().GetSeconds(), tmp));
  if ( dss->GetFlags() & TcpOptionMpTcpDSS::DataFin) {
    PeerClose( SequenceNumber32(dss->GetDataFinDSN()), sf);
  }


  // TOdO replace that

  if( dss->GetFlags() & TcpOptionMpTcpDSS::DataAckPresent) {

    SequenceNumber32 dack = SequenceNumber32(dss->GetDataAck());

    if (dack < m_txBuffer.HeadSequence())
      { // Case 1: Old ACK, ignored.
        NS_LOG_LOGIC ("Ignored ack " << dack  );
      }
    else if (dack  == m_txBuffer.HeadSequence())
      { // Case 2: Potentially a duplicated ACK
        if (dack  < m_nextTxSequence)
          {
            NS_LOG_LOGIC ("TODO Dupack of " << dack );
            // TODO add new prototpye ?
  //          DupAck(tcpHeader,
  //          ++m_dupAckCount);
          }
        // otherwise, the ACK is precisely equal to the nextTxSequence
        NS_ASSERT( dack  <= m_nextTxSequence);
      }
    else if (dack  > m_txBuffer.HeadSequence())
      { // Case 3: New ACK, reset m_dupAckCount and update m_txBuffer
        NS_LOG_LOGIC ("New DataAck [" << dack  << "]");
        NewAck( dack );
        m_dupAckCount = 0;
      }
    }

  //!
  if( (dss->GetFlags() & TcpOptionMpTcpDSS::DSNMappingPresent) && !dss->DataFinMappingOnly() ) {
    sf->AddPeerMapping(dss->GetMapping());
  }
}

/* process while in CLOSING */
void
MpTcpSocketBase::ProcessDSSClosing( Ptr<TcpOptionMpTcpDSS> dss, Ptr<MpTcpSubFlow> sf)
{
  NS_LOG_FUNCTION (this << dss << " from " << sf);


// CLOSING state means simultaneous close, i.e. no one is sending data to
      // anyone. If anything other than ACK is received, respond with a reset.
//  if(dss->GetFlags() & TcpOptionMpTcpDSS::DataFin) {
//    if()else
//    { // CLOSING state means simultaneous close, i.e. no one is sending data to
//      // anyone. If anything other than ACK is received, respond with a reset.
//      SendFastClose(sf);
//      CloseAndNotify();
//    }
//  }
  if(dss->GetFlags() & TcpOptionMpTcpDSS::DataAckPresent) {
    SequenceNumber32 dack(dss->GetDataAck());
    if ( dack == m_rxBuffer.NextRxSequence())
    { // This ACK corresponds to the FIN sent
      TimeWait();
      return;
    }
  }

// CLOSING state means simultaneous close, i.e. no one is sending data to
//      // anyone. If anything other than ACK is received, respond with a reset.
  SendFastClose(sf);
  CloseAndNotify();
}

/** when in m_closed fin_wait etc */
void
MpTcpSocketBase::ProcessDSSWait( Ptr<TcpOptionMpTcpDSS> dss, Ptr<MpTcpSubFlow> sf)
{
  NS_LOG_FUNCTION (this << dss << " from " << sf);

  if(dss->GetFlags() & TcpOptionMpTcpDSS::DataFin) {
    if(m_state == FIN_WAIT_1)
    {
      // TODO send
      PeerClose( SequenceNumber32(dss->GetDataFinDSN() ), sf);
//      TcpHeader header;
//      sf->GenerateEmptyPacketHeader(header,TcpHeader::ACK);
//      AppendDataAck(header);
//      sf->SendEmptyPacket(header);

//      NS_LOG_INFO("FIN_WAIT_1 -> CLOSING");
//      m_state = CLOSING;

    }
    else {

      SendFastClose(sf);
//      CloseAndNotify();
    }
  }

  // TODO I should check
  // m_txBuffer.SetHeadSequence(m_nextTxSequence)
  if(dss->GetFlags() & TcpOptionMpTcpDSS::DataAckPresent) {

    SequenceNumber32 dack(dss->GetDataAck() );

    if (dack == m_rxBuffer.NextRxSequence())
    { // This ACK corresponds to the DATA FIN sent
      NS_LOG_INFO("Ack corresponds to DFIN sent");
      if(m_state == FIN_WAIT_1) {
        NS_LOG_INFO(" FIN_WAIT_1 -> FIN_WAIT_2");
        m_state= FIN_WAIT_2;
        return;
      }
      // CLOSING or LAST_ACK
      else if(m_state == CLOSING || m_state == LAST_ACK){
        TimeWait();
        return;
      }
      else {
        NS_LOG_ERROR("dack=" << dack << " not equal to the one expected " << dack);
      }

    }
  }



}




/** Received a packet upon CLOSE_WAIT, FIN_WAIT_1, or FIN_WAIT_2 states */
void
MpTcpSocketBase::ProcessWait(Ptr<Packet> packet, const TcpHeader& tcpHeader)
{
  NS_LOG_FUNCTION (this << tcpHeader);

  NS_FATAL_ERROR("TO remove");

}


/** Peacefully close the socket by notifying the upper layer and deallocate end point */
//void
//MpTcpSocketBase::CloseAndNotify(void)
//{
//  NS_LOG_FUNCTION (this);
//
//  if (!m_closeNotified)
//    {
//      NotifyNormalClose();
//    }
//  if (m_state != TIME_WAIT)
//    {
//      DeallocateEndPoint();
//    }
//  m_closeNotified = true;
//  NS_LOG_INFO (TcpStateName[m_state] << " -> CLOSED");
//  CancelAllTimers();
//  m_state = CLOSED;
//
//}

/** Move TCP to Time_Wait state and schedule a transition to Closed state */
void
MpTcpSocketBase::TimeWait()
{
  NS_LOG_INFO (TcpStateName[m_state] << " -> TIME_WAIT");
//  TcpSocketBase::TimeWait();
  CloseAllSubflows();
  m_state = TIME_WAIT;
  CancelAllTimers();
//  // Move from TIME_WAIT to CLOSED after 2*MSL. Max segment lifetime is 2 min
//  // according to RFC793, p.28
  m_timewaitEvent = Simulator::Schedule(Seconds(2 * m_msl), &MpTcpSocketBase::CloseAndNotify, this);
}


/** Peacefully close the socket by notifying the upper layer and deallocate end point */
void
MpTcpSocketBase::CloseAndNotify(void)
{
  NS_LOG_FUNCTION (this);

  // TODO check the number of open subflows
  if (!m_closeNotified)
    {
      NotifyNormalClose();
    }
  if (m_state != TIME_WAIT)
    {
      DeallocateEndPoint();
    }
  m_closeNotified = true;
  NS_LOG_INFO (TcpStateName[m_state] << " -> CLOSED");
  CancelAllTimers();
  m_state = CLOSED;
//  GenerateCWND();
//  GenerateRTT();
  //GenerateSendvsACK();

}

/* Peer sent me a DATA FIN. Remember its sequence in rx buffer.
It means there won't be any mapping above that dataseq
*/

void
MpTcpSocketBase::PeerClose(Ptr<Packet> p, const TcpHeader& tcpHeader)
{
  NS_LOG_FUNCTION(this << " PEEER CLOSE CALLED !" << tcpHeader);

  NS_FATAL_ERROR("TO REMOVE");

//  Ptr<TcpOptionMpTcpDSS> dss;
//  NS_ASSERT_MSG( GetMpTcpOption(tcpHeader,dss), "If this function was called, it must be because a dss had been found" );
//  NS_ASSERT( dss->GetFlags() & TcpOptionMpTcpDSS::DataFin);
//
//  /* */
//  SequenceNumber32 dsn = SequenceNumber32 (dss->GetDataFinDSN() );
//  if( dsn < m_rxBuffer.NextRxSequence() || m_rxBuffer.MaxRxSequence() < dsn) {
//      //!
//    NS_LOG_INFO("dsn " << dsn << " out of expected range [ " << m_rxBuffer.NextRxSequence()  << " - " << m_rxBuffer.MaxRxSequence() << " ]" );
//    return ;
//  }
//  /*
// Notably, it is only DATA_ACKed once all
//   data has been successfully received at the connection level.  Note,
//   therefore, that a DATA_FIN is decoupled from a subflow FIN.  It is
//   only permissible to combine these signals on one subflow if there is
//   no data outstanding on other subflows. */
//
//  // Copier/coller de
//
//  // Ignore all out of range packets
////  if (tcpHeader.GetSequenceNumber() < m_rxBuffer.NextRxSequence() || tcpHeader.GetSequenceNumber() > m_rxBuffer.MaxRxSequence())
////    {
////      return;
////    }
//
//  // For any case, remember the FIN position in rx buffer first
//  //! +1 because the datafin doesn't count as payload
//  // TODO rename mapping into GetDataMapping
//  NS_LOG_LOGIC("Setting FIN sequence to " << dss->GetMapping().TailDSN());
//  m_rxBuffer.SetFinSequence(
//                            dss->GetMapping().TailDSN()
//                            );
//
//  // Return if FIN is out of sequence, otherwise move to CLOSE_WAIT state by DoPeerClose
//  if (!m_rxBuffer.Finished())
//  {
//    NS_LOG_WARN("Out of range");
//    return;
//  }
//
//  // For any case, remember the FIN position in rx buffer first
////  #error TODO
//
//
//
//
//  NS_LOG_LOGIC ("Accepted DATA FIN at seq " << tcpHeader.GetSequenceNumber () + SequenceNumber32 (p->GetSize ()));
//
////  NS_LOG_LOGIC ("State " << m_state );
////  m_state == FIN_WAIT_1;
//
//  // Simultaneous close: Application invoked Close() when we are processing this FIN packet
//  if (m_state == FIN_WAIT_1)
//    {
//      NS_LOG_INFO ("FIN_WAIT_1 -> CLOSING");
//      m_state = CLOSING;
//
//      // TODO should send dataACK
//      TcpHeader header;
//      AppendDataAck(header);
//      GenerateEmptyPacketHeader(header,TcpHeader::ACK);
//      //!
//      GetSubflow(0)->SendEmptyPacket(header);
//      return;
//    }
//  DoPeerClose();
}

/** Received a in-sequence FIN. Close down this socket. */
// FIN is in sequence, notify app and respond with a FIN
void
MpTcpSocketBase::DoPeerClose(void)
{
  NS_FATAL_ERROR("To remove");
//  NS_ASSERT(m_state == ESTABLISHED || m_state == SYN_RCVD);

  // Move the state to CLOSE_WAIT
  NS_LOG_INFO (TcpStateName[m_state] << " -> CLOSE_WAIT");
  m_state = CLOSE_WAIT;

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
  if (m_shutdownSend)
    { // The application declares that it would not sent any more, close this socket
      Close();
    }
    else
    { // Need to ack, the application will close later
//    #error TODO send Dataack
      TcpHeader header;
      AppendDataAck(header);
      GenerateEmptyPacketHeader(header,TcpHeader::ACK);
      //!

      GetSubflow(0)->SendEmptyPacket(header);
    }

  if (m_state == LAST_ACK)
  {
      NS_LOG_LOGIC ("TcpSocketBase " << this << " scheduling Last Ack timeout 01 (LATO1)");
      NS_FATAL_ERROR("TODO");
//      m_lastAckEvent = Simulator::Schedule(m_rtt->RetransmitTimeout(), &TcpSocketBase::LastAckTimeout, this);
    }
}

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





// TODO this could be reimplemented via choosing
void
MpTcpSocketBase::SendEmptyPacket(TcpHeader& header)
{
  NS_FATAL_ERROR("Disabled. Should call subflow member");
}

void
MpTcpSocketBase::AppendDataFin(TcpHeader& header) const
//const
{

  Ptr<TcpOptionMpTcpDSS> dss;
  GetOrCreateMpTcpOption(header,dss);
//  if(!GetMpTcpOption(header,dss))
//    dss = Create<>(TcpOptionMpTcpMain::MP_DSS);

  dss->EnableDataFin( m_txBuffer.TailSequence() );
}


/** Do the action to close the socket. Usually send a packet with appropriate
 flags depended on the current m_state. */

int
MpTcpSocketBase::DoClose()
{
  NS_LOG_FUNCTION(this);

  // TODO close all subflows
  // TODO send a data fin
  TcpHeader header;
  Ptr<MpTcpSubFlow> subflow = GetSubflow(0);


  switch (m_state)
  {
  case SYN_RCVD:
  case ESTABLISHED:
// send FIN to close the peer
//
      subflow->GenerateEmptyPacketHeader(header,TcpHeader::ACK);
//      SendEmptyPacket(header);
      AppendDataFin(header);
      subflow->SendEmptyPacket(header);
      NS_LOG_INFO ("ESTABLISHED -> FIN_WAIT_1");
      m_state = FIN_WAIT_1;
      break;

  case CLOSE_WAIT:
// send ACK to close the peer
      subflow->GenerateEmptyPacketHeader(header, TcpHeader::ACK);
      AppendDataAck(header);
      subflow->SendEmptyPacket(header);
//      SendEmptyPacket(TcpHeader::FIN | TcpHeader::ACK);
      NS_LOG_INFO ("CLOSE_WAIT -> LAST_ACK");
      m_state = LAST_ACK;

      break;

  case SYN_SENT:
  case CLOSING:
// Send RST if application closes in SYN_SENT and CLOSING
// TODO deallocate all childrne
      NS_LOG_INFO("trying to close while closing..");
//      NS_LOG_INFO ("CLOSING -> LAST_ACK");
//      m_state = TIME_WAIT;
        NotifyErrorClose();
      DeallocateEndPoint();
//      SendRST();
//      CloseAndNotify();
//      break;
  case LISTEN:
  case LAST_ACK:
//      CloseAllSubflows();
// In these three states, move to CLOSED and tear down the end point
      CloseAndNotify();

      break;
  case CLOSED:
  case FIN_WAIT_1:
  case FIN_WAIT_2:
  case TIME_WAIT:
  default: /* mute compiler */
// Do nothing in these four states
      break;
  }
  return 0;
}




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
should be straightforward
TODO remove
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


Ptr<Packet>
MpTcpSocketBase::Recv(uint32_t maxSize, uint32_t flags)
{
  NS_LOG_FUNCTION(this);
  return TcpSocketBase::Recv(maxSize,flags);
  // TODO here I could choose to discard mappings
}



uint32_t
MpTcpSocketBase::GetTxAvailable(void) const
{
  NS_LOG_FUNCTION (this);
  uint32_t value = m_txBuffer.Available();
  NS_LOG_DEBUG("Tx available " << value);
  return value;
}

//this would not accomodate with google option that proposes to add payload in
// syn packets MPTCP
/**
This function should be overridable since it may depend on the CC, cf RFC:

   To compute cwnd_total, it is an easy mistake to sum up cwnd_i across
   all subflows: when a flow is in fast retransmit, its cwnd is
   typically inflated and no longer represents the real congestion
   window.  The correct behavior is to use the ssthresh (slow start
   threshold) value for flows in fast retransmit when computing
   cwnd_total.  To cater to connections that are app limited, the
   computation should consider the minimum between flight_size_i and
   cwnd_i, and flight_size_i and ssthresh_i, where appropriate.
**/
uint32_t
MpTcpSocketBase::CalculateTotalCWND()
{
  uint32_t totalCwnd = 0;
  for (uint32_t i = 0; i < GetNActiveSubflows(); i++)
    {
      Ptr<MpTcpSubFlow> sf = m_subflows[Established][i];

      // fast recovery
      if ( sf->m_inFastRec)
        totalCwnd += sf->GetSSThresh();
      else
        totalCwnd += sf->m_cWnd.Get();          // Should be this all the time ?!
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



/** Kill this socket. This is a callback function configured to m_endpoint in
 SetupCallback(), invoked when the endpoint is destroyed. */
void
MpTcpSocketBase::Destroy(void)
{
  NS_LOG_FUNCTION(this);NS_LOG_INFO("Enter Destroy(" << this << ") m_sockets:  " << m_tcp->m_sockets.size()<< ")");
  m_endPoint = 0;
  // TODO loop through subflows and Destroy them too ?
//  if (m_tcp != 0)
//    {
//      std::vector<Ptr<TcpSocketBase> >::iterator it = std::find(m_tcp->m_sockets.begin(), m_tcp->m_sockets.end(), this);
//      if (it != m_tcp->m_sockets.end())
//        {
//          m_tcp->m_sockets.erase(it);
//        }
//    }
//  CancelAllSubflowTimers();
  NS_LOG_INFO("Leave Destroy(" << this << ") m_sockets:  " << m_tcp->m_sockets.size()<< ")");
}


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



}  //namespace ns3
