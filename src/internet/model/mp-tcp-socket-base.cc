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
#include "ns3/mp-tcp-subflow.h"
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
dumpSequence32(Ptr<OutputStreamWrapper> stream, std::string context, SequenceNumber32 oldSeq, SequenceNumber32 newSeq)
{
  //<< context <<
//  if (context == "NextTxSequence")

  *stream->GetStream() << Simulator::Now()
                       << "," << oldSeq
                       << "," << newSeq
                       << std::endl;
}


void
dumpUint32(Ptr<OutputStreamWrapper> stream, std::string context, uint32_t oldVal, uint32_t newVal) {

//  NS_LOG_UNCOND("Context " << context << "oldVal=" << oldVal << "newVal=" << newVal);

  *stream->GetStream() << Simulator::Now()
                       << "," << oldVal
                       << "," << newVal
                       << std::endl;
}


void
dumpTcpState(Ptr<OutputStreamWrapper> stream, std::string context, TcpStates_t oldVal, TcpStates_t newVal) {
  // TODO rely
  *stream->GetStream() << Simulator::Now()
                      << "," << TcpSocket::TcpStateName[oldVal]
                      << "," << TcpSocket::TcpStateName[newVal]
                      << std::endl;
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


static const std::string containerNames[MpTcpSocketBase::Maximum] = {
  "Established",
  "Others",
  "Closing"
//  ,
//  "Maximum"

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
  m_initialCWnd(10), // TODO reset to 1
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



MpTcpSocketBase::SubflowList::size_type
MpTcpSocketBase::GetNActiveSubflows() const
{
  return m_subflows[Established].size();
}

  //std::vector<MpTcpSubflow>::size_ uint8
Ptr<MpTcpSubflow>
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

  //! TODO Set in TcpSocketBase an attribute to enable idsn random
  // motivation is that it's clearer to plot from 0
  if(m_nullIsn) {
    idsn = 0;

  }
  // + 1 ?
  m_rxBuffer.SetNextRxSequence(SequenceNumber32( (uint32_t)idsn ));
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
  Ptr<MpTcpSubflow> sFlow = CreateSubflow(true);

  ComputeTotalCWND();

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



  Simulator::ScheduleNow(&MpTcpSubflow::CompleteFork, sFlow, p, mptcpHeader, fromAddress, toAddress);

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
//      Ptr<MpTcpSubflow> sFlow = m_subflows[i];
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


//  NS_ASSERT( (dss->GetFlags() & TcpOptionMpTcpDSS::DataAckPresent) == 0);

//   = CreateObject<TcpOptionMpTcpDSS>();
  uint32_t dack = m_rxBuffer.NextRxSequence().GetValue();
  dss->SetDataAck( dack );

  // TODO check the option is not in the header already
//  NS_ASSERT_MSG( hdr.GetOption()GetOp)


}


/*
A receiver MUST NOT shrink the right edge of the receive window (i.e.,
DATA_ACK + receive window)
   */
void
MpTcpSocketBase::SetRemoteWindow(uint32_t win_size)
{
  //No checks are done here
  NS_LOG_FUNCTION(" Updating remote window. New m_rWnd=" << win_size );
  m_rWnd = win_size;

  // Go through all containers
  for(int i = 0; i < Maximum; ++i) {

//    Established
//    NS_LOG_INFO("Closing all subflows in state [" << containerNames [i] << "]");
    for( SubflowList::const_iterator it = m_subflows[i].begin(); it != m_subflows[i].end(); it++ )
    {

      (*it)->m_rWnd = m_rWnd;

    }

  }

}


// TODO rename into DSS

void
MpTcpSocketBase::ProcessMpTcpOptions(TcpHeader header, Ptr<MpTcpSubflow> sf)
{
  NS_LOG_FUNCTION(this);
  TcpHeader::TcpOptionList l;
  header.GetOptions(l);
  for(TcpHeader::TcpOptionList::const_iterator it = l.begin(); it != l.end(); ++it)
  {
    if( (*it)->GetKind() == TcpOption::MPTCP)
    {
      Ptr<TcpOptionMpTcpMain> opt = DynamicCast<TcpOptionMpTcpMain>(*it);
      NS_ASSERT(opt);
//      T temp;
      switch(opt->GetSubType()) {
        //!
        case TcpOptionMpTcpMain::MP_CAPABLE:
        case TcpOptionMpTcpMain::MP_JOIN:
            // Handled at subflow level
//            NS_LOG_DEBUG("Handled at subflow level");
            break;
        case TcpOptionMpTcpMain::MP_DSS:
          {
            Ptr<TcpOptionMpTcpDSS> dss = DynamicCast<TcpOptionMpTcpDSS>(opt);
            ProcessDSS(header,dss,sf);
          }
            break;

        // TODO redirect options to mptcp id manager
        case TcpOptionMpTcpMain::MP_ADD_ADDR:
        case TcpOptionMpTcpMain::MP_REMOVE_ADDR:
        case TcpOptionMpTcpMain::MP_PRIO:
        case TcpOptionMpTcpMain::MP_FAIL:
        case TcpOptionMpTcpMain::MP_FASTCLOSE:
          NS_LOG_WARN("Unsupported option yet");
          break;
      }

//      == temp.GetSubType()  )
//      {
//        //!
//        ret = DynamicCast<T>(opt);
//        return true;
//      }
    }
  }

}


/*
Quote from rfc 6824:
    Because of this, an implementation MUST NOT use the RCV.WND
    field of a TCP segment at the connection level if it does not also
    carry a DSS option with a Data ACK field

    and in not established mode ?
    TODO
*/
void
MpTcpSocketBase::ProcessDSS(const TcpHeader& tcpHeader, Ptr<TcpOptionMpTcpDSS> dss
                             , Ptr<MpTcpSubflow> sf
                             )
{
  NS_LOG_FUNCTION ( this << "Received ack " << dss << " from subflow " << sf);

  // might be suboptimal but should make sure it gets properly updated
//  m_cWnd = ComputeTotalCWND();
//  SequenceNumber32 dfin;
//  SequenceNumber32 dack;


  // TODO maybe this should be done within an processMPTCPoption, more global. For instance during 3WHS
  /*Because of this, an implementation MUST NOT use the RCV.WND
  field of a TCP segment at the connection level if it does not also
  carry a DSS option with a Data ACK field*/
  if(dss->GetFlags() & TcpOptionMpTcpDSS::DataAckPresent)
  {

    /*
    The receive window is relative to the DATA_ACK.  As in TCP, a
    receiver MUST NOT shrink the right edge of the receive window (i.e.,
    DATA_ACK + receive window).  The receiver will use the data sequence
    number to tell if a packet should be accepted at the connection
    level.

    TODO use, OutOfRange or IsInWindow ?
    */
    if( dss->GetDataAck() + tcpHeader.GetWindowSize() >= m_rxBuffer.NextRxSequence().GetValue() + RemoteWindow())
    {
      // TODO update all r_wnd of subflows
      NS_LOG_LOGIC("Updating receive window");
      SetRemoteWindow(tcpHeader.GetWindowSize());
    }
    else {
//      NS_LOG_DEBUG("Not advancing window");
    }





  }





//  #if 0
  switch(m_state) {

    case ESTABLISHED:
      ProcessDSSEstablished(tcpHeader, dss, sf);
      break;

    case LAST_ACK:
    case CLOSING:
//      ProcessDSSClosing(dss,sf);
//      break;
    case FIN_WAIT_1:
    case FIN_WAIT_2:
    case CLOSE_WAIT:

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
      NS_LOG_ERROR("Unhandled case" << TcpStateName[m_state]);
      break;
  };
//  #endif
  // If there is any data piggybacked, store it into m_rxBuffer
//  if (packet->GetSize() > 0)
//    {
//      ReceivedData(packet, tcpHeader);
//    }
//  #endif

}


void
MpTcpSocketBase::DupAck( SequenceNumber32 ack,Ptr<MpTcpSubflow> sf)
{
  //!
  NS_LOG_ERROR("Duplicate ACK, TODO");
  /*
  As discussed earlier, however, an MPTCP
   implementation MUST NOT treat duplicate ACKs with any MPTCP option,
   with the exception of the DSS option, as indications of congestion

  and an MPTCP implementation SHOULD NOT send more than two
   duplicate ACKs
   */
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


//void
//MpTcpSocketBase::OnSubflowReset( Ptr<MpTcpSubflow> sf)
//{
//
//}

void
MpTcpSocketBase::OnSubflowClosed(Ptr<MpTcpSubflow> subflow, bool reset)
{
  NS_LOG_LOGIC("Subflow " << subflow  << "definitely closed");
  //! TODO it should remove itself from the list of subflows and when 0 are active
  // it should call CloseAndNotify ?
  if(reset) {
    NS_FATAL_ERROR("Case not handled yet.");
  }

//  SubflowList::iterator it = std::find(m_subflows[Closing].begin(), m_subflows[Closing].end(), subflow);
// m_containers[Closing].erase(it);
//NS_ASSERT(it != m_subflows[Closing].end());
  SubflowList::iterator it = std::remove(m_subflows[Closing].begin(), m_subflows[Closing].end(), subflow);


}



//Ptr<Socket> sock
//SequenceNumber32 dataSeq,
/**
TODO the decision to ack is unclear with this structure.
May return a bool to let subflow know if it should return a ack ?
it would leave the possibility for meta to send ack on another subflow

We have to extract data from subflows on a per mapping basis because mappings
may not necessarily be contiguous
**/
void
MpTcpSocketBase::OnSubflowRecv(Ptr<MpTcpSubflow> sf)
{
  NS_LOG_FUNCTION(this << "Received data from subflow=" << sf);

//  NS_ASSERT(IsConnected());

  SequenceNumber32 expectedDSN = m_rxBuffer.NextRxSequence();

  /* Extract one by one mappings from subflow */
  while(true) {

    Ptr<Packet> p;
    SequenceNumber32 dsn;
    uint32_t canRead = m_rxBuffer.MaxBufferSize() - m_rxBuffer.Size();

    if(canRead <= 0) {
      NS_LOG_LOGIC("No free space in meta Rx Buffer");
      break;
    }

    /* Todo tell if we stop to extract only between mapping boundaries or if
    Extract
    */
    p = sf->ExtractAtMostOneMapping(canRead, false, dsn);

    if (p->GetSize() == 0)
    {
      NS_LOG_DEBUG("packet extracted empty.");
      break;
    }

    // THIS MUST WORK. else we removed the data from subflow buffer so it would be lost
    // Pb here, htis will be extracted but will not be saved into the main buffer
    // TODO use an assert instead
//    NS_LOG_INFO( "Meta  << "next Rx" << m_rxBuffer.NextRxSequence() );
    // Notify app to receive if necessary
    NS_LOG_DEBUG( "Before adding to metaRx: RxBufferHead=" << m_rxBuffer.HeadSequence() << " NextRxSequence=" << m_rxBuffer.NextRxSequence());

    if(!m_rxBuffer.Add(p, dsn)) {
      NS_LOG_WARN("Data might have been lost");
    }
//    NS_ASSERT_MSG(m_rxBuffer.Add(p, dsn), "Data got LOST");
//    NS_ASSERT_MSG(m_rxBuffer.Add(p, dsn), "Data got LOST");
    NS_LOG_DEBUG( "After adding to metaRx: RxBufferHead=" << m_rxBuffer.HeadSequence() << " NextRxSequence=" << m_rxBuffer.NextRxSequence());
  }

  // TODO should restablish delayed acks ?


  if (expectedDSN < m_rxBuffer.NextRxSequence())
    {
      NS_LOG_LOGIC("The Rxbuffer advanced");

      // NextRxSeq advanced, we have something to send to the app
      if (!m_shutdownRecv)
        {
          //<< m_receivedData
          NS_LOG_LOGIC("Notify data Rcvd" );
          NotifyDataRecv();

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

/**
TODO check that it autodisconnects when we destroy the object ?
**/
void
MpTcpSocketBase::OnSubflowNewCwnd(std::string context, uint32_t oldCwnd, uint32_t newCwnd)
{
  NS_LOG_LOGIC("Subflow updated window from " << oldCwnd << " to " << newCwnd
//        << " (context=" << context << ")"
        );

  //
  m_cWnd = ComputeTotalCWND();
}

/*
TODO it should block subflow creation until it received a DSS on a new subflow
TODO rename ? CreateAndAdd? Add ? Start ? Initiate
*/
Ptr<MpTcpSubflow>
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
    /*
    Before allowing more subflows, we need to check if we already received a DSS ! (cf standard)

    */
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
    return 0;
//    return 0;
  }
  else if(m_state == TIME_WAIT || m_state == CLOSE_WAIT || m_state == CLOSING)
  {
    NS_LOG_ERROR("Not allowed to  create new subflow ");
    return 0;
  }

  Ptr<Socket> sock = m_tcp->CreateSocket(GetMpTcpSubflowTypeId());

  Ptr<MpTcpSubflow> sFlow = DynamicCast<MpTcpSubflow>(sock);
  // So that we know when the connection gets established
  //sFlow->SetConnectCallback( MakeCallback (&MpTcpSocketBase::OnSubflowEstablishment, Ptr<MpTcpSocketBase>(this) ) );
  sFlow->SetMeta(this);
  sFlow->m_masterSocket = masterSocket; // TODO Maybe useless . remove ?


  /**
  We need to update MPTCP level cwin every time a subflow window is updated,
  thus we resort to the tracing system to track subflows cwin
  **/
  NS_ASSERT(sFlow->TraceConnect ("CongestionWindow", "CongestionWindow", MakeCallback(&MpTcpSocketBase::OnSubflowNewCwnd, this)));


  sFlow->SetInitialCwnd( GetInitialCwnd() );  //! Could be done maybe in SetMeta ?
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

      Ptr<MpTcpSubflow> sFlow = CreateSubflow(true);

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
  NS_FATAL_ERROR("TO REMOVE, use SendFastClose instead");
}

void
MpTcpSocketBase::SendFastClose(Ptr<MpTcpSubflow> sf)
{
  NS_LOG_LOGIC ("Sending MP_FASTCLOSE");
//  NS_FATAL_ERROR("TODO");
  // TODO: send an MPTCP_fail
   TcpHeader header;
//   Ptr<MpTcpSubflow> sf = GetSubflow(0);
  sf->GenerateEmptyPacketHeader(header,TcpHeader::RST);
  Ptr<TcpOptionMpTcpFastClose> opt = Create<TcpOptionMpTcpFastClose>();

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
      Ptr<MpTcpSubflow> sFlow = CreateSubflow(
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
   no data outstanding on other subflows.

  */
void
MpTcpSocketBase::PeerClose( SequenceNumber32 dsn, Ptr<MpTcpSubflow> sf)
{
  NS_LOG_LOGIC("Datafin with seq=" << dsn);


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
  NS_LOG_LOGIC ("Accepted MPTCP FIN at seq " << dsn);

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
      TimeWait();
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


//   DoPeerClose();
}

void
MpTcpSocketBase::OnInfiniteMapping(Ptr<TcpOptionMpTcpDSS> dss, Ptr<MpTcpSubflow> sf)
{
  NS_FATAL_ERROR("Infinite mapping not implemented");
}



/**
this function supposes that

**/
void
MpTcpSocketBase::OnSubflowNewAck(Ptr<MpTcpSubflow> subflow)
{
  NS_LOG_LOGIC("new subflow ack " );
//  SyncTxBuffers(subflow);
  SyncTxBuffers();
}


void
MpTcpSocketBase::SyncTxBuffers()
{
  NS_LOG_LOGIC("Syncing Tx buffer with all subflows");
  for(int i = 0; i < Maximum; ++i) {

//    Established
//    NS_LOG_INFO("Closing all subflows in state [" << containerNames [i] << "]");
    for( SubflowList::const_iterator it = m_subflows[i].begin(); it != m_subflows[i].end(); it++ )
    {

//      SubflowList::iterator it = std::find(m_subflows[i].begin(), m_subflows[i].end(), subflow);
//      NS_ASSERT(it != m_subflows[from].end() ); //! the subflow must exist
//      if(it != m_subflows[i].end()) {
      SyncTxBuffers(*it);
    }
  }




  // TODO I should go through all
  // TODO that should be triggered !!! it should ask the meta for data rather !
  if (GetTxAvailable() > 0)
    {
      NS_LOG_INFO("Tx available" << GetTxAvailable());
      NotifySend(GetTxAvailable());
    }



  // if no more data and socket closing
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
      // TODO maybe
//      if(m_state == FIN_WAIT_1 && m_txBuffer.Size() == 0 &&  (dsn == m_txBuffer.HeadSequence() + SequenceNumber32(1) ) ) {
      if(m_state == FIN_WAIT_1 && m_txBuffer.Size() == 0
      &&  (FirstUnackedSeq() ==  m_txBuffer.HeadSequence() + SequenceNumber32(1) ) ) {

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


      return;
    }
  // in case it freed some space in cwnd, try to send more data
  SendPendingData(m_connected);
}


// TODO maybe add a bool to ask for
//SequenceNumber32 const& ack,
void
MpTcpSocketBase::SyncTxBuffers(Ptr<MpTcpSubflow> subflow)
{

  NS_LOG_LOGIC("Syncing TxBuffer between meta and subflow " << subflow);

  while(true) {
//    SequenceNumber32 dack = 0;
    MpTcpMapping mapping;

    if(!subflow->DiscardAtMostOneTxMapping(FirstUnackedSeq(), mapping )) {
      NS_LOG_DEBUG("Nothing discarded");
      break;
    }

    /**
    returned mapping discarded because we don't support NR sack right now
    **/
    NS_LOG_DEBUG("subflow Tx mapping " << mapping << " discarded");
    m_txBuffer.DiscardUpTo( mapping.TailDSN());
  }
}


/**
TODO call 64bits  version ?
It should know from which subflow it comes from
TODO update the r_Wnd here


This is not really possible until we change the buffer system:
"The sender MUST keep data in its send buffer as long as the data has
not been acknowledged at both connection level and on all subflows on
which it has been sent."

TODO:
**/


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
      m_retxEvent = Simulator::Schedule(m_rto, &MpTcpSocketBase::ReTxTimeout, this);
    }

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
      " nbAckedBytes " << (dsn - FirstUnackedSeq())); // Number bytes ack'ed


  /**
  This is possible because packets were copied int osubflows buffers, and that there is no intent to
  reinject them on other paths
//  m_txBuffer.DiscardUpTo(dsn);
  TODO here I should
  **/
  m_firstTxUnack = dsn;

  SyncTxBuffers();

  // TODO wrong. what happens with NR-SACK ?
  if (dsn > m_nextTxSequence)
    {
      m_nextTxSequence = dsn; // If advanced
    }

  #if 0
  Following has been moved to SyncTxBuffers()
  // TODO I should go through all
  // TODO that should be triggered !!! it should ask the meta for data rather !
  if (GetTxAvailable() > 0)
    {
      NS_LOG_INFO("Tx available" << GetTxAvailable());
      NotifySend(GetTxAvailable());
    }

//  if (dsn > m_nextTxSequence)
//    {
//      m_nextTxSequence = dsn; // If advanced
//    }


  // m_txFueer
  // TODO move that elsewhere ?
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
      // TODO maybe
//      if(m_state == FIN_WAIT_1 && m_txBuffer.Size() == 0 &&  (dsn == m_txBuffer.HeadSequence() + SequenceNumber32(1) ) ) {
      if(m_state == FIN_WAIT_1 && m_txBuffer.Size() == 0 &&  (dsn == FirstUnackedSeq() + SequenceNumber32(1) ) ) {

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


      return;
    }
  // in case it freed some space in cwnd, try to send more data
  SendPendingData(m_connected);
  #endif
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


    Ptr<MpTcpSubflow> sf = GetSubflow(it->first);
    MpTcpMapping& mapping = it->second;
//    Retrieve data  Rename SendMappedData
    //SequenceNumber32 dataSeq = mappings[i].first;
    //uint16_t mappingSize = mappings[i].second;

    NS_LOG_DEBUG("Sending mapping "<< mapping << " on subflow #" << (int)it->first);

    //sf->AddMapping();
    Ptr<Packet> p = m_txBuffer.CopyFromSequence(mapping.GetLength(), mapping.HeadDSN());
    NS_ASSERT(p->GetSize() == mapping.GetLength());

    int ret = sf->SendMapping(p, mapping);


    if( ret < 0)
    {
      // TODO dump the mappings ?
      NS_FATAL_ERROR("Could not send mapping. The generated mappings");
    }

    // if successfully sent,
    nbMappingsDispatched++;

//    bool sentPacket =
    sf->SendPendingData();
//    NS_LOG_DEBUG("Packet sent ? boolean=s" << sentPacket );

  // TODO here update the m_nextTxSequence only if it is in order
      // Maybe the max is unneeded; I put it here
    if( mapping.HeadDSN() <= m_nextTxSequence && mapping.TailDSN() >= m_nextTxSequence) {
      m_nextTxSequence = mapping.TailDSN() + 1;
    }

    m_highTxMark = std::max( m_highTxMark.Get(), mapping.TailDSN());
//      m_nextTxSequence = std::max(m_nextTxSequence.Get(), mapping.TailDSN() + 1);
    NS_LOG_LOGIC("m_nextTxSequence=" << m_nextTxSequence << " m_highTxMark=" << m_highTxMark);
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
//  Ptr<MpTcpSubflow> sFlow = m_subflows[sFlowIdx];
//
//  NS_LOG_INFO ("Subflow ("<<(int)sFlowIdx<<") ReTxTimeout Expired at time "
//        << Simulator::Now ().GetSeconds()<< " unacked packets count is "<<sFlow->m_mapDSN.size()
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

void
MpTcpSocketBase::OnSubflowDupAck(Ptr<MpTcpSubflow> sf)
{
  NS_LOG_DEBUG("Dup ack signaled by subflow " << sf );

}


// TODO move that away a t'on besoin de passer le mapping ?
// OnRetransmit()
// OnLoss
#if 0
void
MpTcpSocketBase::ReduceCWND(uint8_t sFlowIdx)
{

  NS_ASSERT(m_algoCC);

//  Ptr<MpTcpSubflow> sFlow = m_subflows[sFlowIdx];
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

/**
Retransmit timeout

This function should be very interesting because one may
adopt different strategies here, like reinjecting on other subflows etc...
Maybe allow for a callback to be set here.
*/
void
MpTcpSocketBase::Retransmit()
{
  NS_LOG_FUNCTION (this);
  NS_FATAL_ERROR("TODO reestablish retransmit ?");
  NS_LOG_ERROR("TODO");

  TcpSocketBase::Retransmit();
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
//  Ptr<MpTcpSubflow> sFlow = m_subflows[sFlowIdx];
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
  if(m_nullIsn) {
    m_nextTxSequence = (uint32_t)idsn;
  }
  else {
    m_nextTxSequence = (uint32_t)0;
  }

  SetTxHead(m_nextTxSequence);
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
MpTcpSocketBase::MoveSubflow(Ptr<MpTcpSubflow> subflow, mptcp_container_t from, mptcp_container_t to)
{

  NS_LOG_DEBUG("Moving subflow " << subflow << " from " << containerNames[from] << " to " << containerNames[to]);
  NS_ASSERT(from != to);
  SubflowList::iterator it = std::find(m_subflows[from].begin(), m_subflows[from].end(), subflow);
  m_subflows[to].push_back(*it);
  m_subflows[from].erase(it);
}


/*
We shouldn't need the from container, it could be found
*/
void
MpTcpSocketBase::MoveSubflow(Ptr<MpTcpSubflow> subflow, mptcp_container_t to)
{


  NS_LOG_DEBUG("Moving subflow " << subflow << " to " << containerNames[to]);

  for(int i = 0; i < Maximum; ++i) {

//    Established
//    NS_LOG_INFO("Closing all subflows in state [" << containerNames [i] << "]");
//    for( SubflowList::const_iterator it = m_subflows[i].begin(); it != m_subflows[i].end(); it++ )
//    {

      SubflowList::iterator it = std::find(m_subflows[i].begin(), m_subflows[i].end(), subflow);
//      NS_ASSERT(it != m_subflows[from].end() ); //! the subflow must exist
      if(it != m_subflows[i].end()) {
          NS_LOG_DEBUG("Found sf in container [" << containerNames[i] << "]");
//          if( i == to) {
//            NS_LOG_WARN("destination container is same as source");
//            return;
//          }
          MoveSubflow(subflow, static_cast<mptcp_container_t>(i), to);
//          m_subflows[to].push_back(*it);
//          m_subflows[from].erase(it);
          return;
      }

  }

  NS_FATAL_ERROR("Subflow not found in any container");

  //! TODO it should call the meta
  //! SetSendCallback (Callback<void, Ptr<Socket>, uint32_t> sendCb)
//  subflow->SetSendCallback();


}

void
MpTcpSocketBase::OnSubflowEstablishment(Ptr<MpTcpSubflow> subflow)
{
  NS_LOG_LOGIC(this << "New subflow " <<subflow << " established");
  //Ptr<MpTcpSubflow> subflow = DynamicCast<MpTcpSubflow>(sock);

  NS_ASSERT_MSG(subflow,"Contact ns3 team");


  ComputeTotalCWND();

  if(subflow->IsMaster())
  {
    //<< (m_server) ? "server" : "client"
    NS_LOG_INFO("Master subflow established, moving meta(server:" << m_server << ") from " << TcpStateName[m_state] << " to ESTABLISHED state");
    m_state = ESTABLISHED;


    // TODO relay connection establishement to sthg else ?
    // TODO  should move
    // NS_LOG_INFO("Moving from temporary to active");
    // will set m_connected to true;
//    NotifyNewConnectionCreated
    SetRemoteWindow( subflow->m_rWnd );
    // TODO move that to the SYN_RCVD
    if(! m_server)
    {
      // If client
      NS_LOG_DEBUG("I am client, amn't I ?");
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



TypeId
MpTcpSocketBase::GetInstanceTypeId(void) const
{
  return MpTcpSocketBase::GetTypeId();
}

/**
TODO move that elsewhere, and plot the first line to get the initial value else it makes
for bad plots.
**/
void
SetupSocketTracing(Ptr<TcpSocketBase> sock, const std::string prefix)
{
  std::ios::openmode mode = std::ofstream::out | std::ofstream::trunc;

  AsciiTraceHelper asciiTraceHelper;
  Ptr<OutputStreamWrapper> streamTxNext = asciiTraceHelper.CreateFileStream (prefix+"_TxNext.csv", mode);
  Ptr<OutputStreamWrapper> streamTxHighest = asciiTraceHelper.CreateFileStream (prefix+"_TxHighest.csv", mode);
  Ptr<OutputStreamWrapper> streamRxAvailable = asciiTraceHelper.CreateFileStream (prefix+"_RxAvailable.csv", mode);
  Ptr<OutputStreamWrapper> streamRxTotal = asciiTraceHelper.CreateFileStream (prefix+"_RxTotal.csv", mode);
  Ptr<OutputStreamWrapper> streamRxNext = asciiTraceHelper.CreateFileStream (prefix+"_RxNext.csv", mode);
  Ptr<OutputStreamWrapper> streamTxUnack = asciiTraceHelper.CreateFileStream (prefix+"_TxUnack.csv", mode);
  Ptr<OutputStreamWrapper> streamStates = asciiTraceHelper.CreateFileStream (prefix+"_states.csv", mode);
  Ptr<OutputStreamWrapper> streamCwnd = asciiTraceHelper.CreateFileStream (prefix+"_cwnd.csv", mode);
  Ptr<OutputStreamWrapper> streamRwnd = asciiTraceHelper.CreateFileStream (prefix+"_rwnd.csv", mode);
  Ptr<OutputStreamWrapper> streamSSThreshold = asciiTraceHelper.CreateFileStream (prefix+"_ssThresh.csv", mode);

  Time now = Simulator::Now();
  *streamTxNext->GetStream() << "Time,oldNextTxSequence,newNextTxSequence" << std::endl
                             << now << ",," << sock->m_nextTxSequence << std::endl;

  *streamTxHighest->GetStream() << "Time,oldHighestSequence,newHighestSequence" << std::endl
                              << now << ",," << sock->m_highTxMark << std::endl;

  // In fact it might be acked but as it neds to be moved on a per-mapping basis
  //
  *streamTxUnack->GetStream() << "Time,oldUnackSequence,newUnackSequence" << std::endl
                                  << now << ",," << sock->FirstUnackedSeq() << std::endl;

  *streamRxNext->GetStream() << "Time,oldRxNext,newRxNext" << std::endl
                             << now << ",," << sock->m_rxBuffer.NextRxSequence() << std::endl;

  *streamRxAvailable->GetStream() << "Time,oldRxAvailable,newRxAvailable" << std::endl
                                  << now << ",," << sock->GetRxAvailable() << std::endl;

  *streamRxTotal->GetStream() << "Time,oldRxTotal,newRxTotal" << std::endl
                                  << now << ",," << sock->m_rxBuffer.Size() << std::endl;

  // TODO
  *streamCwnd->GetStream() << "Time,oldCwnd,newCwnd" << std::endl;
//                          << now << ",," << sock->m_cWnd.Get() << std::endl;

  *streamRwnd->GetStream() << "Time,oldRwnd,newRwnd" << std::endl
                           << now << ",," << sock->RemoteWindow() << std::endl;

  // We don't plot it, just looking at it so we don't care of the initial state
  *streamStates->GetStream() << "Time,oldState,newState" << std::endl;
//                            << now << ",," << sock->m_state << std::endl;

//  , HighestSequence, RWND\n";

//  NS_ASSERT(f.is_open());

  // TODO je devrais etre capable de voir les CongestionWindow + tailles de buffer/ Out of order
//  CongestionWindow
//  Ptr<MpTcpSocketBase> sock(this);
  NS_ASSERT(sock->TraceConnect ("NextTxSequence", "NextTxSequence", MakeBoundCallback(&dumpSequence32, streamTxNext)));
  NS_ASSERT(sock->TraceConnect ("HighestSequence", "HighestSequence", MakeBoundCallback(&dumpSequence32, streamTxHighest)));
//  NS_ASSERT(sock->m_txBuffer.TraceConnect ("UnackSequence", "UnackSequence", MakeBoundCallback(&dumpSequence32, streamTxUnack)));
  NS_ASSERT(sock->TraceConnect ("UnackSequence", "UnackSequence", MakeBoundCallback(&dumpSequence32, streamTxUnack)));

  NS_ASSERT(sock->TraceConnect ("CongestionWindow", "CongestionWindow", MakeBoundCallback(&dumpUint32, streamCwnd)));
  NS_ASSERT(sock->TraceConnect ("State", "State", MakeBoundCallback(&dumpTcpState, streamStates) ));

//  Ptr<MpTcpSocketBase> sock2 = DynamicCast<MpTcpSocketBase>(sock);

//  Ptr<TcpTxBuffer> txBuffer( &sock->m_txBuffer);
//  NS_ASSERT(txBuffer->TraceConnect ("UnackSequence", "UnackSequence", MakeBoundCallback(&dumpSequence32, streamTx)));

//  NS_LOG_UNCOND("Starting research !!");


  NS_ASSERT(sock->m_rxBuffer.TraceConnect ("NextRxSequence", "NextRxSequence", MakeBoundCallback(&dumpSequence32, streamRxNext) ));
  NS_ASSERT(sock->m_rxBuffer.TraceConnect ("RxTotal", "RxTotal", MakeBoundCallback(&dumpUint32, streamRxTotal) ));
  NS_ASSERT(sock->m_rxBuffer.TraceConnect ("RxAvailable", "RxAvailable", MakeBoundCallback(&dumpUint32, streamRxAvailable) ));

  NS_ASSERT(sock->TraceConnect ("RWND", "Remote WND", MakeBoundCallback(&dumpUint32, streamRwnd)));

  /*
  This part is kinda specific to what we want to do
  */
  Ptr<MpTcpSubflow> sf = DynamicCast<MpTcpSubflow>(sock);
//  if(sock->GetInstanceTypeId() == MpTcpSubflow::GetTypeId())
  if(sf)
  {
    //!

    NS_ASSERT(sf->TraceConnect ("SSThreshold", "SSThreshold", MakeBoundCallback(&dumpUint32, streamSSThreshold)));
    *streamSSThreshold->GetStream() << "Time,oldSSThresh,newSSThresh" << std::endl
                                  << now << ",," << sf->GetSSThresh() << std::endl;

    // TODO Trace first Cwnd
//    *streamCwnd->GetStream() << now << ",," << sf->m_cWnd.Get() << std::endl;
  }
  else if(sock->GetInstanceTypeId() == MpTcpSocketBase::GetTypeId())
  {
    //! Does nothing for now
    // could go to SetupMetaTracing
  }
  else {
    NS_FATAL_ERROR("The passed sock is not related to MPTCP (which is not a problem in absolute terms)");
  }
}

void
MpTcpSocketBase::SetupMetaTracing(std::string prefix)
{
//  f.open(filename, std::ofstream::out | std::ofstream::trunc);
  m_tracePrefix = prefix + "/";

//  prefix = m_tracePrefix + "/meta";

  SetupSocketTracing(this, m_tracePrefix + "/meta");
}


void
MpTcpSocketBase::OnSubflowClosing(Ptr<MpTcpSubflow> sf)
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
MpTcpSocketBase::OnSubflowDupack(Ptr<MpTcpSubflow> sf, MpTcpMapping mapping)
{
  NS_LOG_LOGIC("Subflow Dupack TODO.Nothing done by meta");
}

void
MpTcpSocketBase::OnSubflowRetransmit(Ptr<MpTcpSubflow> sf)
{
  NS_LOG_WARN("Subflow retransmit. Nothing done by meta");
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
  // suboptimal but works
//  m_cWnd = ComputeTotalCWND();
  NS_LOG_LOGIC("remoteWin=" << RemoteWindow() << ", totalCwnd=" << m_cWnd.Get ());
//  return std::min(m_rWnd.Get(), totalcWnd);
  return std::min ( RemoteWindow(), m_cWnd.Get ());
//  return m_rWnd.Get();
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

  Ptr<MpTcpSubflow> sFlow = m_subflows[sFlowIdx];
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

/**
This does not change much for now
**/
Time
MpTcpSocketBase::ComputeReTxTimeoutForSubflow( Ptr<MpTcpSubflow> sf)
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
  Ptr<MpTcpSubflow> sFlow = m_subflows[sFlowIdx];
  sFlow->m_dupAckCount++;
  ptrDSN->dupAckCount++; // Used for evaluation purposes only
  uint32_t cwnd = sFlow->cwnd.Get();
  uint32_t m_segmentSize = sFlow->GetSegSize();
  ComputeTotalCWND();

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
//  if (m_rxBuffer.Size() != 0)
  if (GetRxAvailable() != 0)
  {
    NS_FATAL_ERROR("TODO rxbuffer != 0");
      SendRST();
      return 0;
  }

  uint32_t remainingData = m_txBuffer.SizeFromSequence(m_nextTxSequence);
//  uint32_t remainingData = GetTxAvailable();


  NS_LOG_UNCOND("Call to close: data =" << remainingData );

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

/**
TODO it should trigger an event in the path id manager
**/
int
MpTcpSocketBase::CloseSubflow(Ptr<MpTcpSubflow> sf)
{
  NS_LOG_LOGIC("Closing sf " << sf);

  int ret = sf->Close();
  if(ret != 0) {
    NS_FATAL_ERROR("Could not close subflow");
  }

  return ret;
}

void
MpTcpSocketBase::CloseAllSubflows()
{
  NS_LOG_FUNCTION(this << "Closing all subflows");
  NS_ASSERT( m_state == FIN_WAIT_2 || m_state == CLOSING || m_state == CLOSE_WAIT);

  for(int i = 0; i < Closing; ++i) {
//    Established
    NS_LOG_INFO("Closing all subflows in state [" << containerNames [i] << "]");
//    std::for_each( );
    for( SubflowList::const_iterator it = m_subflows[i].begin(); it != m_subflows[i].end(); it++ )
    {
        Ptr<MpTcpSubflow> sf = *it;
        NS_ASSERT( CloseSubflow(sf) == 0);

//        }
//        NS_ASSERT_MSG(sf->Close() == 0, "Can't close subflow");
    }

    m_subflows[Closing].insert( m_subflows[Closing].end(), m_subflows[i].begin(), m_subflows[i].end());
    m_subflows[i].clear();
    //! Once subflow of current container were closed, we move everything to
    //!
//    MoveSubflow(sf, Closing);
  }
}


void
MpTcpSocketBase::ReceivedAck(
//  const TcpHeader& tcpHeader,
//  Ptr<TcpOptionMpTcpDSS> dss
  SequenceNumber32 dack
  , Ptr<MpTcpSubflow> sf
  , bool count_dupacks
  )
{
  NS_LOG_FUNCTION("Received DACK " << dack << "from subflow" << sf << "(Enable dupacks:" << count_dupacks << " )");
//  NS_ASSERT( dss->GetFlags() & TcpOptionMpTcpDSS::DataAckPresent);

//  SequenceNumber32 dack = SequenceNumber32(dss->GetDataAck());

  if (dack < FirstUnackedSeq())
    { // Case 1: Old ACK, ignored.
      NS_LOG_LOGIC ("Old ack Ignored " << dack  );
    }
  else if (dack  == FirstUnackedSeq())
    { // Case 2: Potentially a duplicated ACK
      if (dack  < m_nextTxSequence)
        {
        /* TODO dupackcount shall only be increased if there is only a DSS option ! */
          NS_LOG_WARN ("TODO Dupack of " << dack << " not handled yet." );
          // TODO add new prototpye ?
//            DupAck(tcpHeader, ++m_dupAckCount);
        }
      // otherwise, the ACK is precisely equal to the nextTxSequence
      NS_ASSERT( dack  <= m_nextTxSequence);
    }
  else if (dack  > FirstUnackedSeq())
    { // Case 3: New ACK, reset m_dupAckCount and update m_txBuffer
      NS_LOG_LOGIC ("New DataAck [" << dack  << "]");

      NewAck( dack );
      m_dupAckCount = 0;
    }

}



void
MpTcpSocketBase::ProcessDSSEstablished(const TcpHeader& tcpHeader, Ptr<TcpOptionMpTcpDSS> dss, Ptr<MpTcpSubflow> sf)
{
  NS_LOG_FUNCTION (this << dss << " from " << sf);

//  #if 0
//  uint32_t ack = (tcpHeader.GetAckNumber()).GetValue();
//  uint32_t tmp = ((ack - initialSeqNb) / m_segmentSize) % mod;
//  ACK.push_back(std::make_pair(Simulator::Now().GetSeconds(), tmp));
  if ( dss->GetFlags() & TcpOptionMpTcpDSS::DataFin)
  {
    NS_LOG_LOGIC("DFIN detected " << dss->GetDataFinDSN());
    PeerClose( SequenceNumber32(dss->GetDataFinDSN()), sf);
  }


  // TOdO replace that

  if( dss->GetFlags() & TcpOptionMpTcpDSS::DataAckPresent)
  {
    //tcpHeader,
    ReceivedAck( SequenceNumber32(dss->GetDataAck()), sf, false);
//    SequenceNumber32 dack = SequenceNumber32(dss->GetDataAck());


  }

  //! datafin case handled at the start of the function
  if( (dss->GetFlags() & TcpOptionMpTcpDSS::DSNMappingPresent) && !dss->DataFinMappingOnly() )
  {
      sf->AddPeerMapping(dss->GetMapping());
  }
}

/* process while in CLOSING/LAST_ACK */
void
MpTcpSocketBase::ProcessDSSClosing( Ptr<TcpOptionMpTcpDSS> dss, Ptr<MpTcpSubflow> sf)
{

  /////////////////////////////////////////////
  ////
  //// ZIS FUNCTION IS NEVER CALLED for now
  ////
  ////
  /////////////////////////////////////////////
  //// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
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

  // If there is a datafin in there, I should ack it
  if ( dss->GetFlags() & TcpOptionMpTcpDSS::DataFin) {
    //
    PeerClose( SequenceNumber32(dss->GetDataFinDSN()), sf);
  }


  if(dss->GetFlags() & TcpOptionMpTcpDSS::DataAckPresent) {

    SequenceNumber32 dack(dss->GetDataAck());
    NS_LOG_LOGIC("Received while closing dack="<< dack);
    // TODO maybe add 1 since it acknowledges the datafin ?
    // or maybe it is already
    // I changed m_rx by m_tx here
//    if ( dack == m_txBuffer.NextRxSequence())
    if ( dack == m_nextTxSequence)
    { // This ACK corresponds to the FIN sent
      NS_LOG_LOGIC("Our datafin got acked since dack=m_nextTxSequence="<< m_nextTxSequence);
      TimeWait(); //! TimeWait starts closing the subflows
      return;
    }
  }


// CLOSING state means simultaneous close, i.e. no one is sending data to
//      // anyone. If anything other than ACK is received, respond with a reset.
//  SendFastClose(sf);
//  CloseAndNotify();
}

/** when in m_closed fin_wait etc
According to 6824
A connection is considered closed once both hosts' DATA_FINs have
been acknowledged by DATA_ACKs.
*/
void
MpTcpSocketBase::ProcessDSSWait( Ptr<TcpOptionMpTcpDSS> dss, Ptr<MpTcpSubflow> sf)
{
  NS_LOG_FUNCTION (this << dss << " from " << sf);

  if(dss->GetFlags() & TcpOptionMpTcpDSS::DataFin)
  {
    NS_LOG_LOGIC("Received datafin ");
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
  if(dss->GetFlags() & TcpOptionMpTcpDSS::DataAckPresent)
  {
    SequenceNumber32 dack(dss->GetDataAck() );
    NS_LOG_INFO("dack=" << dack <<  " to compare with m_nextTxSequence=" << m_nextTxSequence);
//    if (dack == m_rxBuffer.NextRxSequence())
    if (dack == m_nextTxSequence)
    { // This ACK corresponds to the DATA FIN sent
      NS_LOG_LOGIC("Ack corresponds to DFIN sent");
      if(m_state == FIN_WAIT_1) {
        NS_LOG_LOGIC(" FIN_WAIT_1 -> FIN_WAIT_2");
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
    else {
      ReceivedAck(dack,sf,false);
    }
  }


  if( (dss->GetFlags() & TcpOptionMpTcpDSS::DSNMappingPresent) && !dss->DataFinMappingOnly() )
  {
      sf->AddPeerMapping(dss->GetMapping());
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
  Time timewait_duration = Seconds(2 * m_msl);
  NS_LOG_INFO (TcpStateName[m_state] << " -> TIME_WAIT "
              << "with duration of " << timewait_duration
              << "; m_msl=" << m_msl);
//  TcpSocketBase::TimeWait();
  CloseAllSubflows();
  m_state = TIME_WAIT;
  CancelAllTimers();
//  // Move from TIME_WAIT to CLOSED after 2*MSL. Max segment lifetime is 2 min
//  // according to RFC793, p.28
  m_timewaitEvent = Simulator::Schedule(timewait_duration, &MpTcpSocketBase::OnTimeWaitTimeOut, this);
}

void
MpTcpSocketBase::OnTimeWaitTimeOut(void)
{
  // Would normally call CloseAndNotify
  NS_LOG_LOGIC("Timewait timeout expired");
  NS_LOG_UNCOND("after timewait timeout, there are still " << m_subflows[Closing].size() << " subflows pending");
  CloseAndNotify();
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

}

/* Peer sent me a DATA FIN. Remember its sequence in rx buffer.
It means there won't be any mapping above that dataseq
*/

void
MpTcpSocketBase::PeerClose(Ptr<Packet> p, const TcpHeader& tcpHeader)
{
  NS_LOG_FUNCTION(this << " PEEER CLOSE CALLED !" << tcpHeader);

  NS_FATAL_ERROR("TO REMOVE. Function overriden by PeerClose(subflow)");

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
//  Ptr<MpTcpSubflow> sFlow = m_subflows[sFlowIdx];
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
//  NS_ASSERT(m_state == )
  Ptr<TcpOptionMpTcpDSS> dss;
  GetOrCreateMpTcpOption(header,dss);
//  if(!GetMpTcpOption(header,dss))
//    dss = Create<>(TcpOptionMpTcpMain::MP_DSS);

  // TODO we should replace this by sthg else like m_nextTxSequence ?
//  dss->EnableDataFin( m_txBuffer.TailSequence() );
//well so far this worked
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
  Ptr<MpTcpSubflow> subflow = GetSubflow(0);


  switch (m_state)
  {
  case SYN_RCVD:
  case ESTABLISHED:
// send FIN to close the peer
      NS_LOG_INFO ("ESTABLISHED -> FIN_WAIT_1");
      m_state = FIN_WAIT_1;
      subflow->GenerateEmptyPacketHeader(header,TcpHeader::ACK);
//      SendEmptyPacket(header);
      AppendDataFin(header);
      subflow->SendEmptyPacket(header);

      break;

  case CLOSE_WAIT:
// send ACK to close the peer
      NS_LOG_INFO ("CLOSE_WAIT -> LAST_ACK");
      m_state = LAST_ACK;

      subflow->GenerateEmptyPacketHeader(header, TcpHeader::ACK);
      AppendDataAck(header);
      subflow->SendEmptyPacket(header);
//      SendEmptyPacket(TcpHeader::FIN | TcpHeader::ACK);


      break;

  case SYN_SENT:
//      SendRST();
//      CloseAndNotify();

  case CLOSING:
// Send RST if application closes in SYN_SENT and CLOSING
// TODO deallocate all childrne
      NS_LOG_WARN("trying to close while closing..");
//      NS_LOG_INFO ("CLOSING -> LAST_ACK");
//      m_state = TIME_WAIT;
//        NotifyErrorClose();
//      DeallocateEndPoint();

      break;
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

TODO fix this to handle fast recovery
**/
uint32_t
MpTcpSocketBase::ComputeTotalCWND()
{
  NS_LOG_DEBUG("Cwnd before update=" << m_cWnd.Get());
  uint32_t totalCwnd = 0;

  for (uint32_t i = 0; i < Maximum; i++)
  {
    for( SubflowList::const_iterator it = m_subflows[i].begin(); it != m_subflows[i].end(); it++ )
    {
  //      Ptr<MpTcpSubflow> sf = m_subflows[Established][i];
        Ptr<MpTcpSubflow> sf = *it;

        // TODO handle fast recovery
        // fast recovery
  //      if ( sf->m_inFastRec) {
  //        NS_LOG_DEBUG("Is in Fast recovery");
  //        totalCwnd += sf->GetSSThresh();
  //      }
  //      else
        {
//          NS_LOG_WARN("Don't consider Fast recovery yet");
          totalCwnd += sf->m_cWnd.Get();          // Should be this all the time ?!
        }
    }
  }
  m_cWnd = totalCwnd;
    NS_LOG_DEBUG("Cwnd after computation=" << m_cWnd.Get());
  return totalCwnd;
}

#if 0
void
MpTcpSocketBase::OpenCWND(uint8_t sFlowIdx, uint32_t ackedBytes)
{
  NS_LOG_FUNCTION(this << (int) sFlowIdx << ackedBytes);
  Ptr<MpTcpSubflow> sFlow = m_subflows[sFlowIdx];

//  double adder = 0;
  uint32_t cwnd = sFlow->cwnd.Get();
  uint32_t ssthresh = sFlow->GetSSThresh();

  int MSS = sFlow->GetSegSize();


//  ComputeTotalCWND();

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
//      Ptr<MpTcpSubflow> sFlow = m_subflows[i];
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
//  Ptr<MpTcpSubflow> sFlow = m_subflows[sFlowIdx];
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
