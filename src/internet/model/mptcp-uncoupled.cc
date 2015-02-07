
#include "ns3/mptcp-uncoupled.h"
#include "ns3/log.h"
#include "ns3/object.h"
#include "ns3/mp-tcp-id-manager.h"
#include "ns3/mptcp-subflow-uncoupled.h"
//#include "ns3/mp-tcp-id-manager.h"


NS_LOG_COMPONENT_DEFINE("MpTcpCCUncoupled");

namespace ns3 {



NS_OBJECT_ENSURE_REGISTERED (MpTcpCCUncoupled);

TypeId
MpTcpCCUncoupled::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::MpTcpCCUncoupled")
    .SetParent<MpTcpSocketBase> ()
    .AddConstructor<MpTcpCCUncoupled> ()
//    .AddAttribute ("ReTxThreshold", "Threshold for fast retransmit",
//                    UintegerValue (3),
//                    MakeUintegerAccessor (&TcpNewReno::m_retxThresh),
//                    MakeUintegerChecker<uint32_t> ())
//    .AddAttribute ("LimitedTransmit", "Enable limited transmit",
//		    BooleanValue (false),
//		    MakeBooleanAccessor (&TcpNewReno::m_limitedTx),
//		    MakeBooleanChecker ())
//    .AddTraceSource ("CongestionWindow",
//                     "The TCP connection's congestion window",
//                     MakeTraceSourceAccessor (&MpTcpCCUncoupled::m_cWnd))
  ;
  return tid;
}


//TypeId
//MpTcpCCUncoupled::GetInstanceTypeId(void) const
//{
//  return GetTypeId();
//}


MpTcpCCUncoupled::MpTcpCCUncoupled(void) :
  MpTcpSocketBase()
{
  NS_LOG_FUNCTION (this);
}

MpTcpCCUncoupled::MpTcpCCUncoupled(const MpTcpCCUncoupled& sock) :
  MpTcpSocketBase(sock)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_LOGIC ("Invoked the copy constructor");
}

MpTcpCCUncoupled::~MpTcpCCUncoupled()
{
  NS_LOG_FUNCTION (this);
}



  // inherited function, no need to doc.
//TypeId
//MpTcpCCUncoupled::GetInstanceTypeId (void) const
//{
//  return GetTypeId();
//}

TypeId
MpTcpCCUncoupled::GetMpTcpSubflowTypeId()
{
  return MpTcpSubflowUncoupled::GetTypeId();
}

Ptr<MpTcpSocketBase>
MpTcpCCUncoupled::ForkAsMeta(void)
{
  NS_LOG_UNCOND ("Fork as meta" << this->GetInstanceTypeId() << " to " << GetTypeId());
//  Ptr<MpTcpCCUncoupled> p =

  return CopyObject<MpTcpCCUncoupled>(this);
}

uint32_t
MpTcpCCUncoupled::GetSSThresh(void) const
{
  return 2;
}



uint32_t
MpTcpCCUncoupled::GetInitialCwnd(void) const
{
  return 10;
}

//
//uint32_t
//MpTcpCCUncoupled::OpenCWND(Ptr<MpTcpSubflow> sf, uint32_t ackedBytes)
//{
//  //!
//  double adder = static_cast<double> (sf->m_segmentSize * sf->m_segmentSize) / sf->m_cWnd.Get ();
//  adder = std::max (1.0, adder);
////  m_cWnd += static_cast<uint32_t> (adder);
//  return (sf->m_cWnd + static_cast<uint32_t> (adder));
//}
//
//uint32_t
//MpTcpCCUncoupled::ReduceCWND(Ptr<MpTcpSubflow> sf)
//{
//  //!
//  return sf->m_cWnd/2;
//}






} //end of ns3
