
#include "ns3/mp-tcp-olia.h"
#include "ns3/log.h"
#include "ns3/object.h"
#include "ns3/mp-tcp-id-manager.h"
//#include "ns3/mp-tcp-id-manager.h"

NS_LOG_COMPONENT_DEFINE("MpTcpCCOlia");


namespace ns3 {



NS_OBJECT_ENSURE_REGISTERED (MpTcpCCOlia);

TypeId
MpTcpCCOlia::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::MpTcpCCOlia")
    .SetParent<MpTcpSocketBase> ()
    .AddConstructor<MpTcpCCOlia> ()
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
//                     MakeTraceSourceAccessor (&MpTcpCCOlia::m_cWnd))
  ;
  return tid;
}


//TypeId
//MpTcpCCOlia::GetInstanceTypeId(void) const
//{
//  return GetTypeId();
//}


MpTcpCCOlia::MpTcpCCOlia(void) :
  MpTcpSocketBase()
{
  NS_LOG_FUNCTION (this);
}

MpTcpCCOlia::MpTcpCCOlia(const MpTcpCCOlia& sock) :
  MpTcpSocketBase(sock)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_LOGIC ("Invoked the copy constructor");
}

MpTcpCCOlia::~MpTcpCCOlia()
{
  NS_LOG_FUNCTION (this);
}


//uint32_t
//MpTcpCCOlia::OpenCWND(uint32_t cwnd, uint32_t ackedBytes) {
//
//  return 1;
//}
//
//uint32_t
//MpTcpCCOlia::ReduceCWND(uint32_t cwnd)
//{
//  return cwnd/2;
//}
//
//  // inherited function, no need to doc.
//TypeId
//MpTcpCCOlia::GetInstanceTypeId (void) const
//{
//  return GetTypeId();
//}

Ptr<MpTcpSocketBase>
MpTcpCCOlia::ForkAsMeta(void)
{
  NS_LOG_UNCOND ("Fork as meta" << this->GetInstanceTypeId() << " to " << GetTypeId());
//  Ptr<MpTcpCCOlia> p =

  return CopyObject<MpTcpCCOlia>(this);
}

uint32_t
MpTcpCCOlia::GetSSThresh(void) const
{
  return 2;
}

TypeId
MpTcpCCOlia::GetMpTcpSubflowTypeId()
{
  return MpTcpSubflow::GetTypeId();
}


uint32_t
MpTcpCCOlia::GetInitialCwnd(void) const
{
  return 10;
}

//
//Ptr<SubFlow>
//MpTcpCCOlia::GetSubflowToUse(Ptr<MpTcpSocketBase> metaSock)
//{
//  uint8_t nextSubFlow = 0;
//  switch (m_distribAlgo)
//    {
//  case Round_Robin:
//    nextSubFlow = (m_lastUsedsFlowIdx + 1) % m_subflows.size();
//    break;
//  default:
//    break;
//    }
//  return nextSubFlow;
//
//}
//




} //end of ns3
