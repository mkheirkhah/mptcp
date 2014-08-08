
#include "ns3/mp-tcp-olia.h"
#include "ns3/log.h"
#include "ns3/object.h"

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




MpTcpCCOlia::MpTcpCCOlia(void)
{
  NS_LOG_FUNCTION (this);
}

MpTcpCCOlia::MpTcpCCOlia(const MpTcpCCOlia& sock)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_LOGIC ("Invoked the copy constructor");
}

MpTcpCCOlia::~MpTcpCCOlia()
{
  NS_LOG_FUNCTION (this);
}


Ptr<MpTcpSocketBase>
MpTcpCCOlia::MpTcpFork(void)
{
  return CopyObject<MpTcpCCOlia>(this);
}

uint32_t
MpTcpCCOlia::GetSSThresh(void) const
{
  return 2;
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
