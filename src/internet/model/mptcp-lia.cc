
#include "ns3/mp-tcp-olia.h"
#include "ns3/log.h"
#include "ns3/object.h"
#include "ns3/mp-tcp-id-manager.h"
//#include "ns3/mp-tcp-id-manager.h"

NS_LOG_COMPONENT_DEFINE("MpTcpLia");


namespace ns3 {



NS_OBJECT_ENSURE_REGISTERED (MpTcpLia);

TypeId
MpTcpLia::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::MpTcpLia")
    .SetParent<MpTcpSocketBase> ()
    .AddConstructor<MpTcpLia> ()
//    .AddAttribute ("ReTxThreshold", "Threshold for fast retransmit",
//                    UintegerValue (3),
//                    MakeUintegerAccessor (&TcpNewReno::m_retxThresh),
//                    MakeUintegerChecker<uint32_t> ())
//    .AddAttribute ("LimitedTransmit", "Enable limited transmit",
//		    BooleanValue (false),
//		    MakeBooleanAccessor (&TcpNewReno::m_limitedTx),
//		    MakeBooleanChecker ())
    .AddTraceSource ("Alpha",
//                     "The TCP connection's congestion window",
//                     MakeTraceSourceAccessor (&MpTcpLia::m_cWnd))
  ;
  return tid;
}


//TypeId
//MpTcpLia::GetInstanceTypeId(void) const
//{
//  return GetTypeId();
//}


MpTcpLia::MpTcpLia(void) :
  MpTcpSocketBase()
{
  NS_LOG_FUNCTION (this);
}

MpTcpLia::MpTcpLia(const MpTcpLia& sock) :
  MpTcpSocketBase(sock)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_LOGIC ("Invoked the copy constructor");
}

MpTcpLia::~MpTcpLia()
{
  NS_LOG_FUNCTION (this);
}

  // inherited function, no need to doc.
//TypeId
//MpTcpLia::GetInstanceTypeId (void) const
//{
//  return GetTypeId();
//}

Ptr<MpTcpSocketBase>
MpTcpLia::ForkAsMeta(void)
{
  NS_LOG_UNCOND ("Fork as meta" << this->GetInstanceTypeId() << " to " << GetTypeId());
//  Ptr<MpTcpLia> p =

  return CopyObject<MpTcpLia>(this);
}

uint32_t
MpTcpLia::GetSSThresh(void) const
{
  return 2;
}


        calculateAlpha();
        adder = alpha * MSS * MSS / m_totalCwnd;
        adder = std::max(1.0, adder);
        sFlow->cwnd += static_cast<double>(adder);

        NS_LOG_ERROR ("Subflow "
                <<(int)sFlowIdx
                <<" Congestion Control (Linked_Increases): alpha "<<alpha
                <<" increment is "<<adder
                <<" GetSSThresh() "<< GetSSThresh()
                << " cwnd "<<cwnd );
        break;


uint32_t
MpTcpLia::GetInitialCwnd(void) const
{
  return 10;
}

//
//Ptr<SubFlow>
//MpTcpLia::GetSubflowToUse(Ptr<MpTcpSocketBase> metaSock)
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


