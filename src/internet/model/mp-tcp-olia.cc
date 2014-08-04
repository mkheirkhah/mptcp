
#include "ns3/mp-tcp-olia.h"
#include "ns3/log.h"
#include "ns3/object.h"




namespace ns3 {

NS_LOG_COMPONENT_DEFINE("MpTcpCCOlia");


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
