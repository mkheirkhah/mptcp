
#include "ns3/mp-tcp-olia.h"
#include "ns3/log.h"




namespace ns3 {

NS_LOG_COMPONENT_DEFINE("MpTcpCCOlia");


MpTcpCCOlia::MpTcpCCOlia()
{

}

MpTcpCCOlia::~MpTcpCCOlia()
{
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
