
#include "ns3/mp-tcp-olia.h"
#include "ns3/log.h"




namespace ns3 {

NS_LOG_COMPONENT_DEFINE("MpTcpCCOlia");

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

} //end of ns3
