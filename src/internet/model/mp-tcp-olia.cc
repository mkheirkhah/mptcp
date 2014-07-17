
#include "ns3/mp-tcp-olia.h"



namespace ns3 {


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
