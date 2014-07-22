#ifndef MPTCP_CC_H
#define MPTCP_CC_H


#include <stdint.h>


namespace ns3
{

class MpTcpCongestionControl
{

public:

  virtual ~MpTcpCongestionControl() {}

  virtual uint32_t
  GetSSThresh(void) const = 0;

  virtual uint32_t
  GetInitialCwnd(void) const = 0;

  /**

  **/
  virtual const char*
  GetName(void) const = 0;
};


}


#endif /* MPTCP_CC_H */
