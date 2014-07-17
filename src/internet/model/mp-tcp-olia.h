#ifndef MPTCP_CC_OLIA_H
#define MPTCP_CC_OLIA_H

#include"ns3/mp-tcp-cc.h"

namespace ns3
{

class MpTcpCCOlia : public MpTcpCongestionControl
{

public:

  MpTcpCCOlia();
  virtual ~MpTcpCCOlia();

  virtual uint32_t
  GetSSThresh(void) const;

  virtual uint32_t
  GetInitialCwnd(void) const;


};


}


#endif /* MPTCP_CC_OLIA_H */
