
#ifndef MPTCP_SCHEDULER_H
#define MPTCP_SCHEDULER_H


#include <stdint.h>
#include "ns3/ptr.h"
//#include "ns3/mp-tcp-socket-base.h"


namespace ns3
{

class MpTcpScheduler
{

public:

  virtual ~MpTcpScheduler() {}


  /**
  \brief
  \return Subflow on which to send
  **/
//  virtual Ptr<MpTcpSubflow> GetSubflowToUse(Ptr<MpTcpSocketBase> metaSock);


  /**
  \brief Name of the scheduler
  **/
//  virtual const char*
//  GetName(void) const = 0;
};


}


#endif /* MPTCP_SCHEDULER_H */
