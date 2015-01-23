#ifndef MP_TCP_SUBFLOW_UNCOUPLED_H
#define MP_TCP_SUBFLOW_UNCOUPLED_H

#include "mp-tcp-subflow.h"

namespace ns3 {


class MpTcpSubflowUncoupled : public MpTcpSubFlow
{
public:
  static TypeId
  GetTypeId(void);

  virtual TypeId GetInstanceTypeId(void) const;

protected:
    Ptr<MpTcpSubFlow>
    ForkAsSubflow(void);

  virtual void OpenCwndInCA(uint32_t acked);
  virtual void ReduceCwnd();
};

}


#endif
