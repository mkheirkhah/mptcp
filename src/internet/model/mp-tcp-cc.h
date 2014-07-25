#ifndef MPTCP_CC_H
#define MPTCP_CC_H


#include <stdint.h>


namespace ns3
{


class MpTcpCongestionControl
{

public:
//  MpTcpCongestionControl();
  virtual ~MpTcpCongestionControl() {}

  virtual uint32_t
  GetSSThresh(void) const = 0;

  virtual uint32_t
  GetInitialCwnd(void) const = 0;

  /**
  \brief
  \return The name of the congestion control
  **/
  virtual const char*
  GetName(void) const = 0;


protected:
  // Put here for hte sake of simplicity
  // but should be moved to derived classes.
//  DataDistribAlgo_t m_distribAlgo; //!< Algorithm for Data Distribution
};


}


#endif /* MPTCP_CC_H */
