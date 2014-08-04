
#ifndef MPTCP_CC_FULLY_COUPLED_H
#define MPTCP_CC_FULLY_COUPLED_H


#include <stdint.h>
#include "ns3/object.h"
//#include "ns3/mp-tcp-typedefs.h"


namespace ns3
{

/**
\brief Defined in RFC 6356 (http://tools.ietf.org/html/rfc6356)

*/
class MpTcpCongestionCoupled : public MpTcpCongestionControl
{

public:

  MpTcpCongestionCoupled(  );
  virtual ~MpTcpCongestionCoupled() {}

  virtual uint32_t
  GetInitialSSThresh(void) const = 0;

  virtual uint32_t
  GetInitialCwnd(void) const = 0;

  /**
  \brief
  \return The name of the congestion control
  **/
  virtual const char*
  GetName(void) const {
    return "Coupled";
  };

  /**
  \return Nb of
  */
  virtual void OpenCWNDInCA(Ptr<MpTcpSubFlow> subflow, uint32_t ackedBytes);

protected:
  void CalculateAlpha();
  double m_alpha;
  uint32_t m_totalCwnd;

  // Put here for hte sake of simplicity
  // but should be moved to derived classes.
//  DataDistribAlgo_t m_distribAlgo; //!< Algorithm for Data Distribution
};


}


#endif /* MPTCP_CC_H */
