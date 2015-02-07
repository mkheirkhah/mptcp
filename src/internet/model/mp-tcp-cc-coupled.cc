
#include "ns3/mp-tcp-cc-coupled.h"

namespace ns3
{

void
MpTcpCongestionCoupled::CalculateAlpha()
{
  // this method is called whenever a congestion happen in order to regulate the agressivety of m_subflows
  // m_alpha = cwnd_total * MAX(cwnd_i / rtt_i^2) / {SUM(cwnd_i / rtt_i))^2}   //RFC 6356 formula (2)

  NS_LOG_FUNCTION(this);
  m_alpha = 0;
  double maxi = 0;
  double sumi = 0;

  for (uint32_t i = 0; i < m_metaSock->GetNActiveSubflows(); i++)
    {
      Ptr<MpTcpSubflow> sFlow = m_metaSock->GetSubflow(i);

      Time time = sFlow->rtt->GetCurrentEstimate();
      double rtt = time.GetSeconds();
      double tmpi = sFlow->cwnd.Get() / (rtt * rtt);
      if (maxi < tmpi)
        maxi = tmpi;

      sumi += sFlow->cwnd.Get() / rtt;
    }
  m_alpha = (m_totalCwnd * maxi) / (sumi * sumi);
}


//
uint32_t
MpTcpCongestionCoupled::OpenCWNDInCA(Ptr<MpTcpSubflow> subflow, uint32_t ackedBytes)
{
  NS_ASSERT( subflow );

  uint32_t MSS = subflow->GetSegSize();
  double inc = static_cast<double>(MSS * MSS) / m_totalCwnd;
  inc = std::max(1.0, inc);
  subflow->cwnd += static_cast<double>(inc);
//  NS_LOG_ERROR (
//      "Subflow "<<(int)sFlowIdx
//      <<" Congestion Control (Fully_Coupled) increment is "
//      << adder <<" GetSSThresh() "<< GetSSThresh() << " cwnd "<<cwnd);
  return 0;
}

}
