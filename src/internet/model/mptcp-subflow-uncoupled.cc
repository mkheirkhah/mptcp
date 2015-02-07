#include "mptcp-subflow-uncoupled.h"
#include "ns3/log.h"

NS_LOG_COMPONENT_DEFINE ("MpTcpSubflowUncoupled");

namespace ns3 {





NS_OBJECT_ENSURE_REGISTERED(MpTcpSubflowUncoupled);

TypeId
MpTcpSubflowUncoupled::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::MpTcpSubflowUncoupled")
      .SetParent<MpTcpSubflow>()
      .AddConstructor<MpTcpSubflowUncoupled>()

    ;
  return tid;
}

TypeId
MpTcpSubflowUncoupled::GetInstanceTypeId(void) const
{
  return GetTypeId();
}


Ptr<MpTcpSubflow>
MpTcpSubflowUncoupled::ForkAsSubflow(void)
{
  return CopyObject<MpTcpSubflowUncoupled> (this);
}

void
MpTcpSubflowUncoupled::OpenCwndInCA(uint32_t acked)
{
  NS_LOG_DEBUG("Opening cwnd");
  double adder = static_cast<double> (m_segmentSize * m_segmentSize) / m_cWnd.Get ();
  adder = std::max (1.0, adder);
  m_cWnd += static_cast<uint32_t> (adder);
// m_cWnd +=
//  GetMeta()->
}

void
MpTcpSubflowUncoupled::ReduceCwnd()
{
  NS_LOG_DEBUG("Reduce CWND");
    SetSSThresh( std::max(2 * m_segmentSize, BytesInFlight() / 2) );
    m_cWnd = GetSSThresh() + 3 * m_segmentSize;
}

} // end of ns3
