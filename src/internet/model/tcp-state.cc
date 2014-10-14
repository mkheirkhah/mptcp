#include "tcp-state.h"

namespace ns3
{


void
TcpState::Set (const TcpStates_t &v)
{
    if (m_v != v)
      {
        m_cb (m_v, v);
        m_v = v;
      }
}


}
