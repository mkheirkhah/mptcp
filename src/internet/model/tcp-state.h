
/**

Should inherit from TracedValue
**/
#include "ns3/traced-value.h"

namespace ns3
{

class TcpState : public TracedValue<TcpStates_t>
{
public:
  virtual void Set (const TcpStates_t &v) ;
}

}
