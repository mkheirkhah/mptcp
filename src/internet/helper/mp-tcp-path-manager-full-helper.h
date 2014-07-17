#include <map>
#include "ns3/object.h"
#include "ns3/callback.h"


namespace ns3 
{

/**
 * @brief A helper class to make life easier while doing simple IPv4 address
 * assignment in scripts.
 */
class MpTcpPathManagerHelper : public Object
{

public:
  MpTcpPathManagerHelper();
  virtual ~MpTcpPathManagerHelper();
  
  // TODO implement full
  //! Received from const subflow
//  virtual bool AddAddr(const Address& address, uint16_t port);
  
  //! 
//  virtual bool RemAddr(const Address& address, uint16_t port);

protected:
  Callback<void, Ptr<Socket> >                   m_onNewAddr;
  
  std::map<uint8_t, MpTcpAddressInfo> m_remoteAddrs;
} // end of MpTcpPathManagerHelper

} // end of ns3
