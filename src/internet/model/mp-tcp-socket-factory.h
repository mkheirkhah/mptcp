#ifndef MPTCP_SOCKET_FACTORY_H
#define MPTCP_SOCKET_FACTORY_H

#include "ns3/socket-factory.h"

namespace ns3
{

class Socket;

/**
 * \ingroup tcp
 *
 * \brief socket factory implementation for native ns-3 MPTCP
 *
 */
class MpTcpSocketFactory : public SocketFactory
{
public:
  /**
   * Get the type ID.
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId();
};

}

#endif /* MPTCP_SOCKET_FACTORY_H */
