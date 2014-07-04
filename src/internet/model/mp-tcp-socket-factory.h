#ifndef MPTCP_SOCKET_FACTORY_H
#define MPTCP_SOCKET_FACTORY_H

#include "ns3/socket-factory.h"

namespace ns3
{

class Socket;

class MpTcpSocketFactory : public SocketFactory
{
public:
  static TypeId GetTypeId();
};

}

#endif MPTCP_SOCKET_FACTIRY_H
