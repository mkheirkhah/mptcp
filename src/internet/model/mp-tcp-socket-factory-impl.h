#ifndef MP_TCP_SOCKET_FACTORY_IMPL_H
#define MP_TCP_SOCKET_FACTORY_IMPL_H

#include "mp-tcp-socket-factory.h"

namespace ns3
{

class TcpL4Protocol;

class MpTcpSocketFactoryImpl : public MpTcpSocketFactory
{
public:
  MpTcpSocketFactoryImpl();
  virtual ~MpTcpSocketFactoryImpl();
  void SetTcp(Ptr<TcpL4Protocol>);
  virtual Ptr<Socket> CreateSocket();

protected:
  virtual void DoDispose();

private:
  Ptr<TcpL4Protocol> m_mptcp;
};

} // namespace ns3

#endif /* MP_TCP_SOCKET_FACTORY_IMPL_H */
