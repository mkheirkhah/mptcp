#include "mp-tcp-socket-factory-impl.h"
#include "tcp-socket-factory.h"
#include "ns3/ptr.h"
#include "tcp-l4-protocol.h"
#include "ns3/socket.h"
#include "ns3/assert.h"
#include "mp-tcp-socket-base.h"

namespace ns3
{


//TypeId GetTypeId (void);

MpTcpSocketFactoryImpl::MpTcpSocketFactoryImpl() :
    m_mptcp(0)
{
}

MpTcpSocketFactoryImpl::~MpTcpSocketFactoryImpl()
{
  NS_ASSERT(m_mptcp == 0);
}

void
MpTcpSocketFactoryImpl::SetTcp(Ptr<TcpL4Protocol> mptcp)
{
  m_mptcp = mptcp;
}

Ptr<Socket>
MpTcpSocketFactoryImpl::CreateSocket(void)
{
//  CreateObject()
  return m_mptcp->CreateSocket( MpTcpSocketBase::GetTypeId() );
}

void
MpTcpSocketFactoryImpl::DoDispose (void)
{
  m_mptcp = 0;
  MpTcpSocketFactory::DoDispose ();
}

}
