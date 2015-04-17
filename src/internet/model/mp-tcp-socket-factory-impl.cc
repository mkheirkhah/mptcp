/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) <2013-2015> University Of Sussex
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Morteza Kheirkhah <m.kheirkhah@sussex.ac.uk>
 */
#include "mp-tcp-socket-factory-impl.h"
#include "ns3/ptr.h"
#include "tcp-l4-protocol.h"
#include "ns3/socket.h"
#include "ns3/assert.h"
//#include "mp-tcp-socket-base.h"

namespace ns3
{

MpTcpSocketFactoryImpl::MpTcpSocketFactoryImpl() :
    m_mptcp(0)
{
}

MpTcpSocketFactoryImpl::~MpTcpSocketFactoryImpl()
{
  NS_ASSERT(m_mptcp == 0);
}

void
MpTcpSocketFactoryImpl::SetTcp(Ptr<TcpL4Protocol> mptcp){
  m_mptcp = mptcp;
}

Ptr<Socket>
MpTcpSocketFactoryImpl::CreateSocket(void){
  return m_mptcp->CreateSocket();
}

void
MpTcpSocketFactoryImpl::DoDispose (void)
{
  m_mptcp = 0;
  MpTcpSocketFactory::DoDispose ();
}

}
