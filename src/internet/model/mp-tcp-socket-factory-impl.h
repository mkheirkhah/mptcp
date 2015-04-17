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
