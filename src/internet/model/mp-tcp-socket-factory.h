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
