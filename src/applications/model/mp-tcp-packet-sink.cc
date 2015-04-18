/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright 2014 University of Sussex, UK.
 * Copyright 2007 University of Washington
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
 * Author:  Tom Henderson (tomhend@u.washington.edu)
 * Modified by Morteza Kheirkhah (m.kheirkhah@sussex.ac.uk)
*/

#include "ns3/address.h"
#include "ns3/address-utils.h"
#include "ns3/log.h"
#include "ns3/inet-socket-address.h"
#include "ns3/node.h"
#include "ns3/socket.h"
#include "ns3/udp-socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/mp-tcp-packet-sink.h"

using namespace std;

NS_LOG_COMPONENT_DEFINE("MpTcpPacketSink");

namespace ns3
{

NS_OBJECT_ENSURE_REGISTERED(MpTcpPacketSink);

TypeId
MpTcpPacketSink::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::MpTcpPacketSink")
      .SetParent<Application>()
      .AddConstructor<MpTcpPacketSink>()
      .AddAttribute("Local", "The Address on which to Bind the rx socket.",
          AddressValue(),
          MakeAddressAccessor(&MpTcpPacketSink::m_local),
          MakeAddressChecker())
      .AddAttribute ("Protocol", "The type id of the protocol to use for the rx socket.",
                   TypeIdValue (TcpSocketFactory::GetTypeId ()),
                   MakeTypeIdAccessor (&MpTcpPacketSink::m_tid),
                   MakeTypeIdChecker ())
//    .AddTraceSource ("Rx", "A packet has been received",
//                     MakeTraceSourceAccessor (&MpTcpPacketSink::m_rxTrace))
      ;
  return tid;
}

MpTcpPacketSink::MpTcpPacketSink()
{
  NS_LOG_FUNCTION (this);
  m_socket = 0;
  m_totalRx = 0;
}

MpTcpPacketSink::~MpTcpPacketSink()
{
  NS_LOG_FUNCTION (this);
}

uint32_t
MpTcpPacketSink::GetTotalRx() const
{
  return m_totalRx;
}

void
MpTcpPacketSink::DoDispose(void)
{
  NS_LOG_FUNCTION (this);
  m_socket = 0;

  // chain up
  Application::DoDispose();
}

// Application Methods
void
MpTcpPacketSink::StartApplication()    // Called at time specified by Start
{
  NS_LOG_FUNCTION (this);
  // Create the socket if not already
  if (!m_socket)
    {
      size = 2000;
      //buf = new uint8_t[size];
      //m_socket = CreateObject<MpTcpSocketBase>(GetNode());
      m_socket = DynamicCast<MpTcpSocketBase>(Socket::CreateSocket (GetNode (), m_tid));
      m_socket->Bind(m_local);
      m_socket->Listen();
      NS_LOG_LOGIC("StartApplication -> MptcpPacketSink got an listening socket " << m_socket << " binded to addrs:port  " << InetSocketAddress::ConvertFrom(m_local).GetIpv4() << ":" << InetSocketAddress::ConvertFrom(m_local).GetPort());
    }

  m_socket->SetRecvCallback(MakeCallback(&MpTcpPacketSink::HandleRead, this));
  m_socket->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address &>(),
      MakeCallback(&MpTcpPacketSink::HandleAccept, this));
  m_socket->SetCloseCallbacks(MakeCallback(&MpTcpPacketSink::HandlePeerClose, this),
      MakeCallback(&MpTcpPacketSink::HandlePeerError, this));
}

void
MpTcpPacketSink::StopApplication()     // Called at time specified by Stop
{
  NS_LOG_FUNCTION (this);     //
  NS_LOG_WARN (Simulator::Now().GetSeconds() << " MpTcpPacketSink -> Total received bytes " << m_totalRx);
  while (!m_socketList.empty()) //these are accepted sockets, close them
    {
      Ptr<Socket> acceptedSocket = m_socketList.front();
      m_socketList.pop_front();
      NS_LOG_INFO("MpTcpPacketSink -> Drop this accepted socket ,"<<acceptedSocket << ", and call Close on it ");
      acceptedSocket->Close();
      NS_LOG_INFO("MpTcpPacketSink -> Now SocketListSize is " << m_socketList.size());
    }

  if (m_socket)
    {
      NS_LOG_INFO("MpTcpPacketSink -> FINALY closing the listening socket, " << m_socket);
      m_socket->Close();
      m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket> >());
    }
}

void
MpTcpPacketSink::HandleRead(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << m_socket);
  Ptr<MpTcpSocketBase> mpSocket = DynamicCast<MpTcpSocketBase>(socket);
  uint32_t dataAmount = mpSocket->Recv(size);
  //uint32_t dataAmount = m_socket->Recv(buf, size);
  m_totalRx += dataAmount;
  NS_LOG_INFO ("MpTcpPacketSink:HandleRead() -> Received " << dataAmount << " bytes total Rx " << m_totalRx);
}

void
MpTcpPacketSink::HandlePeerClose(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
//  list<Ptr<Socket> >::iterator it = std::find(m_socketList.begin(), m_socketList.end(), socket);
//  if (it != m_socketList.end())
//    {
//      m_socketList.erase(it);
//      NS_LOG_UNCOND("A Socket has been Removed with Normal callback");
//    }
}

void
MpTcpPacketSink::HandlePeerError(Ptr<Socket> socket)
{
//  list<Ptr<Socket> >::iterator it = std::find(m_socketList.begin(), m_socketList.end(), socket);
//  if (it != m_socketList.end())
//    {
//      m_socketList.erase(it);
//      NS_LOG_UNCOND("A Socket has been Removed with Error callback");
//    }
  NS_LOG_FUNCTION(this << socket);
}

void
MpTcpPacketSink::HandleAccept(Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback(MakeCallback(&MpTcpPacketSink::HandleRead, this));
//  s->SetCloseCallbacks(MakeCallback(&MpTcpPacketSink::HandlePeerClose, this),
//      MakeCallback(&MpTcpPacketSink::HandlePeerError, this));
  m_socketList.push_back(s);
  NS_LOG_INFO("MptcpPacketSink got an new connection. SocketList: " << m_socketList.size());
}

Ptr<MpTcpSocketBase>
MpTcpPacketSink::getMpTcpSocket()
{
  return m_socket;
}

} // Namespace ns3
