 /* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2010 Georgia Institute of Technology
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
 * Author: George F. Riley <riley@ece.gatech.edu>
 */

#include "ns3/log.h"
#include "ns3/address.h"
#include "ns3/node.h"
#include "ns3/nstime.h"
#include "ns3/socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/tcp-socket-factory.h"
#include "mptcp-bulk-send-application.h"

NS_LOG_COMPONENT_DEFINE ("MpTcpBulkSendApplication");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (MpTcpBulkSendApplication)
  ;

TypeId
MpTcpBulkSendApplication::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::MpTcpBulkSendApplication")
    .SetParent<Application> ()
    .AddConstructor<MpTcpBulkSendApplication> ()
    .AddAttribute ("SendSize", "The amount of data to send each time.",
                   UintegerValue (512),
                   MakeUintegerAccessor (&MpTcpBulkSendApplication::m_sendSize),
                   MakeUintegerChecker<uint32_t> (1))
    .AddAttribute ("Remote", "The address of the destination",
                   AddressValue (),
                   MakeAddressAccessor (&MpTcpBulkSendApplication::m_peer),
                   MakeAddressChecker ())
    .AddAttribute ("MaxBytes",
                   "The total number of bytes to send. "
                   "Once these bytes are sent, "
                   "no data  is sent again. The value zero means "
                   "that there is no limit.",
                   UintegerValue (0),
                   MakeUintegerAccessor (&MpTcpBulkSendApplication::m_maxBytes),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("Protocol", "The type of protocol to use.",
                   TypeIdValue (TcpSocketFactory::GetTypeId ()),
                   MakeTypeIdAccessor (&MpTcpBulkSendApplication::m_tid),
                   MakeTypeIdChecker ())
    .AddTraceSource ("Tx", "A new packet is created and is sent",
                     MakeTraceSourceAccessor (&MpTcpBulkSendApplication::m_txTrace))
  ;
  return tid;
}


MpTcpBulkSendApplication::MpTcpBulkSendApplication ()
  : m_socket (0),
    m_connected (false),
    m_totBytes (0)
{
  NS_LOG_FUNCTION (this);
  m_data = new uint8_t[1000000];
}

MpTcpBulkSendApplication::~MpTcpBulkSendApplication ()
{
  NS_LOG_FUNCTION (this);
  delete [] m_data;
}

void
MpTcpBulkSendApplication::SetMaxBytes (uint32_t maxBytes)
{
  NS_LOG_FUNCTION (this << maxBytes);
  m_maxBytes = maxBytes;
}

Ptr<Socket>
MpTcpBulkSendApplication::GetSocket (void) const
{
  NS_LOG_FUNCTION (this);
  return m_socket;
}

void
MpTcpBulkSendApplication::DoDispose (void)
{
  NS_LOG_FUNCTION (this);

  m_socket = 0;
  // chain up
  Application::DoDispose ();
}

// Application Methods
void MpTcpBulkSendApplication::StartApplication (void) // Called at time specified by Start
{
  NS_LOG_FUNCTION (this);
  NS_LOG_DEBUG("Node: " << GetNode()->GetId()<< "Remote: " << m_peer << " MaxBytes: " << m_maxBytes  << " SendSize: " << m_sendSize);
  // Create the socket if not already
  if (!m_socket)
    {
      m_socket = CreateObject<MpTcpSocketBase>(GetNode());
      //m_socket = Socket::CreateSocket (GetNode (), m_tid);
      // Fatal error if socket type is not NS3_SOCK_STREAM or NS3_SOCK_SEQPACKET
//      if (m_socket->GetSocketType () != Socket::NS3_SOCK_STREAM &&
//          m_socket->GetSocketType () != Socket::NS3_SOCK_SEQPACKET)
//        {
//          NS_FATAL_ERROR ("Using BulkSend with an incompatible socket type. "
//                          "BulkSend requires SOCK_STREAM or SOCK_SEQPACKET. "
//                          "In other words, use TCP instead of UDP.");
//        }
//      if (Inet6SocketAddress::IsMatchingType (m_peer))
//        {
//          m_socket->Bind6 ();
//        }
      //else if (InetSocketAddress::IsMatchingType (m_peer))
      m_socket->Bind();
//      if (InetSocketAddress::IsMatchingType(m_peer))
//        {
//
//        }
      m_socket->Connect(m_peer);
      //m_socket->ShutdownRecv ();
      m_socket->SetConnectCallback(MakeCallback(&MpTcpBulkSendApplication::ConnectionSucceeded, this),
          MakeCallback(&MpTcpBulkSendApplication::ConnectionFailed, this));
      m_socket->SetDataSentCallback(MakeCallback(&MpTcpBulkSendApplication::DataSend, this));
      //m_socket->SetSendCallback(MakeCallback(&MpTcpBulkSendApplication::DataSend, this));
    }
  if (m_connected)
    {
      SendData ();
    }
}

void MpTcpBulkSendApplication::StopApplication (void) // Called at time specified by Stop
{
  NS_LOG_FUNCTION (this);

  if (m_socket != 0)
    {
      m_socket->Close ();
      m_connected = false;
    }
  else
    {
      NS_LOG_WARN ("MpTcpBulkSendApplication found null socket to close in StopApplication");
    }
}

// Private helpers
void MpTcpBulkSendApplication::SendData (void)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_DEBUG("m_totBytes: " << m_totBytes << " maxByte: " << m_maxBytes << " GetTxAvailable: " << m_socket->GetTxAvailable() << " SendSize: " << m_sendSize);
  //while (m_maxBytes == 0 || m_totBytes < m_maxBytes)
  while (m_totBytes < m_maxBytes && m_socket->GetTxAvailable() > 0)
    { // Time to send more
      uint32_t toSend = m_sendSize;
      // Make sure we don't send too many
      if (m_maxBytes > 0)
        {
          toSend = std::min(m_sendSize, m_maxBytes - m_totBytes);
          toSend = std::min(toSend, m_socket->GetTxAvailable());
        }
      NS_LOG_DEBUG("toSend: " << toSend);
      int actual = m_socket->FillBuffer(&m_data[toSend], toSend);
      m_totBytes += actual;
      NS_LOG_DEBUG("totalByte: " <<  m_totBytes);
      m_socket->SendBufferedData();
      NS_LOG_DEBUG("SendBufferedData END");
    }

  if (m_totBytes == m_maxBytes && m_connected)
    {
      m_socket->Close();
      m_connected = false;
    }
}

void MpTcpBulkSendApplication::ConnectionSucceeded (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_LOGIC ("MpTcpBulkSendApplication Connection succeeded");
  m_connected = true;
  SendData ();
}

void MpTcpBulkSendApplication::ConnectionFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_LOGIC ("MpTcpBulkSendApplication, Connection Failed");
}

void MpTcpBulkSendApplication::DataSend (Ptr<Socket>, uint32_t)
{
  NS_LOG_FUNCTION (this);

  if (m_connected)
    { // Only send new data if the connection has completed
      Simulator::ScheduleNow (&MpTcpBulkSendApplication::SendData, this);
    }
}

void MpTcpBulkSendApplication::Printer(){
  for (uint32_t i = 0; i < 1000; i++){
      NS_LOG_INFO("Index " << i << " => " << (int)m_data[i]);
  }
}

} // Namespace ns3
