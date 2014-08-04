/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2011 Adrian Sai-wah Tam
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
 * Author: Adrian Sai-wah Tam <adrian.sw.tam@gmail.com>
 */

#include "tcp-option-mptcp.h"

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (TcpOptionMpTcpCapable);
NS_OBJECT_ENSURE_REGISTERED (TcpOptionMpTcpJoin);



/////////////////////////////////////////////////////////
////////  MP_CAPABLE
/////////////////////////////////////////////////////////
TcpOptionMpTcpCapable::TcpOptionMpTcpCapable()
    : TcpOptionMpTcp<MP_CAPABLE> (),
    m_version(0),m_flags(0),m_senderKey(0),m_receiverKey(0)
{
}

TcpOptionMpTcpCapable::~TcpOptionMpTcpCapable ()
{
}


void TcpOptionMpTcpCapable::Print (std::ostream &os) const
{
  os << "MP_CAPABLE. version" << ";" << m_version;
}

void TcpOptionMpTcpCapable::Serialize (Buffer::Iterator start) const
{
  TcpOptionMpTcp<MP_CAPABLE>::Serialize(start);

  // la je continue a sérialiser
}

uint32_t TcpOptionMpTcpCapable::Deserialize (Buffer::Iterator start)
{
  TcpOptionMpTcp<MP_CAPABLE>::Deserialize(start);
  return 2;
}

uint8_t TcpOptionMpTcpCapable::GetLength (void) const
{
    return (2+0);
}



/////////////////////////////////////////////////////////
////////  MP_JOIN
/////////////////////////////////////////////////////////
TcpOptionMpTcpJoin::TcpOptionMpTcpJoin()
    : TcpOptionMpTcp (),
    m_pathId(0),m_receiverToken(0),m_senderToken(0)
{
}

TcpOptionMpTcpJoin::~TcpOptionMpTcpJoin ()
{
}


void TcpOptionMpTcpJoin::Print (std::ostream &os) const
{
  os << "MP_Join" << ";" << m_pathId;
}

void TcpOptionMpTcpJoin::Serialize (Buffer::Iterator start) const
{
  TcpOptionMpTcp<MP_JOIN>::Serialize(start);

  // la je continue a sérialiser
}

uint32_t TcpOptionMpTcpJoin::Deserialize (Buffer::Iterator start)
{
  TcpOptionMpTcp<MP_JOIN>::Deserialize(start);
  return 2;
}

uint8_t TcpOptionMpTcpJoin::GetLength (void) const
{
    return 12;
}










#if 0
TcpOptionMpTcp::TcpOptionMpTcp ()
    : TcpOption ()
{
}

TcpOptionMpTcp::~TcpOptionMpTcp ()
{
}

TypeId
TcpOptionMpTcp::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::TcpOptionMpTcp")
    .SetParent<TcpOption> ()
    .AddConstructor<TcpOptionMpTcp> ()
  ;
  return tid;
}

TypeId
TcpOptionMpTcp::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

void
TcpOptionMpTcp::Print (std::ostream &os) const
{
}

uint32_t
TcpOptionMpTcp::GetSerializedSize (void) const
{
  return 2;
}

void
TcpOptionMpTcp::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  i.WriteU8 (GetKind ()); // Kind
  i.WriteU8 (2); // Length
  i.WriteU8 ( SUBTYPE << 4); // Subtype TODO should write U4 only

}

uint32_t
TcpOptionMpTcp::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  uint8_t size = i.ReadU8 ();
  NS_ASSERT (size == 2);
  return 2;
}

uint8_t
TcpOptionMpTcp::GetKind (void) const
{
    /* TODO ideally would refer to the enum in TcpOption::
    Hardcoded here to keep patch self-contained
    */
  return 30;
}

#endif



} // namespace ns3
