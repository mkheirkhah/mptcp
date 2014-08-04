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

#include "tcp-option-mss.h"

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (TcpOptionMSS);

TcpOptionMSS::TcpOptionMSS ()
  : TcpOption (),
    m_mss (1460)
{
}

TcpOptionMSS::~TcpOptionMSS ()
{
}

TypeId
TcpOptionMSS::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::TcpOptionMSS")
    .SetParent<TcpOption> ()
    .AddConstructor<TcpOptionMSS> ()
  ;
  return tid;
}

TypeId
TcpOptionMSS::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

void
TcpOptionMSS::Print (std::ostream &os) const
{
  os << m_mss;
}

uint32_t
TcpOptionMSS::GetSerializedSize (void) const
{
  return 4;
}

void
TcpOptionMSS::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  i.WriteU8 (GetKind ()); // Kind
  i.WriteU8 (4); // Length
  i.WriteHtonU16 (m_mss); // Max segment size
} 

uint32_t
TcpOptionMSS::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  uint8_t size = i.ReadU8 ();
  NS_ASSERT (size == 4);
  m_mss = i.ReadNtohU16 ();
  return 4;
}

uint8_t
TcpOptionMSS::GetKind (void) const
{
  return TcpOption::MSS;
}

uint16_t
TcpOptionMSS::GetMSS (void) const
{
  return m_mss;
}

void
TcpOptionMSS::SetMSS (uint16_t mss)
{
  m_mss = mss;
}

} // namespace ns3
