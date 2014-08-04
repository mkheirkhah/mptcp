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

#include "tcp-option-sack.h"

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (TcpOptionSack);

TcpOptionSack::TcpOptionSack ()
    : TcpOption ()
{
}

TcpOptionSack::~TcpOptionSack ()
{
}

TypeId
TcpOptionSack::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::TcpOptionSack")
    .SetParent<TcpOption> ()
    .AddConstructor<TcpOptionSack> ()
  ;
  return tid;
}

TypeId
TcpOptionSack::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

void
TcpOptionSack::Print (std::ostream &os) const
{
}

uint32_t
TcpOptionSack::GetSerializedSize (void) const
{
  return 2;
}

void
TcpOptionSack::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  i.WriteU8 (GetKind ()); // Kind
  i.WriteU8 (2); // Length
} 

uint32_t
TcpOptionSack::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  uint8_t size = i.ReadU8 ();
  NS_ASSERT (size == 2);
  return 2;
}

uint8_t
TcpOptionSack::GetKind (void) const
{
  return TcpOption::SACK;
}

void
TcpOptionSack::AddSack (SackBlock s)
{
  // Assumed s has no overlap with any SACK block in m_sb
  for (TcpOptionSack::ScoreBoard::iterator i = m_sb.begin (); i != m_sb.end (); ++i)
    {
      if (s.first < i->first)
        {
          m_sb.insert(i,s);
          break;
        }
    }
}

uint32_t
TcpOptionSack::SackCount (void) const
{
  return m_sb.size ();
}

void
TcpOptionSack::ClearSack (void)
{
  m_sb.clear ();
}

TcpOptionSack::SackBlock
TcpOptionSack::GetSack (int offset)
{
  TcpOptionSack::ScoreBoard::iterator i = m_sb.begin ();
  while (offset--) ++i;
  return *i;
}

} // namespace ns3
