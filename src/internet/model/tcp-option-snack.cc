/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014 Natale Patriciello
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
 * Author: Natale Patriciello <natale.patriciello@gmail.com>
 */

#include "tcp-option-snack.h"

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (TcpOptionSnack);

TcpOptionSnack::TcpOptionSnack ()
    : TcpOption ()
{
}

TcpOptionSnack::~TcpOptionSnack ()
{
}

TypeId
TcpOptionSnack::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::TcpOptionSnack")
    .SetParent<TcpOption> ()
    .AddConstructor<TcpOptionSnack> ()
  ;
  return tid;
}

TypeId
TcpOptionSnack::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

void
TcpOptionSnack::Print (std::ostream &os) const
{
}

uint32_t
TcpOptionSnack::GetSerializedSize (void) const
{
  return 2;
}

void
TcpOptionSnack::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  i.WriteU8 (GetKind ()); // Kind
  i.WriteU8 (2); // Length
} 

uint32_t
TcpOptionSnack::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  uint8_t size = i.ReadU8 ();
  NS_ASSERT (size == 2);
  return 2;
}

uint8_t
TcpOptionSnack::GetKind (void) const
{
  return TcpOption::SNACK;
}

void
TcpOptionSnack::AddSnack (SnackBlock s)
{
  // Assumed s has no overlap with any SNACK block in m_sb
  for (TcpOptionSnack::ScoreBoard::iterator i = m_sb.begin (); i != m_sb.end (); ++i)
    {
      if (s.first < i->first)
        {
          m_sb.insert(i,s);
          break;
        }
    }
}

uint32_t
TcpOptionSnack::SnackCount (void) const
{
  return m_sb.size ();
}

void
TcpOptionSnack::ClearSnack (void)
{
  m_sb.clear ();
}

TcpOptionSnack::SnackBlock
TcpOptionSnack::GetSnack (int offset)
{
  TcpOptionSnack::ScoreBoard::iterator i = m_sb.begin ();
  while (offset--) ++i;
  return *i;
}

} // namespace ns3
