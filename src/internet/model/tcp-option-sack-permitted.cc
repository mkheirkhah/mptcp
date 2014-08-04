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

#include "tcp-option-sack-permitted.h"

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (TcpOptionSackPermitted);

TcpOptionSackPermitted::TcpOptionSackPermitted ()
    : TcpOption ()
{
}

TcpOptionSackPermitted::~TcpOptionSackPermitted ()
{
}

TypeId
TcpOptionSackPermitted::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::TcpOptionSackPermitted")
    .SetParent<TcpOption> ()
    .AddConstructor<TcpOptionSackPermitted> ()
  ;
  return tid;
}

TypeId
TcpOptionSackPermitted::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

void
TcpOptionSackPermitted::Print (std::ostream &os) const
{
}

uint32_t
TcpOptionSackPermitted::GetSerializedSize (void) const
{
  return 2;
}

void
TcpOptionSackPermitted::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  i.WriteU8 (GetKind ()); // Kind
  i.WriteU8 (2); // Length
} 

uint32_t
TcpOptionSackPermitted::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  uint8_t size = i.ReadU8 ();
  NS_ASSERT (size == 2);
  return 2;
}

uint8_t
TcpOptionSackPermitted::GetKind (void) const
{
  return TcpOption::SACK_PERM;
}

} // namespace ns3
