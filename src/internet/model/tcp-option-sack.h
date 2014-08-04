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

#ifndef TCP_OPTION_SACK_H
#define TCP_OPTION_SACK_H

#include "tcp-option.h"
#include "ns3/sequence-number.h"

namespace ns3 {

/**
 * Defines the TCP option of kind 5 (Selective Acknowledgement) as in RFC2018
 */

class TcpOptionSack : public TcpOption
{
public:
  TcpOptionSack ();
  virtual ~TcpOptionSack ();

  typedef std::pair<SequenceNumber32, SequenceNumber32> SackBlock;
  typedef std::list<SackBlock> ScoreBoard;

  static TypeId GetTypeId (void);
  virtual TypeId GetInstanceTypeId (void) const;

  virtual void Print (std::ostream &os) const;
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);

  virtual uint8_t GetKind (void) const;
  virtual uint32_t GetSerializedSize (void) const;

  void AddSack (SackBlock s);
  uint32_t SackCount (void) const;

  void ClearSack (void);
  SackBlock GetSack (int offset);
protected:
  ScoreBoard m_sb;
};

} // namespace ns3

#endif /* TCP_OPTION_SACK_H */
