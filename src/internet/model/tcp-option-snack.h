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

#ifndef TCP_OPTION_SNACK_H
#define TCP_OPTION_SNACK_H

#include "tcp-option.h"
#include "ns3/sequence-number.h"

namespace ns3 {

/**
 * Defines the TCP option of kind 21 (Selective Negative Acknowledgement)
 */

class TcpOptionSnack : public TcpOption
{
public:
  TcpOptionSnack ();
  virtual ~TcpOptionSnack ();

  typedef std::pair<SequenceNumber32, SequenceNumber32> SnackBlock;
  typedef std::list<SnackBlock> ScoreBoard;

  static TypeId GetTypeId (void);
  virtual TypeId GetInstanceTypeId (void) const;

  virtual void Print (std::ostream &os) const;
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);

  virtual uint8_t GetKind (void) const;
  virtual uint32_t GetSerializedSize (void) const;

  void AddSnack (SnackBlock s);
  uint32_t SnackCount (void) const;
  void ClearSnack (void);
  SnackBlock GetSnack (int offset);
protected:
  ScoreBoard m_sb;
};

} // namespace ns3

#endif /* TCP_OPTION_SNACK_H */
