/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2007 Georgia Tech Research Corporation
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
 * Author: Raj Bhattacharjea <raj.b@gatech.edu>
 */

#include <stdint.h>
#include <iostream>
#include "tcp-header.h"
#include "ns3/buffer.h"
#include "ns3/address-utils.h"
#include "ns3/log.h"

NS_LOG_COMPONENT_DEFINE ("TcpHeader");
//using namespace std;

namespace ns3
{

NS_OBJECT_ENSURE_REGISTERED(TcpHeader);

TcpHeader::TcpHeader() :
    m_sourcePort(0), m_destinationPort(0), m_sequenceNumber(0), m_ackNumber(0), m_length(5), m_flags(0), m_windowSize(0xffff), m_urgentPointer(
        0), m_calcChecksum(false), m_goodChecksum(true), m_option(0), oLen(0), pLen(0), original(true)
{
}

/*
 TcpHeader::~TcpHeader()
 {
 }
 */

void
TcpHeader::EnableChecksums(void)
{
  m_calcChecksum = true;
}

void
TcpHeader::SetSourcePort(uint16_t port)
{
  m_sourcePort = port;
}
void
TcpHeader::SetDestinationPort(uint16_t port)
{
  m_destinationPort = port;
}
void
TcpHeader::SetSequenceNumber(SequenceNumber32 sequenceNumber)
{
  m_sequenceNumber = sequenceNumber;
}
void
TcpHeader::SetAckNumber(SequenceNumber32 ackNumber)
{
  m_ackNumber = ackNumber;
}
void
TcpHeader::SetLength(uint8_t length)
{
  m_length = length;
}
void
TcpHeader::SetFlags(uint8_t flags)
{
  m_flags = flags;
}
void
TcpHeader::SetWindowSize(uint16_t windowSize)
{
  m_windowSize = windowSize;
}
void
TcpHeader::SetUrgentPointer(uint16_t urgentPointer)
{
  m_urgentPointer = urgentPointer;
}

uint16_t
TcpHeader::GetSourcePort() const
{
  return m_sourcePort;
}
uint16_t
TcpHeader::GetDestinationPort() const
{
  return m_destinationPort;
}
SequenceNumber32
TcpHeader::GetSequenceNumber() const
{
  return m_sequenceNumber;
}
SequenceNumber32
TcpHeader::GetAckNumber() const
{
  return m_ackNumber;
}
uint8_t
TcpHeader::GetLength() const
{
  return m_length;
}
uint8_t
TcpHeader::GetFlags() const
{
  return m_flags;
}
uint16_t
TcpHeader::GetWindowSize() const
{
  return m_windowSize;
}
uint16_t
TcpHeader::GetUrgentPointer() const
{
  return m_urgentPointer;
}

void
TcpHeader::InitializeChecksum(Ipv4Address source, Ipv4Address destination, uint8_t protocol)
{
  m_source = source;
  m_destination = destination;
  m_protocol = protocol;
}

void
TcpHeader::InitializeChecksum(Ipv6Address source, Ipv6Address destination, uint8_t protocol)
{
  m_source = source;
  m_destination = destination;
  m_protocol = protocol;
}

void
TcpHeader::InitializeChecksum(Address source, Address destination, uint8_t protocol)
{
  m_source = source;
  m_destination = destination;
  m_protocol = protocol;
}

uint16_t
TcpHeader::CalculateHeaderChecksum(uint16_t size) const
{
  /* Buffer size must be at least as large as the largest IP pseudo-header */
  /* [per RFC2460, but without consideration for IPv6 extension hdrs]      */
  /* Src address            16 bytes (more generally, Address::MAX_SIZE)   */
  /* Dst address            16 bytes (more generally, Address::MAX_SIZE)   */
  /* Upper layer pkt len    4 bytes                                        */
  /* Zero                   3 bytes                                        */
  /* Next header            1 byte                                         */

  uint32_t maxHdrSz = (2 * Address::MAX_SIZE) + 8;
  Buffer buf = Buffer(maxHdrSz);
  buf.AddAtStart(maxHdrSz);
  Buffer::Iterator it = buf.Begin();
  uint32_t hdrSize = 0;

  WriteTo(it, m_source);
  WriteTo(it, m_destination);
  if (Ipv4Address::IsMatchingType(m_source))
    {
      it.WriteU8(0); /* protocol */
      it.WriteU8(m_protocol); /* protocol */
      it.WriteU8(size >> 8); /* length */
      it.WriteU8(size & 0xff); /* length */
      hdrSize = 12;
    }
  else
    {
      it.WriteU16(0);
      it.WriteU8(size >> 8); /* length */
      it.WriteU8(size & 0xff); /* length */
      it.WriteU16(0);
      it.WriteU8(0);
      it.WriteU8(m_protocol); /* protocol */
      hdrSize = 40;
    }

  it = buf.Begin();
  /* we don't CompleteChecksum ( ~ ) now */
  return ~(it.CalculateIpChecksum(hdrSize));
}

bool
TcpHeader::IsChecksumOk(void) const
{
  return m_goodChecksum;
}

TypeId
TcpHeader::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::TcpHeader").SetParent<Header>().AddConstructor<TcpHeader>();
  return tid;
}

TypeId
TcpHeader::GetInstanceTypeId(void) const
{
  return GetTypeId();
}
/*
 void
 TcpHeader::Print(std::ostream &os) const
 {
 os << m_sourcePort << " > " << m_destinationPort;
 if (m_flags != 0)
 {
 os << " [";
 if ((m_flags & FIN) != 0)
 {
 os << " FIN ";
 }
 if ((m_flags & SYN) != 0)
 {
 os << " SYN ";
 }
 if ((m_flags & RST) != 0)
 {
 os << " RST ";
 }
 if ((m_flags & PSH) != 0)
 {
 os << " PSH ";
 }
 if ((m_flags & ACK) != 0)
 {
 os << " ACK ";
 }
 if ((m_flags & URG) != 0)
 {
 os << " URG ";
 }
 if ((m_flags & ECE) != 0)
 {
 os << " ECE ";
 }
 if ((m_flags & CWR) != 0)
 {
 os << " CWR ";
 }
 os << "]";
 }
 os << " Seq=" << m_sequenceNumber << " Ack=" << m_ackNumber << " Win=" << m_windowSize;
 }
 */

uint32_t
TcpHeader::GetSerializedSize(void) const
{
  return 4 * m_length;
}
void
TcpHeader::Print(std::ostream &os) const
{
  uint8_t flags = GetFlags();
  os << GetSourcePort() << " > " << GetDestinationPort();
  if (flags != 0)
    {
      os << " [";
      if ((flags & FIN) != 0)
        {
          os << " FIN ";
        }
      if ((flags & SYN) != 0)
        {
          os << " SYN ";
        }
      if ((flags & RST) != 0)
        {
          os << " RST ";
        }
      if ((flags & PSH) != 0)
        {
          os << " PSH ";
        }
      if ((flags & ACK) != 0)
        {
          os << " ACK ";
        }
      if ((flags & URG) != 0)
        {
          os << " URG ";
        }
      os << "]";
    }
  os << " Seq=" << GetSequenceNumber() << " Ack=" << GetAckNumber() << " Win=" << GetWindowSize();

  for (uint32_t j = 0; j < m_option.size(); j++)
    {
      os << " {";
      TcpOptions *opt = m_option[j];
      OptMultipathCapable *optMPC;
      //OptJoinConnection *optJOIN;
      //OptAddAddress *optADDR;
      //OptRemoveAddress *optREMADR;
      //OptDataSeqMapping *optDSN;
      //OptTimesTamp *optTT;

      //os << opt->optName;

      if (opt->optName == OPT_MPC)
        {
          os << "OPT_MPC(";
          optMPC = (OptMultipathCapable *) opt;
          os << optMPC->senderToken << ")";
        }
      else if (opt->optName == OPT_JOIN)
        {
          os << "OPT_JOIN";
//          optJOIN = (OptJoinConnection *) opt;
//          os << optJOIN->receiverToken;
//          os << optJOIN->addrID;
        }
      else if (opt->optName == OPT_ADDR)
        {
          os << "OPT_ADDR";
//          optADDR = (OptAddAddress *) opt;
//          os << optADDR->addrID;
//          optADDR->addr.Print(os);
        }
      else if (opt->optName == OPT_REMADR)
        {
          os << "OPT_REMADR";
//          optREMADR = (OptRemoveAddress *) opt;
//          os << optREMADR->addrID;
        }
      else if (opt->optName == OPT_DSN)
        {
          os << "OPT_DSN";
          //optDSN = (OptDataSeqMapping *) opt;
          //os << optDSN->dataSeqNumber;
          //os << optDSN->dataLevelLength;
          //os << optDSN->subflowSeqNumber;
        }
      else if (opt->optName == OPT_TT)
        {
          os << "OPT_TT";
//          optTT = (OptTimesTamp *) opt;
//          os << optTT->TSval;
//          os << optTT->TSecr;
        }
      else if (opt->optName == OPT_DSACK)
        {
          os << "OPT_DSACK";
//          OptDSACK* optDSACK = (OptDSACK *) opt;
//          os << optDSACK->blocks[0]; // left Edge  of the first block
//          os << optDSACK->blocks[1]; // right Edge of the first block
//          os << optDSACK->blocks[2]; // left Edge  of the second block
//          os << optDSACK->blocks[3]; // right Edge of the second block
        }
      os << "}";
    }

}

/*
 void
 TcpHeader::Serialize(Buffer::Iterator start) const
 {
 Buffer::Iterator i = start;
 i.WriteHtonU16(m_sourcePort);
 i.WriteHtonU16(m_destinationPort);
 i.WriteHtonU32(m_sequenceNumber.GetValue());
 i.WriteHtonU32(m_ackNumber.GetValue());
 i.WriteHtonU16(m_length << 12 | m_flags); //reserved bits are all zero
 i.WriteHtonU16(m_windowSize);
 i.WriteHtonU16(0);
 i.WriteHtonU16(m_urgentPointer);

 if (m_calcChecksum)
 {
 uint16_t headerChecksum = CalculateHeaderChecksum(start.GetSize());
 i = start;
 uint16_t checksum = i.CalculateIpChecksum(start.GetSize(), headerChecksum);

 i = start;
 i.Next(16);
 i.WriteU16(checksum);
 }
 }
 */

void
TcpHeader::Serialize(Buffer::Iterator start) const
{
  NS_LOG_FUNCTION(this);
  Buffer::Iterator i = start;
  i.WriteHtonU16(m_sourcePort);
  i.WriteHtonU16(m_destinationPort);
  i.WriteHtonU32(m_sequenceNumber.GetValue()); // WriteHtonU32(uint32_t) so use GetValue()
  i.WriteHtonU32(m_ackNumber.GetValue());      // WriteHtonU32(uint32_t) so use GetValue()
  i.WriteHtonU16(m_length << 12 | m_flags);    //reserved bits are all zero
  i.WriteHtonU16(m_windowSize);
  i.WriteHtonU16(0);
  i.WriteHtonU16(m_urgentPointer);

  if (m_calcChecksum)
    {
      uint16_t headerChecksum = CalculateHeaderChecksum(start.GetSize());
      i = start;
      uint16_t checksum = i.CalculateIpChecksum(start.GetSize(), headerChecksum);

      i = start;
      i.Next(16);
      i.WriteU16(checksum);
    }

  // write options in head
  for (uint32_t j = 0; j < m_option.size(); j++)
    {
      TcpOptions *opt = m_option[j];
      OptMultipathCapable *optMPC;
      OptJoinConnection *optJOIN;
      OptAddAddress *optADDR;
      OptRemoveAddress *optREMADR;
      OptDataSeqMapping *optDSN;
      OptTimesTamp *optTT;
      i.WriteU8(TcpOptionToUint(opt->optName));

      if (opt->optName == OPT_MPC)
        {
          optMPC = (OptMultipathCapable *) opt;
          i.WriteHtonU32(optMPC->senderToken);
        }
      else if (opt->optName == OPT_JOIN)
        {
          optJOIN = (OptJoinConnection *) opt;
          i.WriteHtonU32(optJOIN->receiverToken);
          i.WriteU8(optJOIN->addrID);
        }
      else if (opt->optName == OPT_ADDR)
        {
          optADDR = (OptAddAddress *) opt;
          i.WriteU8(optADDR->addrID);
          i.WriteHtonU32(optADDR->addr.Get());
        }
      else if (opt->optName == OPT_REMADR)
        {
          optREMADR = (OptRemoveAddress *) opt;
          i.WriteU8(optREMADR->addrID);
        }
      else if (opt->optName == OPT_DSN)
        {
          optDSN = (OptDataSeqMapping *) opt;
          i.WriteU64(optDSN->dataSeqNumber);
          i.WriteHtonU16(optDSN->dataLevelLength);
          i.WriteHtonU32(optDSN->subflowSeqNumber);
        }
      else if (opt->optName == OPT_TT) // Option TCP TimesTamp
        {
          optTT = (OptTimesTamp *) opt;
          i.WriteU64(optTT->TSval);
          i.WriteU64(optTT->TSecr);
        }
      else if (opt->optName == OPT_DSACK) // Option Duplicate SACK
        {
          OptDSACK *dsak = (OptDSACK *) opt;
          i.WriteU64(dsak->blocks[0]);  // left Edge  of the first block
          i.WriteU64(dsak->blocks[1]);  // right Edge  of the first block
          i.WriteU64(dsak->blocks[2]);  // left Edge  of the second block
          i.WriteU64(dsak->blocks[3]);  // right Edge  of the second block
//          NS_LOG_LOGIC(
//              "Serialize -> fstLeft (" << dsak->blocks[0] << ") fstRight (" << dsak->blocks[1] << ") sndLeft (" << dsak->blocks[2]
//                  << ") sndRight (" << dsak->blocks[3] << ")");
        }
    }
  for (int j = 0; j < (int) pLen; j++)
    i.WriteU8(255);
  NS_LOG_INFO("TcpHeader::Serialize options length  olen = " << (int) oLen);
  NS_LOG_INFO("TcpHeader::Serialize padding length  plen = " << (int) pLen);
}

/*
 uint32_t
 TcpHeader::Deserialize(Buffer::Iterator start)
 {
 Buffer::Iterator i = start;
 m_sourcePort = i.ReadNtohU16();
 m_destinationPort = i.ReadNtohU16();
 m_sequenceNumber = i.ReadNtohU32();
 m_ackNumber = i.ReadNtohU32();
 uint16_t field = i.ReadNtohU16();
 m_flags = field & 0x3F;
 m_length = field >> 12;
 m_windowSize = i.ReadNtohU16();
 i.Next(2);
 m_urgentPointer = i.ReadNtohU16();

 if (m_calcChecksum)
 {
 uint16_t headerChecksum = CalculateHeaderChecksum(start.GetSize());
 i = start;
 uint16_t checksum = i.CalculateIpChecksum(start.GetSize(), headerChecksum);
 m_goodChecksum = (checksum == 0);
 }

 return GetSerializedSize();
 }
 */

uint32_t
TcpHeader::Deserialize(Buffer::Iterator start)
{
  NS_LOG_FUNCTION(this);
  uint8_t hlen = 0;
  uint8_t plen = 0;
  Buffer::Iterator i = start;
  SetSourcePort(i.ReadNtohU16());
  SetDestinationPort(i.ReadNtohU16());
  SetSequenceNumber(SequenceNumber32(i.ReadNtohU32()));
  SetAckNumber(SequenceNumber32(i.ReadNtohU32()));
  uint16_t field = i.ReadNtohU16();
  SetFlags(field & 0x3F);
  hlen = (field >> 12);
  SetLength(hlen);
  SetWindowSize(i.ReadNtohU16());
  i.Next(2);
  SetUrgentPointer(i.ReadNtohU16());

  hlen = (hlen - 5) * 4;

  if (m_calcChecksum)
    {
      uint16_t headerChecksum = CalculateHeaderChecksum(start.GetSize());
      i = start;
      uint16_t checksum = i.CalculateIpChecksum(start.GetSize(), headerChecksum);
      m_goodChecksum = (checksum == 0);
    }

  // handle options field
  while (!i.IsEnd() && hlen > 0)
    {
      TcpOptions *opt;
      TcpOption_t kind = (TcpOption_t) i.ReadU8(); //TcpOption_t kind = UintToTcpOption(i.ReadU8());
      if (kind == OPT_MPC)
        {
          opt = new OptMultipathCapable(kind, i.ReadNtohU32());
          plen = (plen + 5) % 4;
          hlen -= 5;
        }
      else if (kind == OPT_JOIN)
        {
          opt = new OptJoinConnection(kind, i.ReadNtohU32(), i.ReadU8());
          plen = (plen + 6) % 4;
          hlen -= 6;
        }
      else if (kind == OPT_ADDR)
        {
          opt = new OptAddAddress(kind, i.ReadU8(), Ipv4Address(i.ReadNtohU32()));
          plen = (plen + 6) % 4;
          hlen -= 6;
        }
      else if (kind == OPT_REMADR)
        {
          opt = new OptRemoveAddress(kind, i.ReadU8());
          plen = (plen + 2) % 4;
          hlen -= 2;
        }
      else if (kind == OPT_DSN)
        {
          opt = new OptDataSeqMapping(kind, i.ReadU64(), i.ReadNtohU16(), i.ReadNtohU32());
          plen = (plen + 15) % 4;
          hlen -= 15;
        }
      else if (kind == OPT_TT)
        {
          opt = new OptTimesTamp(kind, i.ReadU64(), i.ReadU64());
          plen = (plen + 17) % 4;
          hlen -= 17;
        }
      else if (kind == OPT_DSACK)
        {
          OptDSACK *dsak = new OptDSACK(kind);
          uint64_t fstLeft = i.ReadU64(), fstRight = i.ReadU64();
          uint64_t sndLeft = i.ReadU64(), sndRight = i.ReadU64();
          dsak->AddfstBlock(fstLeft, fstRight);
          dsak->AddBlock(sndLeft, sndRight);
          opt = dsak;
          plen = (plen + 33) % 4;
          hlen -= 33;
        }
      else
        {
          // the rest are pending octets, so leave
          hlen = 0;
          break;
        }

      m_option.insert(m_option.end(), opt);

    }
  //i.Next(plen);
  NS_LOG_INFO("TcpHeader::Deserialize leaving this method plen" << plen);

  return GetSerializedSize();
}

//----------------------------------------
void
TcpHeader::SetOptionsLength(uint8_t length)
{
  oLen = length;
}

vector<TcpOptions*>
TcpHeader::GetOptions(void) const
{
  return m_option;
}

void
TcpHeader::SetOptions(vector<TcpOptions*> opt)
{
  m_option = opt;
}

uint8_t
TcpHeader::GetOptionsLength() const
{
  uint8_t length = 0;
  TcpOptions *opt;

  for (uint32_t j = 0; j < m_option.size(); j++)
    {
      opt = m_option[j];

      if (opt->optName == OPT_MPC)
        {
          length += 5;
        }
      else if (opt->optName == OPT_JOIN)
        {
          length += 6;
        }
      else if (opt->optName == OPT_ADDR)
        {
          length += 6;
        }
      else if (opt->optName == OPT_REMADR)
        {
          length += 2;
        }
      else if (opt->optName == OPT_DSN)
        {
          length += 15;
        }
    }
  //return oLen;
  return length;
}

void
TcpHeader::SetPaddingLength(uint8_t length)
{
  pLen = length;
}

uint8_t
TcpHeader::GetPaddingLength() const
{
  return pLen;
}

uint8_t
TcpHeader::TcpOptionToUint(TcpOption_t opt) const
{
  //NS_LOG_FUNCTION_NOARGS();
  uint8_t i = 0;

  if (opt == OPT_MPC)
    i = 30;
  else if (opt == OPT_JOIN)
    i = 31;
  else if (opt == OPT_ADDR)
    i = 32;
  else if (opt == OPT_REMADR)
    i = 33;
  else if (opt == OPT_DSN)
    i = 34;
  else if (opt == OPT_DSACK)
    i = 5;
  else if (opt == OPT_NONE)
    i = 0;
  else if (opt == OPT_TT)
    i = 8; // IANA value is 8
  return i;
}

TcpOption_t
TcpHeader::UintToTcpOption(uint8_t kind) const
{
  //NS_LOG_FUNCTION_NOARGS();
  TcpOption_t i = OPT_NONE;

  if (kind == 30)
    i = OPT_MPC;
  else if (kind == 31)
    i = OPT_JOIN;
  else if (kind == 32)
    i = OPT_ADDR;
  else if (kind == 33)
    i = OPT_REMADR;
  else if (kind == 34)
    i = OPT_DSN;
  else if (kind == 5)
    i = OPT_DSACK;
  else if (kind == 0)
    i = OPT_NONE;
  else if (kind == 8)
    i = OPT_TT; // IANA value is 8

  return i;
}


TcpHeader::TcpHeader(const TcpHeader &res)
{
  //NS_LOG_FUNCTION_NOARGS();
  SetSourcePort(res.GetSourcePort());
  SetDestinationPort(res.GetDestinationPort());
  SetFlags(res.GetFlags());
  SetSequenceNumber(res.GetSequenceNumber());
  SetAckNumber(res.GetAckNumber());
  SetWindowSize(res.GetWindowSize());
  //SetOptions         ( res.GetOptions () );
  SetLength(res.GetLength());
  SetOptionsLength(res.GetOptionsLength());
  SetPaddingLength(res.GetPaddingLength());
  SetOptions(res.GetOptions());
  original = false;
}
/*
 TcpHeader
 TcpHeader::Copy()
 {
 TcpHeader l4Header;
 //NS_LOG_FUNCTION_NOARGS();
 l4Header.SetSourcePort(GetSourcePort());
 l4Header.SetDestinationPort(GetDestinationPort());
 l4Header.SetFlags(GetFlags());
 l4Header.SetSequenceNumber(GetSequenceNumber());
 l4Header.SetAckNumber(GetAckNumber());
 l4Header.SetWindowSize(GetWindowSize());
 l4Header.SetOptions(GetOptions());
 l4Header.SetLength(GetLength());
 l4Header.SetOptionsLength(GetOptionsLength());
 l4Header.SetPaddingLength(GetPaddingLength());
 return l4Header;
 }
 */
TcpHeader::~TcpHeader()
{
  if (original == false)
    return;
  //NS_LOG_FUNCTION_NOARGS();
  for (uint32_t i = 0; i < m_option.size(); i++)
    {
      if (m_option[i] != 0)
        switch (m_option[i]->optName)
          {
        case OPT_MPC:
          delete (OptMultipathCapable*) m_option[i];
          break;
        case OPT_JOIN:
          delete (OptJoinConnection*) m_option[i];
          break;
        case OPT_ADDR:
          delete (OptAddAddress*) m_option[i];
          break;
        case OPT_REMADR:
          delete (OptRemoveAddress*) m_option[i];
          break;
        case OPT_DSN:
          delete (OptDataSeqMapping*) m_option[i];
          break;
        case OPT_TT:
          delete (OptTimesTamp*) m_option[i];
          break;
        default:
          break;
          }
    }
  m_option.clear();
  oLen = 0;
}

bool
TcpHeader::AddOptMPC(TcpOption_t optName, uint32_t TxToken)
{
//  NS_LOG_FUNCTION(this);
  if (optName == OPT_MPC)
    {
      OptMultipathCapable* opt = new OptMultipathCapable(optName, TxToken);

      m_option.insert(m_option.end(), opt);

      return true;
    }
  return false;
}

bool
TcpHeader::AddOptJOIN(TcpOption_t optName, uint32_t RxToken, uint8_t addrID)
{
//  NS_LOG_FUNCTION(this);
  if (optName == OPT_JOIN)
    {
      OptJoinConnection* opt = new OptJoinConnection(optName, RxToken, addrID);

      m_option.insert(m_option.end(), opt);
      return true;
    }
  return false;
}

bool
TcpHeader::AddOptADDR(TcpOption_t optName, uint8_t addrID, Ipv4Address addr)
{
//  NS_LOG_FUNCTION(this);
  if (optName == OPT_ADDR)
    {
      OptAddAddress* opt = new OptAddAddress(optName, addrID, addr);

      m_option.insert(m_option.end(), opt);
      return true;
    }
  return false;
}

bool
TcpHeader::AddOptREMADR(TcpOption_t optName, uint8_t addrID)
{
//  NS_LOG_FUNCTION(this);
  if (optName == OPT_REMADR)
    {
      OptRemoveAddress* opt = new OptRemoveAddress(optName, addrID);

      m_option.insert(m_option.end(), opt);
      return true;
    }
  return false;
}

bool
TcpHeader::AddOptDSN(TcpOption_t optName, uint64_t dSeqNum, uint16_t dLevelLength, uint32_t sfSeqNum)
{
//  NS_LOG_FUNCTION(this);
  if (optName == OPT_DSN)
    {
      OptDataSeqMapping* opt = new OptDataSeqMapping(optName, dSeqNum, dLevelLength, sfSeqNum);

      m_option.insert(m_option.end(), opt);
      return true;
    }
  return false;
}

bool
TcpHeader::AddOptTT(TcpOption_t optName, uint64_t tsval, uint64_t tsecr)
{
//  NS_LOG_FUNCTION(this);
  if (optName == OPT_TT)
    {
      OptTimesTamp* opt = new OptTimesTamp(optName, tsval, tsecr);

      m_option.insert(m_option.end(), opt);
      return true;
    }
  return false;
}

bool
TcpHeader::AddOptDSACK(TcpOption_t optName, OptDSACK *ptrDSAK)
{
//  NS_LOG_FUNCTION(this);
  if (optName == OPT_DSACK)
    {
      m_option.insert(m_option.end(), ptrDSAK);
      return true;
    }
  return false;
}
//-----------------------------------------------------------------
}// namespace ns3
