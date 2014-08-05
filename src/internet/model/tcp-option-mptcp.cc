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
#include "ns3/log.h"


NS_LOG_COMPONENT_DEFINE("TcpOptionMpTcpJoin");
NS_LOG_COMPONENT_DEFINE("TcpOptionMpTcpCapable");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (TcpOptionMpTcpCapable);
//NS_OBJECT_ENSURE_REGISTERED (TcpOptionMpTcpJoin);



/////////////////////////////////////////////////////////
////////  MP_CAPABLE
/////////////////////////////////////////////////////////
TcpOptionMpTcpCapable::TcpOptionMpTcpCapable()
    : TcpOptionMpTcp<MP_CAPABLE> (),
    m_version(0),
    m_flags( HMAC_SHA1 ),
    m_senderKey(0),
    m_remoteKey(0)
{
}

TcpOptionMpTcpCapable::~TcpOptionMpTcpCapable ()
{
}


void
TcpOptionMpTcpCapable::SetSenderKey(uint64_t senderKey)
{
  NS_LOG_FUNCTION(this);
  m_senderKey = senderKey;
}

void
TcpOptionMpTcpCapable::SetRemoteKey(uint64_t remoteKey)
{
  NS_LOG_FUNCTION(this);
  m_remoteKey = remoteKey;
}

void
TcpOptionMpTcpCapable::Print (std::ostream &os) const
{
  os << "MP_CAPABLE. version" << m_version
    << "Flags:" << m_flags
    << "Sender's Key [" << GetLocalKey() << "]"
    << "Peer's Key [" << GetPeerKey() << "]"
    ;
}

bool
TcpOptionMpTcpCapable::IsChecksumRequired() const
{
  return ( m_flags >> 7);
}

void
TcpOptionMpTcpCapable::Serialize (Buffer::Iterator i) const
{
//  Buffer::Iterator i = start;
  TcpOptionMpTcp<MP_CAPABLE>::SerializeRef(i);

  i.WriteU8 ( (GetSubType () << 4) + (0x0f & GetVersion()) ); // Kind
  i.WriteU8 ( m_flags ); // Length
  i.WriteHtonU64( GetLocalKey() );
  i.WriteHtonU64( GetPeerKey() );
}

uint32_t
TcpOptionMpTcpCapable::Deserialize (Buffer::Iterator start)
{
  TcpOptionMpTcp<MP_CAPABLE>::Deserialize(start);
  return 2;
}

uint8_t
TcpOptionMpTcpCapable::GetLength (void) const
{
    return (2+0);
}



/////////////////////////////////////////////////////////
////////  MP_JOIN Initial SYN
/////////////////////////////////////////////////////////
TcpOptionMpTcpJoinInitialSyn::TcpOptionMpTcpJoinInitialSyn()
    : TcpOptionMpTcp (),
    m_addressId(0),
    m_peerToken(0),
    m_localToken(0)
{
  NS_LOG_FUNCTION(this);
}

TcpOptionMpTcpJoinInitialSyn::~TcpOptionMpTcpJoinInitialSyn ()
{
}


void
TcpOptionMpTcpJoinInitialSyn::Print (std::ostream &os) const
{
  os << "MP_Join Initial Syn" << ";";
}

void
TcpOptionMpTcpJoinInitialSyn::Serialize (Buffer::Iterator i) const
{
  TcpOptionMpTcp<MP_JOIN>::SerializeRef(i);
  i.WriteU8( GetSubType() << 4 );
  i.WriteU8( GetAddressId() );
  i.WriteHtonU32( GetPeerToken() );
  i.WriteHtonU32( GetLocalToken() );
  // la je continue a sérialiser
}

uint32_t
TcpOptionMpTcpJoinInitialSyn::Deserialize (Buffer::Iterator start)
{
  TcpOptionMpTcp<MP_JOIN>::Deserialize(start);
  return 2;
}

// OK
uint8_t
TcpOptionMpTcpJoinInitialSyn::GetLength (void) const
{
    return 12;
}

///////////////////////////////////////:
//// MP_JOIN SYN_ACK
////
TcpOptionMpTcpJoinSynAckReceived::TcpOptionMpTcpJoinSynAckReceived()
    : TcpOptionMpTcp (),
    m_pathId(0),
    m_receiverToken(0),
    m_senderToken(0)
{
  NS_LOG_FUNCTION(this);
}

TcpOptionMpTcpJoinSynAckReceived::~TcpOptionMpTcpJoinSynAckReceived ()
{
}


void
TcpOptionMpTcpJoinSynAckReceived::Print (std::ostream &os) const
{
  os << "MP_Join Initial Syn" << ";" << m_pathId;
}

void
TcpOptionMpTcpJoinSynAckReceived::Serialize (Buffer::Iterator start) const
{
  TcpOptionMpTcp<MP_JOIN>::Serialize(start);

  // la je continue a sérialiser
}

uint32_t
TcpOptionMpTcpJoinSynAckReceived::Deserialize (Buffer::Iterator start)
{
  TcpOptionMpTcp<MP_JOIN>::Deserialize(start);
  return 2;
}

uint8_t
TcpOptionMpTcpJoinSynAckReceived::GetLength (void) const
{
    return 24;
}



///////////////////////////////////////:
//// MP_JOIN SYN_ACK
////
TcpOptionMpTcpDSN::TcpOptionMpTcpDSN() :
  TcpOptionMpTcp(),
  m_dataSequenceNumber(0),
  m_subflowSequenceNumber(0),
  m_dataLevelLength(0)
{
  NS_LOG_FUNCTION(this);
}

void
TcpOptionMpTcpDSN::Serialize (Buffer::Iterator i) const
{
  //
  TcpOptionMpTcp<DSS>::SerializeRef(i);
  i.WriteHtonU64( GetDataSequenceNumber() );
  i.WriteHtonU32( GetSubflowSequenceNumber() );
  i.WriteHtonU16( GetDataLevelLength() );
  i.WriteHtonU16( 0 );  // Padding
}


//TcpOptionMpTcpDSN::~TcpOptionMpTcpDSN()
//{
//
//}


void
TcpOptionMpTcpDSN::Configure(uint64_t dataSeqNb, uint32_t subflowSeqNb, uint16_t dataLength)
{
  m_dataSequenceNumber = dataSeqNb;
  m_subflowSequenceNumber = subflowSeqNb;
  m_dataLevelLength = dataLength;
}





///////////////////////////////////////:
//// MP_PRIO change priority
////
TcpOptionMpTcpChangePriority::TcpOptionMpTcpChangePriority() :
  TcpOption(),
  m_length(3),
  m_backupFlag(false)
{
}

void
TcpOptionMpTcpChangePriority::Print (std::ostream &os) const
{
  os << "MP_Prio: Change priority to " << m_backupFlag;
  if( GetLength() == 4)
  {
    os << addrId;
  }
}

void
TcpOptionMpTcpChangePriority::SetAddressId(uint8_t addrId)
{
  m_addrId = addrId;
  m_length = 4;
}

bool
TcpOptionMpTcpChangePriority::GetAddressId(uint8_t& addrId) const
{
  if( !EmbeddedAddressId() )
    return false;

  addrId = m_addrId;
  return true;
}

void
TcpOptionMpTcpChangePriority::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  TcpOptionMpTcp::SerializeRef(i);

  i.WriteU8( (GetSubType() << 4) + (uint8_t)m_backupFlag );
  if( EmbeddedAddressId() )
    i.WriteU8( addrId );
}


bool
TcpOptionMpTcpChangePriority::EmbeddedAddressId()
{
  return ( GetLength() == 4);
}

uint32_t
TcpOptionMpTcpChangePriority::Deserialize (Buffer::Iterator start)
{

}

uint8_t
TcpOptionMpTcpChangePriority::GetLength (void) const
{
  return m_length;
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
