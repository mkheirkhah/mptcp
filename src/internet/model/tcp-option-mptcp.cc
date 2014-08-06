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


/**
\note This is a global MPTCP option logger
*/
NS_LOG_COMPONENT_DEFINE("TcpOptionMpTcp");
//NS_LOG_COMPONENT_DEFINE("TcpOptionMpTcpCapable");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (TcpOptionMpTcpCapable);
NS_OBJECT_ENSURE_REGISTERED (TcpOptionMpTcpAddAddress );
NS_OBJECT_ENSURE_REGISTERED (TcpOptionMpTcpRemoveAddress );
NS_OBJECT_ENSURE_REGISTERED (TcpOptionMpTcpJoinInitialSyn );



/////////////////////////////////////////////////////////
////////  MP_CAPABLE
/////////////////////////////////////////////////////////
TcpOptionMpTcpCapable::TcpOptionMpTcpCapable()
    : TcpOptionMpTcp (),
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
  TcpOptionMpTcp::SerializeRef(i);

  i.WriteU8 ( (GetSubType () << 4) + (0x0f & GetVersion()) ); // Kind
  i.WriteU8 ( m_flags ); // Length
  i.WriteHtonU64( GetLocalKey() );
  i.WriteHtonU64( GetPeerKey() );
}

uint32_t
TcpOptionMpTcpCapable::Deserialize (Buffer::Iterator start)
{
  TcpOptionMpTcp::Deserialize(start);
  return 2;
}

uint32_t
TcpOptionMpTcpCapable::GetSerializedSize (void) const
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
  TcpOptionMpTcp::SerializeRef(i);
  i.WriteU8( GetSubType() << 4 );
  i.WriteU8( GetAddressId() );
  i.WriteHtonU32( GetPeerToken() );
  i.WriteHtonU32( GetLocalToken() );
  // la je continue a sérialiser
}

uint32_t
TcpOptionMpTcpJoinInitialSyn::Deserialize (Buffer::Iterator start)
{
  TcpOptionMpTcp::Deserialize(start);
  return 2;
}

// OK
uint32_t
TcpOptionMpTcpJoinInitialSyn::GetSerializedSize (void) const
{
    return 12;
}

///////////////////////////////////////:
//// MP_JOIN SYN_ACK
////
TcpOptionMpTcpJoinSynReceived::TcpOptionMpTcpJoinSynReceived()
    : TcpOptionMpTcp (),
    m_pathId(0),
    m_receiverToken(0),
    m_senderToken(0)
{
  NS_LOG_FUNCTION(this);
}

TcpOptionMpTcpJoinSynReceived::~TcpOptionMpTcpJoinSynReceived ()
{
}


void
TcpOptionMpTcpJoinSynReceived::Print (std::ostream &os) const
{
  os << "MP_Join Initial Syn" << ";" << m_pathId;
}

void
TcpOptionMpTcpJoinSynReceived::Serialize (Buffer::Iterator start) const
{
  TcpOptionMpTcp::SerializeRef(start);

  // la je continue a sérialiser
}

uint32_t
TcpOptionMpTcpJoinSynReceived::Deserialize (Buffer::Iterator start)
{
  TcpOptionMpTcp::Deserialize(start);
  return 2;
}

uint32_t
TcpOptionMpTcpJoinSynReceived::GetSerializedSize (void) const
{
    return 24;
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
  TcpOptionMpTcp::SerializeRef(start);

  // la je continue a sérialiser
}

uint32_t
TcpOptionMpTcpJoinSynAckReceived::Deserialize (Buffer::Iterator start)
{
  TcpOptionMpTcp::Deserialize(start);
  return 2;
}

uint32_t
TcpOptionMpTcpJoinSynAckReceived::GetSerializedSize (void) const
{
    return 24;
}





///////////////////////////////////////:
//// MP_JOIN SYN_ACK
////
TcpOptionMpTcpDSN::TcpOptionMpTcpDSN() :
  TcpOptionMpTcp()
//  ,m_dataSequenceNumber(0),
//  m_subflowSequenceNumber(0),
//  m_dataLevelLength(0)
{
  NS_LOG_FUNCTION(this);
}


TcpOptionMpTcpDSN::~TcpOptionMpTcpDSN()
{

}

void
TcpOptionMpTcpDSN::Serialize (Buffer::Iterator i) const
{
  //
  TcpOptionMpTcp::SerializeRef(i);
  i.WriteHtonU64( GetMapping().GetDataSequenceNumber().GetValue() );
  i.WriteHtonU32( GetMapping().GetSubflowSequenceNumber().GetValue() );
  i.WriteHtonU16( GetMapping().GetDataLevelLength() );
  i.WriteHtonU16( 0 );  // Padding
}

void
TcpOptionMpTcpDSN::SetMapping(MpTcpMapping mapping)
{
  m_mapping = mapping;
}

MpTcpMapping
TcpOptionMpTcpDSN::GetMapping( ) const
{
  return m_mapping;
}

uint32_t
TcpOptionMpTcpDSN::GetSerializedSize() const
{
  return 16;
}

void
TcpOptionMpTcpDSN::Print(std::ostream& os) const
{
  os << "MPTCP option DSN mapping";
}

uint32_t
TcpOptionMpTcpDSN::Deserialize (Buffer::Iterator start)
{
  return 0;
}

//void
//TcpOptionMpTcpDSN::Configure(uint64_t dataSeqNb, uint32_t subflowSeqNb, uint16_t dataLength)
//{
//  m_dataSequenceNumber = dataSeqNb;
//  m_subflowSequenceNumber = subflowSeqNb;
//  m_dataLevelLength = dataLength;
//}



///////////////////////////////////////:
//// ADD_ADDR
////
TcpOptionMpTcpAddAddress::TcpOptionMpTcpAddAddress() :
  TcpOptionMpTcp(),
//  m_length(4),
  m_addressVersion(0),
  m_addrId(0),
  m_port(0)
{
  NS_LOG_LOGIC(this);
}

TcpOptionMpTcpAddAddress::~TcpOptionMpTcpAddAddress()
{
}

void
TcpOptionMpTcpAddAddress::SetAddress(InetSocketAddress address, uint8_t addrId)
{
  m_address = address.GetIpv4();
  m_port = address.GetPort();
  m_addrId  = addrId;
//  m_length = 10;
  m_addressVersion = 4;
}

//void
//TcpOptionMpTcpAddAddress::SetAddress(Ipv6Address address)
//{
//  m_address6 = address;
//  m_addressVersion = 6;
////  m_length = 26;
//}


void
TcpOptionMpTcpAddAddress::Print (std::ostream &os) const
{
  os << "MP ADD_ADDR: " << m_addrId;
//  if( GetSerializedSize() == 4)
//  {
//    os << addrId;
//  }
}

void
TcpOptionMpTcpAddAddress::GetAddress( InetSocketAddress& address) const
{
  address.SetIpv4( m_address);
  address.SetPort( m_port );

}

//virtual uint8_t GetAddress(Address& address) const;

//void
//TcpOptionMpTcpAddAddress::SetAddressId(uint8_t addrId)
//{
//  m_addrId = addrId;
////  m_length = 4;
//}

uint8_t
TcpOptionMpTcpAddAddress::GetAddressId() const
{
  return m_addrId;
}

void
TcpOptionMpTcpAddAddress::Serialize (Buffer::Iterator i) const
{
//  Buffer::Iterator i = start;
  TcpOptionMpTcp::SerializeRef(i);


  i.WriteU8( (GetSubType() << 4) + (uint8_t) m_addressVersion );
  i.WriteU8( m_addrId );

  if(m_addressVersion == 4)
  {
//    i.WriteHtonU32( m_address.GetIpv4().Get() );
    i.WriteHtonU32( m_address.Get() );
  }
  else
  {
    NS_ASSERT_MSG(m_addressVersion==6, "You should set an IP address before serializing MPTCP option ADD_ADDR");

    uint8_t  	buf[16];
//    m_address6.GetIpv6().GetBytes( buf );
    m_address6.GetBytes( buf );
    for(int j = 0; j < 16; ++j)
    {
      i.WriteU8( buf[j] );
    }
    NS_LOG_INFO(this <<  "Got bytes from ipv6");
  }

  i.WriteU8(m_port);
}


//bool
//TcpOptionMpTcpAddAddress::EmbeddedAddressId()
//{
//  return ( GetSerializedSize() == 4);
//}

uint32_t
TcpOptionMpTcpAddAddress::Deserialize (Buffer::Iterator start)
{
  return 0;
}

uint32_t
TcpOptionMpTcpAddAddress::GetSerializedSize (void) const
{
  if(m_addressVersion == 4)
  {
    return 4;
  }

  NS_ASSERT_MSG(m_addressVersion == 6,"Wrong IP version. Maybe you didn't set an address to the MPTCP ADD_ADDR option ?");
  return 6;
}


///////////////////////////////////////:
//// DEL_ADDR change priority
////

TcpOptionMpTcpRemoveAddress::TcpOptionMpTcpRemoveAddress() :
  TcpOptionMpTcp()
//  ,m_addrId(0)
{
  //
  NS_LOG_LOGIC(this);
}


TcpOptionMpTcpRemoveAddress::~TcpOptionMpTcpRemoveAddress()
{
  //
}


void
TcpOptionMpTcpRemoveAddress::GetAddresses(std::vector<uint8_t>& addresses)
{
  addresses = m_addressesId;
}


void
TcpOptionMpTcpRemoveAddress::AddAddressId( uint8_t addrId )
{
  m_addressesId.push_back( addrId );
}


void
TcpOptionMpTcpRemoveAddress::Serialize (Buffer::Iterator i) const
{
//  Buffer::Iterator i = start;
  TcpOptionMpTcp::SerializeRef(i);

  i.WriteU8( (GetSubType() << 4) );
  for(
      std::vector<uint8_t>::const_iterator it = m_addressesId.begin();
        it != m_addressesId.end();
        it++
        )
  {
    i.WriteU8( *it );
  }
}

uint32_t
TcpOptionMpTcpRemoveAddress::Deserialize (Buffer::Iterator start)
{
  return 0;
}

uint32_t
TcpOptionMpTcpRemoveAddress::GetSerializedSize (void) const
{
  return ( 3 + m_addressesId.size() );
}

void
TcpOptionMpTcpRemoveAddress::Print (std::ostream &os) const
{
  os << "REMOVE_ADDR option ";

}


///////////////////////////////////////:
//// MP_PRIO change priority
////
TcpOptionMpTcpChangePriority::TcpOptionMpTcpChangePriority() :
  TcpOptionMpTcp(),
  m_length(3),
  m_addrId(0),
  m_backupFlag(false)
{
}

void
TcpOptionMpTcpChangePriority::Print (std::ostream &os) const
{
  os << "MP_Prio: Change priority to " << m_backupFlag;
  if( GetSerializedSize() == 4)
  {
    os << m_addrId;
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
TcpOptionMpTcpChangePriority::Serialize (Buffer::Iterator i) const
{
//  Buffer::Iterator i = start;
  TcpOptionMpTcp::SerializeRef(i);

  i.WriteU8( (GetSubType() << 4) + (uint8_t)m_backupFlag );
  if( EmbeddedAddressId() )
    i.WriteU8( m_addrId );
}

uint32_t
TcpOptionMpTcpChangePriority::Deserialize (Buffer::Iterator start)
{
  return 0;
}

uint32_t
TcpOptionMpTcpChangePriority::GetSerializedSize (void) const
{
  return m_length;
}


bool
TcpOptionMpTcpChangePriority::EmbeddedAddressId() const
{
  return ( GetSerializedSize() == 4);
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
