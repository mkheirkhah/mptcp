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
//
//NS_OBJECT_ENSURE_REGISTERED (TcpOptionMpTcpCapable);
//NS_OBJECT_ENSURE_REGISTERED (TcpOptionMpTcpAddAddress );
//NS_OBJECT_ENSURE_REGISTERED (TcpOptionMpTcpRemoveAddress );
//NS_OBJECT_ENSURE_REGISTERED (TcpOptionMpTcpJoinInitialSyn );
//NS_OBJECT_ENSURE_REGISTERED ( TcpOptionMpTcpChangePriority );
NS_OBJECT_ENSURE_REGISTERED ( TcpOptionMpTcpMain );
//NS_OBJECT_ENSURE_REGISTERED (TcpOptionMpTcp<DSS> );


/////////////////////////////////////////////////////////
////////  Base for MPTCP options
/////////////////////////////////////////////////////////
TcpOptionMpTcpMain::TcpOptionMpTcpMain() :
  TcpOption()
{
  NS_LOG_FUNCTION(this);
}


TcpOptionMpTcpMain::~TcpOptionMpTcpMain()
{
  NS_LOG_FUNCTION(this);
}

TypeId
TcpOptionMpTcpMain::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::TcpOptionMpTcpMain")
    .SetParent<TcpOption> ()
    //
//    .AddConstructor<TcpOptionMpTcpMain> ()
  ;
//  NS_LOG_UNCOND("TcpOptionMpTcpMain::GetTypeId called !");
  return tid;
}


TypeId
TcpOptionMpTcpMain::GetInstanceTypeId (void) const
{
//  NS_LOG_UNCOND("TcpOptionMpTcpMain::GetInstanceTypeId called");
  return GetTypeId ();
}


void
TcpOptionMpTcpMain::Print (std::ostream &os) const
{
    NS_ASSERT_MSG(false, " You should override TcpOptionMpTcp::Print function");
//    os << "MPTCP option. You should override";
}



std::string
TcpOptionMpTcpMain::SubTypetoString(uint8_t flags, char delimiter)
{
  //
  static const char* flagNames[8] = {
    //"NONE",
    "CAPABLE",
    "JOIN",
    "DSS",
    "ADD_ADDR",
    "REM_ADDR",
    "CHANGE_PRIORITY",
    "MP_FAIL",
    "MP_FASTCLOSE"
  };

  std::string flagsDescription = "";

  for(int i = 0; i < 8; ++i)
  {
    if( flags & (1 << i) )
    {
      if(flagsDescription.length() > 0) flagsDescription += delimiter;
      flagsDescription.append( flagNames[i] );

    }
  }
  return flagsDescription;
}


Ptr<TcpOption>
TcpOptionMpTcpMain::CreateMpTcpOption(uint8_t subtype)
{
  switch(subtype)
  {
    case MP_CAPABLE:
      return CreateObject<TcpOptionMpTcpCapable>();

    case MP_JOIN:
      // TODO merge the 3 options
      return CreateObject<TcpOptionMpTcpJoin>();

    case MP_DSS:
      return CreateObject<TcpOptionMpTcpDSS>();
    case MP_FAIL:
    case MP_FASTCLOSE:
      NS_ASSERT_MSG(false,"Unsupported MPTCP options. Implement them !" );

//      return CreateObject<TcpOptionMpTcp>();
      break;

    case MP_PRIO:
      return CreateObject<TcpOptionMpTcpChangePriority>();
    case MP_REMOVE_ADDR:
      return CreateObject<TcpOptionMpTcpChangePriority>();

    default:
      NS_ASSERT_MSG(false,"Unsupported MPTCP suboption");
  };

  return 0;
}

void
TcpOptionMpTcpMain::SerializeRef (Buffer::Iterator& i) const
{
//    Buffer::Iterator& i = start;
    i.WriteU8 (GetKind ()); // Kind
    i.WriteU8 ( GetSerializedSize() ); // Length


    // TODO may be an error otherwise here !

//    i.WriteU8 ( ( (GetSubType() << 4 ) && 0xf0) ); // Subtype TODO should write U4 only
    //i.WriteU8 ( GetSerializedSize() ); // Subtype TODO should write U4 only

}



/////////////////////////////////////////////////////////
////////  MP_CAPABLE
/////////////////////////////////////////////////////////
TcpOptionMpTcpCapable::TcpOptionMpTcpCapable()
    : TcpOptionMpTcp (),
    m_version(0),
    m_flags( HMAC_SHA1 ),
    m_senderKey(0),
    m_remoteKey(0),
    m_length(12)
{
  NS_LOG_FUNCTION(this);
}

TcpOptionMpTcpCapable::~TcpOptionMpTcpCapable ()
{
  NS_LOG_FUNCTION_NOARGS();
}


bool
TcpOptionMpTcpCapable::operator==(const TcpOptionMpTcpCapable& opt) const
{
  return (GetPeerKey() == opt.GetPeerKey() && GetSenderKey() == opt.GetSenderKey() );
}


void
TcpOptionMpTcpCapable::SetSenderKey(const uint64_t& senderKey)
{
  NS_LOG_FUNCTION(this);
  m_senderKey = senderKey;
}

void
TcpOptionMpTcpCapable::SetRemoteKey(const uint64_t& remoteKey)
{
  NS_LOG_FUNCTION(this);
  m_length = 20;
  m_remoteKey = remoteKey;
}

void
TcpOptionMpTcpCapable::Print (std::ostream &os) const
{
  os << "MP_CAPABLE. version" << m_version
    << "MPTCP Flags: [" << m_flags << "]"
    << "Sender's Key :[" << GetSenderKey() << "]"
    << "Peer's Key [";
  if( HasReceiverKey() )
    os  << GetPeerKey();
  else
    os << "None";
  os << "]";

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
  i.WriteHtonU64( GetSenderKey() );
  if( HasReceiverKey() )
  {
    i.WriteHtonU64( GetPeerKey() );
  }
}

uint32_t
TcpOptionMpTcpCapable::Deserialize (Buffer::Iterator i)
{

  uint32_t length =  (uint32_t)i.ReadU8( );

  NS_ASSERT( length == 12 || length == 20 );
  //NS_ABORT_UNLESS

  uint8_t subtype_and_version = i.ReadU8();
  NS_ASSERT( subtype_and_version >> 4 == GetSubType()  );
  m_flags = i.ReadU8();

  SetSenderKey( i.ReadNtohU64() );

  if( length == 20)
  {
    SetRemoteKey( i.ReadNtohU64() );
  }
  return length;
}

uint32_t
TcpOptionMpTcpCapable::GetSerializedSize (void) const
{
  // 12 or 20
    return (m_length);
}




/////////////////////////////////////////////////////////
////////  MP_JOIN Initial SYN
/////////////////////////////////////////////////////////
TcpOptionMpTcpJoin::TcpOptionMpTcpJoin()
    : TcpOptionMpTcp (),
    m_state(Uninitialized),
    m_addressId(0),
    m_flags(0)
//    m_peerToken(0),
//    m_nonce(0)
{
  NS_LOG_FUNCTION(this);

  // TODO Generate a random number
//  m_nonce = 3232;
}

TcpOptionMpTcpJoin::~TcpOptionMpTcpJoin ()
{
  NS_LOG_FUNCTION(this);
}

void
TcpOptionMpTcpJoin::SetPeerToken(uint32_t token)
{
  NS_ASSERT( m_state & Syn);
  m_buffer[0] = token;
}

void
TcpOptionMpTcpJoin::Print (std::ostream &os) const
{
  os << "MP_JOIN: " ;
  switch(m_state)
  {
    case Uninitialized:
      os << "Uninitialized";
      return ;

    case Syn:
      os << "[Syn] with token [" << GetPeerToken() << "], nonce [" << GetNonce() << "]";
      return;

    case SynAck:
      os << "[SynAck] with nonce [" << GetNonce() << "]";
      return;


    case Ack:
      //TODO compare hash etc..
      os << "[Ack] with hash [" << "TODO" << "]";
      return;
  };
}

void
TcpOptionMpTcpJoin::SetAddressId(uint8_t addrId)
{
  NS_ASSERT(m_state & (SynAck | Ack) );
  m_addressId =  addrId;
}




uint32_t
TcpOptionMpTcpJoin::GetPeerToken() const
{
  NS_ASSERT(m_state & Syn );
  return m_buffer[0];
}



void
TcpOptionMpTcpJoin::SetState(State s)
{
  NS_ASSERT(m_state == Uninitialized);
  m_state = s;
//  m_buffer.AddAtStart(s);
//  return ( m_state == state);
}

uint8_t
TcpOptionMpTcpJoin::GetAddressId() const
{
  NS_ASSERT(m_state & (SynAck | Ack) );
  return m_addressId;
}

bool
TcpOptionMpTcpJoin::operator==(const TcpOptionMpTcpJoin& opt) const
{
//  NS_ASSERT(m_state & (SynAck | Ack) );
//  bool result = false;
  if( m_state != opt.m_state) return false;

  switch(m_state)
  {
    case Uninitialized:
      return true;

    case Syn:
      return (
        GetPeerToken() == opt.GetPeerToken()
        && GetNonce() == opt.GetNonce()
    //    && GetLocalToken() == opt.GetLocalToken()
        && GetAddressId() == opt.GetAddressId()
        );



    case SynAck:
      return (
          GetNonce() == opt.GetNonce()
//          && GetTruncatedHmac() == opt.GetTruncatedHmac()
          && GetAddressId()  == opt.GetAddressId()
          );


    case Ack:
      //TODO compare hash etc..
      return true;
  };

  NS_ASSERT_MSG(false, "Contact ns3 team");
  return false;
}

uint32_t
TcpOptionMpTcpJoin::GetNonce() const
{
  NS_ASSERT(m_state & (Syn | SynAck) );
  return m_buffer[0];
}

void
TcpOptionMpTcpJoin::SetNonce(uint32_t nonce)
{
//  NS_ASSERT(m_state & () Syn);
  if(m_state == Syn)
    m_buffer[1] = nonce;
  else if(m_state == SynAck)
    m_buffer[2] = nonce;
  else
    NS_ASSERT(false);
}


void
TcpOptionMpTcpJoin::Serialize (Buffer::Iterator i) const
{
  TcpOptionMpTcp::SerializeRef(i);
  i.WriteU8( GetSubType() << 4 );
  if(m_state & (Syn | SynAck) )
    i.WriteU8( GetAddressId() );
  else
    i.WriteU8( 0 );

  switch( m_state )
  {
    case Uninitialized:
      NS_ASSERT_MSG(false,"Can't");

    case Syn:
      i.WriteHtonU32( GetPeerToken() );
      i.WriteHtonU32( GetNonce() );
      break;

    case SynAck:
      {
        uint64_t hmac = GetTruncatedHmac();
//        temp ;
        i.WriteHtonU64(hmac);
      }
      i.WriteHtonU32( GetNonce() );
      break;

    case Ack:
      // +=4 cos amount of bytes we write
      for(int j = 0; j < m_state/4-1; j++)
      {
        i.WriteHtonU32( m_buffer[j]);
      }
      break;
  }


// CopyData
//  CreateFragment

//  i.Write( m_buffer.Begin(), m_buffer.End() );
  // la je continue a sérialiser
}

const uint8_t*
TcpOptionMpTcpJoin::GetHmac() const
{
  NS_ASSERT(m_state == Ack);
  //  i.Read( &m_hmac[0], 20);
//  m_buffer.Read();
//  return &m_hmac[0];
  return 0;
};


uint32_t
TcpOptionMpTcpJoin::Deserialize (Buffer::Iterator i)
{
  NS_ASSERT(m_state == Uninitialized);

//  TcpOptionMpTcp::Deserialize(start);
  uint32_t length = (uint32_t) i.ReadU8();
//  NS_ASSERT( length == 12);

  uint8_t subtype_and_flags = i.ReadU8()  ;
  NS_ASSERT( (subtype_and_flags >> 4) == GetSubType() );

  // 4 because first line of
  m_state = static_cast<State>( length );
//  m_buffer.AddAtBegin(m_state);

  m_addressId = i.ReadU8();

  switch( m_state )
  {
    case Uninitialized:
      NS_ASSERT_MSG(false, "" );

    case Syn:
//      m_buffer.Write()
      // TODO copy to buffer?
      SetPeerToken( i.ReadNtohU32() );
      SetNonce(  i.ReadNtohU32() );
      break;

    case SynAck:
      SetTruncatedHmac( i.ReadNtohU64() );
      SetNonce(i.ReadNtohU32() );  // read nonce
      break;

    case Ack:
      i.Read( (uint8_t*)&m_buffer, 20);
      break;
  };




  return m_state;
}

void
TcpOptionMpTcpJoin::SetHmac(uint8_t hmac[20])
{
  //
//  std::copy(hmac, hmac+20,m_hmac);
}


//void
//TcpOptionMpTcpJoin::SetAddressId(uint8_t addrId)
//{
//  NS_ASSERT_MSG( m_state != Ack, "Not usable in state ack" );
//  m_addressId =  addrId;
//}
// OK
uint32_t
TcpOptionMpTcpJoin::GetSerializedSize (void) const
{
  NS_ASSERT(m_state != Uninitialized);

  return (m_state);
}

void
TcpOptionMpTcpJoin::SetTruncatedHmac(uint64_t hmac)
{
  NS_ASSERT_MSG(m_state == SynAck,"Wrong state");
  m_buffer[0] = hmac >> 32;
  m_buffer[1] = (hmac);
}

uint64_t
TcpOptionMpTcpJoin::GetTruncatedHmac() const
{
  NS_ASSERT_MSG(m_state == SynAck,"Wrong state");
  uint64_t temp = 0;
  temp = m_buffer[0] ;
  temp = temp << 32;
  temp |= m_buffer[1] ;

  return temp;
};

#if 0


void
TcpOptionMpTcpJoinInitialSyn::Serialize (Buffer::Iterator i) const
{
  TcpOptionMpTcp::SerializeRef(i);
  i.WriteU8( GetSubType() << 4 );
  i.WriteU8( GetAddressId() );
  i.WriteHtonU32( GetPeerToken() );
  i.WriteHtonU32( m_nonce );
  // la je continue a sérialiser
}

uint32_t
TcpOptionMpTcpJoinInitialSyn::Deserialize (Buffer::Iterator i)
{
//  TcpOptionMpTcp::Deserialize(start);
  uint32_t length = (uint32_t) i.ReadU8();
  NS_ASSERT( length == 12);

  uint8_t subtype_and_flags = i.ReadU8()  ;
  NS_ASSERT( (subtype_and_flags >> 4) == GetSubType() );

  SetAddressId( i.ReadU8());
  SetPeerToken( i.ReadNtohU32() );
  m_nonce = i.ReadNtohU32();
  return 12;
}





///////////////////////////////////////:
//// MP_JOIN SYN_ACK
////
TcpOptionMpTcpJoinSynReceived::TcpOptionMpTcpJoinSynReceived()
    : TcpOptionMpTcp (),
    m_addressId(0),
    m_flags(0),
    m_truncatedHmac(0),
    m_nonce(0)
{
  NS_LOG_FUNCTION(this);
}

TcpOptionMpTcpJoinSynReceived::~TcpOptionMpTcpJoinSynReceived ()
{
//  NS_LOG_FUNCTION_NOARGS();
  NS_LOG_FUNCTION(this);
}


void
TcpOptionMpTcpJoinSynReceived::SetNonce(uint32_t nonce)
{
  m_nonce = nonce;
}

void
TcpOptionMpTcpJoinSynReceived::Print (std::ostream &os) const
{
  os << "MP_Join Initial Syn" << ";" << m_addressId;
}

bool
TcpOptionMpTcpJoinSynReceived::operator==(const TcpOptionMpTcpJoinSynReceived& opt) const
{
  return (
      GetNonce() == opt.GetNonce()
      && GetTruncatedHmac() == opt.GetTruncatedHmac()
      && GetAddressId()  == opt.GetAddressId()
      )
      ;
}

void
TcpOptionMpTcpJoinSynReceived::SetTruncatedHmac(uint64_t hmac)
{
  // TODO truncate from real hmac ?
  m_truncatedHmac = hmac;
}

void
TcpOptionMpTcpJoinSynReceived::Serialize (Buffer::Iterator i) const
{
  TcpOptionMpTcp::SerializeRef(i);
  i.WriteU8( GetSubType() << 4 );
  i.WriteU8( GetAddressId() );

  i.WriteHtonU64( GetTruncatedHmac() );
  i.WriteHtonU32( m_nonce );

  // la je continue a sérialiser
}



uint32_t
TcpOptionMpTcpJoinSynReceived::Deserialize (Buffer::Iterator i)
{
  uint32_t length = (uint32_t) i.ReadU8();
  NS_ASSERT( length == 16);

  uint8_t subtype_and_flags = i.ReadU8()  ;
  NS_ASSERT( (subtype_and_flags >> 4) == GetSubType() );

  SetAddressId( i.ReadU8() );
  m_truncatedHmac = i.ReadNtohU64();

  m_nonce = i.ReadNtohU32();

  return length;
}

uint32_t
TcpOptionMpTcpJoinSynReceived::GetSerializedSize (void) const
{
    return 16;
}

///////////////////////////////////////:
//// MP_JOIN SYN_ACK
////
TcpOptionMpTcpJoinSynAckReceived::TcpOptionMpTcpJoinSynAckReceived()
    : TcpOptionMpTcp ()
//    m_(0),
//    m_receiverToken(0),
//    m_senderToken(0)
{
  NS_LOG_FUNCTION(this);
}

TcpOptionMpTcpJoinSynAckReceived::~TcpOptionMpTcpJoinSynAckReceived ()
{
  NS_LOG_FUNCTION(this); // Use this ?
}


void
TcpOptionMpTcpJoinSynAckReceived::SetHmac(uint8_t hmac[20])
{
  //
  std::copy(hmac, hmac+20,m_hmac);
}


bool
TcpOptionMpTcpJoinSynAckReceived::operator==(const TcpOptionMpTcpJoinSynAckReceived&) const
{
  // TODO compare 2 arrays
  return true;
}

void
TcpOptionMpTcpJoinSynAckReceived::Print (std::ostream &os) const
{
  os << "MP_Join SynAck received";
}

void
TcpOptionMpTcpJoinSynAckReceived::Serialize (Buffer::Iterator i) const
{
//  TcpOptionMpTcp::SerializeRef(start);
  TcpOptionMpTcp::SerializeRef(i);
  i.WriteU8( GetSubType() << 4 );
  i.WriteU8( 0 ); // Reserved

  // TODO write sender's HMAC
  i.Write(&m_hmac[0], 20);
//  i.WriteHtonU64( 0  );
//  i.WriteHtonU64( 0  );
//  i.WriteHtonU32( 0 );

}

uint32_t
TcpOptionMpTcpJoinSynAckReceived::Deserialize (Buffer::Iterator i)
{
  uint32_t length =  (uint32_t)i.ReadU8( );

  NS_ASSERT( length == 24 );
  //NS_ABORT_UNLESS

  uint8_t subtype_and_rsvd = i.ReadU8();
  NS_ASSERT( subtype_and_rsvd >> 4 == GetSubType()  );
  i.ReadU8(); // reserved

  // Retrieve HMAC
  i.Read( &m_hmac[0], 20);
//  i.ReadNtohU64();
//  i.ReadNtohU64();
//  i.ReadNtohU32();

  return length;
}

uint32_t
TcpOptionMpTcpJoinSynAckReceived::GetSerializedSize (void) const
{
    return 24;
}
#endif





///////////////////////////////////////:
//// MP_JOIN SYN_ACK
////
TcpOptionMpTcpDSS::TcpOptionMpTcpDSS() :
  TcpOptionMpTcp(),
  m_flags(0),
  m_dataAck(0)
//  ,m_dataSequenceNumber(0),
//  m_subflowSequenceNumber(0),
//  m_dataLevelLength(0)
{
  NS_LOG_FUNCTION(this);
}


TcpOptionMpTcpDSS::~TcpOptionMpTcpDSS()
{
  NS_LOG_FUNCTION(this);
}

void
TcpOptionMpTcpDSS::SetMapping(MpTcpMapping mapping)
{
  m_mapping = mapping;
  m_flags |= DSNMappingPresent;
//  m_flags |= DSNMappingPresent;
}

MpTcpMapping
TcpOptionMpTcpDSS::GetMapping(void) const
{
  return m_mapping;
}

uint32_t
TcpOptionMpTcpDSS::GetSerializedSize(void) const
{
  uint32_t length = 4;
//  4 + 4 + 4 +2 +2;

  if( m_flags & DataAckPresent)
  {
    length += 4;
    if( m_flags & DataAckOf8Bytes)  length += 4;

  }

  if( m_flags & DSNMappingPresent)
  {
    length += 12;
    if( m_flags & DSNOfEightBytes)  length += 4;
  }

//  NS_LOG_UNCOND( "size " << length);

  return length;
}

void
TcpOptionMpTcpDSS::Print(std::ostream& os) const
{
//  static
  os << "MP_DSS: ";
  //Flags [" << GetFlags() << "]";
  if(GetFlags() & DataAckPresent)
  {
    os << "Acknowledges [" << GetDataAck() << "]";
    if(GetFlags() & DataAckOf8Bytes){
      os << "(8bytes DACK)";
    }
  }

  if(GetFlags() & DSNMappingPresent)
  {
    os << "DSN:" << GetMapping();
    if(GetFlags() & DSNOfEightBytes){
      os << "(8bytes mapping)";
    }
  }
//      << "Data seq [" << GetDataAck() << "]"
//      << "Mapping size [" << GetMapping().GetDataLevelLength()
//      << "] Associated to subflow seq nb [" << GetMapping().GetSSN() << "]"
      ;
}

//uint32_t GetDataAck() const { return m_dataAck; };

void
TcpOptionMpTcpDSS::Serialize (Buffer::Iterator i) const
{
  //
  TcpOptionMpTcp::SerializeRef(i);
  i.WriteU8( GetSubType() << 4);
  i.WriteU8( m_flags );

  if( m_flags & DataAckPresent)
  {
//    NS_LOG_INFO("Serializing DataAck");
    if( m_flags & DataAckOf8Bytes)
    {
      // Not implemented
      NS_LOG_ERROR("Not implemented");
    }
    else
    {
      i.WriteHtonU32( m_dataAck );
    }
  }

  if( m_flags & DSNMappingPresent)
  {
//    NS_LOG_INFO("Serializing DSN mapping");
    if( m_flags & DSNOfEightBytes)
    {
      // Not implemented
      NS_LOG_ERROR("Not implemented");
    }
    else
    {
      i.WriteHtonU32( m_mapping.GetDSN().GetValue() );
    }
    i.WriteHtonU32( GetMapping().GetSSN().GetValue() );
    i.WriteHtonU16( GetMapping().GetDataLevelLength() );
    i.WriteHtonU16( 0 );  // Checksum
  }

  //  i.WriteHtonU64( GetMapping().GetDSN().GetValue() );

}


uint32_t
TcpOptionMpTcpDSS::Deserialize (Buffer::Iterator i)
{
  uint32_t length =  (uint32_t)i.ReadU8( );


  // 4
  // +4   or  + 8
  // +12 or + 16
  NS_ASSERT( (length % 4) == 0 && length <= 28);
//    length == 4 // if it's 4, it doesn't carry anything :/
//    || length== 8 || length == 12   // Only carries DataAck
//    || length == 16 || length == 20 // Only carries DSN mapping
//    || length ==
//    26


  uint8_t subtype_and_reserved = i.ReadU8();
//  NS_LOG_UNCOND("subtype " << (int)subtype_and_reserved << "compared to REAL one" << (int)GetSubType() );
  NS_ASSERT( (subtype_and_reserved >> 4) == GetSubType()  );
  m_flags = i.ReadU8();

//  NS_LOG_INFO ("Deserialized flags " << (int)m_flags);
  if( m_flags & DataAckPresent)
  {
//    NS_LOG_INFO("Deserializing DataAck");
    if( m_flags & DataAckOf8Bytes)
    {
      // Not implemented
      NS_LOG_ERROR("Not implemented");
    }
    else
    {
      m_dataAck = i.ReadNtohU32 ( );
    }
  }

  // Read mapping
  if(m_flags & DSNMappingPresent)
  {
//    NS_LOG_INFO("Deserializing DSN mapping");

    uint32_t dataSeqNb(0);
    uint16_t dataLevelLength(0);

    if( m_flags & DSNOfEightBytes)
    {
      // Not implemented
      NS_LOG_ERROR("Not implemented");
    }
    else
    {
       dataSeqNb = i.ReadNtohU32( );
    }
    m_mapping.MapToSSN( SequenceNumber32(i.ReadNtohU32())  );

    dataLevelLength = i.ReadNtohU16();

    m_mapping.Configure( SequenceNumber32(dataSeqNb ), dataLevelLength);
  }



  return length;

}

void
TcpOptionMpTcpDSS::SetDataAck(uint32_t dataAck)
{
  m_dataAck = dataAck;
  m_flags |= DataAckPresent;
}

bool
TcpOptionMpTcpDSS::operator==(const TcpOptionMpTcpDSS& opt) const
{
  //!
  return (m_flags == opt.m_flags
      && GetMapping() == opt.GetMapping()
      && GetDataAck() == opt.GetDataAck()
    );
}

//void
//TcpOptionMpTcpDSS::Configure(uint64_t dataSeqNb, uint32_t subflowSeqNb, uint16_t dataLength)
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
  m_addressVersion(0),
  m_addrId(0)
{
  NS_LOG_FUNCTION(this);
}

TcpOptionMpTcpAddAddress::~TcpOptionMpTcpAddAddress()
{
  NS_LOG_FUNCTION(this);

}

void
TcpOptionMpTcpAddAddress::SetAddress(const Address& _address, uint8_t addrId)
{
  if(InetSocketAddress::IsMatchingType(_address) )
  {
    m_addressVersion = 4;
    InetSocketAddress address =  InetSocketAddress::ConvertFrom(_address);
    m_address = address.GetIpv4();
//    m_address6 = address6.GetIpv6();
    m_port = address.GetPort();
  }
  else
  {
    NS_ASSERT_MSG(Inet6SocketAddress::IsMatchingType(_address), "Address of unsupported type");
    m_addressVersion = 6;
    Inet6SocketAddress address6 =  Inet6SocketAddress::ConvertFrom(_address);
    m_address6 = address6.GetIpv6();
    m_port = address6.GetPort();
  }

  m_addrId  = addrId;
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
  os << "MP_ADD_ADDR: address id [" << GetAddressId() << "]"
    << " associated to IP [";
  if(m_addressVersion == 4)
  {
    os << m_address;
  }
  else {
    os << m_address6;
  }
  os << "]";
//  if( GetSerializedSize() == 4)
//  {
//    os << addrId;
//  }
}

InetSocketAddress
TcpOptionMpTcpAddAddress::GetAddress() const
{
  NS_ASSERT(m_addressVersion == 4);
  return InetSocketAddress(m_address, m_port);
}


Inet6SocketAddress
TcpOptionMpTcpAddAddress::GetAddress6() const
{
  NS_ASSERT(m_addressVersion == 6);
  return Inet6SocketAddress(m_address6,m_port);
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

  NS_ASSERT_MSG(m_addressVersion == 4 || m_addressVersion == 6, "Set an IP before serializing");

//  uint8_t addressVersion = 0;
//  InetSocketAddress address;
//  Inet6SocketAddress address6;

//  if(InetSocketAddress::IsMatchingType(m_address) )
//  {
//    addressVersion = 4;
//    address_v4 =  InetSocketAddress::ConvertFrom(m_address);
//  }
//  else if( Inet6SocketAddress::IsMatchingType(m_address) )
//  {
//    addressVersion = 6;
//    address6 =  Inet6SocketAddress::ConvertFrom(m_address);
//  }
//  else
//  {
//    NS_ABORT_MSG("Address of wrong type");
//  }

  i.WriteU8( (GetSubType() << 4) + (uint8_t) m_addressVersion );
  i.WriteU8( GetAddressId() );


  if(m_addressVersion == 4)
  {
//    i.WriteHtonU32( m_address.GetIpv4().Get() );
    i.WriteHtonU32( m_address.Get() );
//    i.WriteU8(m_address.GetPort());
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
//    NS_LOG_INFO(this <<  "Got bytes from ipv6");
//    i.WriteU8(m_address.GetPort());
  }

  i.WriteU8(m_port);
}


//bool
//TcpOptionMpTcpAddAddress::EmbeddedAddressId()
//{
//  return ( GetSerializedSize() == 4);
//}

uint32_t
TcpOptionMpTcpAddAddress::Deserialize (Buffer::Iterator i)
{
  uint32_t length =  (uint32_t)i.ReadU8( );

  NS_ASSERT( length == 10
//      || length == 8
//      || length == 20
      || length==22
      );
  //NS_ABORT_UNLESS

  uint8_t subtype_and_ipversion = i.ReadU8();
  NS_ASSERT( subtype_and_ipversion >> 4 == GetSubType()  );

  m_addressVersion = subtype_and_ipversion  & 0x0f;
  NS_ASSERT_MSG(m_addressVersion == 4 || m_addressVersion == 6, "Unsupported address version");

  m_addrId =  i.ReadU8();

//  SetSenderKey( i.ReadNtohU64() );

  if( m_addressVersion == 4)
  {
    m_address.Set ( i.ReadNtohU32() );
  }
  else
  {
    // ipv6
    NS_FATAL_ERROR("IPv6 not supported yet");
//    m_address6.Set( );
  }
  return length;
}

uint8_t
TcpOptionMpTcpAddAddress::GetAddressVersion(void) const
{
  return m_addressVersion;
}

uint32_t
TcpOptionMpTcpAddAddress::GetSerializedSize (void) const
{
  if( GetAddressVersion() == 4)
  {
    return  10;
  }

  NS_ASSERT_MSG( GetAddressVersion()  == 6,"Wrong IP version. Maybe you didn't set an address to the MPTCP ADD_ADDR option ?");
  return 22;
}


bool
TcpOptionMpTcpAddAddress::operator==(const TcpOptionMpTcpAddAddress& opt) const
{
  return (GetAddressId() == opt.GetAddressId()
    && m_address == opt.m_address
    && m_address6 == opt.m_address6
//    && m_port == opt.m_port

  );
}


///////////////////////////////////////:
//// DEL_ADDR change priority
////

TcpOptionMpTcpRemoveAddress::TcpOptionMpTcpRemoveAddress() :
  TcpOptionMpTcp()
//  ,m_addrId(0)
{
  //
  NS_LOG_FUNCTION(this);
}


TcpOptionMpTcpRemoveAddress::~TcpOptionMpTcpRemoveAddress()
{
  //
  NS_LOG_FUNCTION(this);
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
TcpOptionMpTcpRemoveAddress::Deserialize (Buffer::Iterator i)
{
  uint32_t length =  (uint32_t)i.ReadU8( );

  NS_ASSERT_MSG( length > 3,"You probably forgot to add AddrId to the MPTCP Remove option");
  //NS_ABORT_UNLESS

  uint8_t subtype_and_resvd = i.ReadU8();
  NS_ASSERT( subtype_and_resvd >> 4 == GetSubType()  );
//  m_flags = i.ReadU8();
//
//  SetSenderKey( i.ReadNtohU64() );
  m_addressesId.clear();
  for(uint32_t j = 3; j < length; ++j)
  {
    m_addressesId.push_back( i.ReadU8() );
  }

  return length;

}

uint32_t
TcpOptionMpTcpRemoveAddress::GetSerializedSize (void) const
{
  return ( 3 + m_addressesId.size() );
}

void
TcpOptionMpTcpRemoveAddress::Print (std::ostream &os) const
{
  os << "MP_REMOVE_ADDR. Removing addresses:";
  for(
      std::vector<uint8_t>::const_iterator it = m_addressesId.begin();
        it != m_addressesId.end();
        it++
        )
  {
    os << *it << "/";
  }
}

bool
TcpOptionMpTcpRemoveAddress::operator==(const TcpOptionMpTcpRemoveAddress& opt) const
{
  return (m_addressesId == opt.m_addressesId);

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
  NS_LOG_FUNCTION(this);
}

void
TcpOptionMpTcpChangePriority::Print (std::ostream &os) const
{
  os << "MP_Prio: Change priority of address with id [";

  if( GetSerializedSize() == 4)
  {
    os << m_addrId;
  }
  os << "] to flags ["  << m_backupFlag << "]";
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
  TcpOptionMpTcp::SerializeRef(i);

  i.WriteU8( (GetSubType() << 4) + (uint8_t)m_backupFlag );
  if( EmbeddedAddressId() )
    i.WriteU8( m_addrId );
}


uint32_t
TcpOptionMpTcpChangePriority::Deserialize (Buffer::Iterator i)
{
  uint32_t length =  (uint32_t)i.ReadU8( );

  NS_ASSERT( length == 3 || length == 4 );
  //NS_ABORT_UNLESS

  uint8_t subtype_and_backup = i.ReadU8();
  NS_ASSERT( subtype_and_backup >> 4 == GetSubType()  );
  m_backupFlag = subtype_and_backup & 0x0f;

  if( length == 4)
  {
    SetAddressId( i.ReadU8() );
  }

  return m_length;
}

uint32_t
TcpOptionMpTcpChangePriority::GetSerializedSize (void) const
{
  return m_length;
}


//
//TypeId
//TcpOptionMpTcpChangePriority::GetTypeId (void)
//{
//  static TypeId tid = TypeId ("ns3::TcpOptionMpTcpChangePriority")
////    .SetParent<TcpOptionMpTcpMain> ()
//    .SetParent<TcpOptionMpTcp> ()
//    .AddConstructor<TcpOptionMpTcpChangePriority> ()
//  ;
//  return tid;
//}
//
//TypeId
//TcpOptionMpTcpChangePriority::GetInstanceTypeId (void) const
//{
//  return GetTypeId ();
//}


bool
TcpOptionMpTcpChangePriority::EmbeddedAddressId() const
{
  return ( GetSerializedSize() == 4);
}

bool
TcpOptionMpTcpChangePriority::operator==(const TcpOptionMpTcpChangePriority& opt) const
{

  return (
    GetPriority() == opt.GetPriority()
//    && GetAddressId() ==
    && m_addrId == opt.m_addrId
    );
}




///////////////////////////////////////////////////
//// MP_FASTCLOSE to totally stop a flow of data
////
TcpOptionMpTcpFastClose::TcpOptionMpTcpFastClose() :
  TcpOptionMpTcp(),
  m_peerKey(0)
{
  NS_LOG_FUNCTION(this);
}


void
TcpOptionMpTcpFastClose::SetPeerKey(const uint64_t& remoteKey)
{
  m_peerKey = remoteKey;
}


void
TcpOptionMpTcpFastClose::Print (std::ostream &os) const
{
//  TcpOptionMpTcpMain::Print(os);
  os << "MP_FastClose: Receiver key set to ["
    << GetPeerKey() << "]";
}

bool
TcpOptionMpTcpFastClose::operator==(const TcpOptionMpTcpFastClose& opt) const
{

  return (
    GetPeerKey() == opt.GetPeerKey()

    );
}


void
TcpOptionMpTcpFastClose::Serialize (Buffer::Iterator i) const
{
  TcpOptionMpTcp::SerializeRef(i);

  i.WriteU8( (GetSubType() << 4) + (uint8_t)0 );
  i.WriteHtonU64( GetPeerKey() );
}


uint32_t
TcpOptionMpTcpFastClose::Deserialize (Buffer::Iterator i)
{
  uint32_t length =  (uint32_t)i.ReadU8( );

  NS_ASSERT( length == 12 );
  //NS_ABORT_UNLESS

  uint8_t subtype_and_backup = i.ReadU8();
  NS_ASSERT( subtype_and_backup >> 4 == GetSubType()  );
//  m_backupFlag = subtype_and_backup & 0x0f;

  SetPeerKey( i.ReadNtohU64() );

  return 12;
}

uint32_t
TcpOptionMpTcpFastClose::GetSerializedSize (void) const
{
  return 12;
}

///////////////////////////////////////////////////
//// MP_FASTCLOSE to totally stop a flow of data
////
TcpOptionMpTcpFallback::TcpOptionMpTcpFallback() :
  TcpOptionMpTcp(),
  m_dsn(0)
{
  NS_LOG_FUNCTION(this);
}


void
TcpOptionMpTcpFallback::SetDSN(const uint64_t& dsn)
{
  m_dsn = dsn;
}


void
TcpOptionMpTcpFallback::Print (std::ostream &os) const
{
//  TcpOptionMpTcpMain::Print(os);
  os << "MP_FastClose: Receiver key set to ["
    << GetDSN() << "]";
}

bool
TcpOptionMpTcpFallback::operator==(const TcpOptionMpTcpFallback& opt) const
{

  return (
    GetDSN() == opt.GetDSN()

    );
}


void
TcpOptionMpTcpFallback::Serialize (Buffer::Iterator i) const
{
  TcpOptionMpTcp::SerializeRef(i);

  i.WriteU8( (GetSubType() << 4) + (uint8_t)0 );
  i.WriteHtonU64( GetDSN() );
}


uint32_t
TcpOptionMpTcpFallback::Deserialize (Buffer::Iterator i)
{
  uint32_t length =  (uint32_t)i.ReadU8( );

  NS_ASSERT( length == 12 );
  //NS_ABORT_UNLESS

  uint8_t subtype_and_backup = i.ReadU8();
  NS_ASSERT( subtype_and_backup >> 4 == GetSubType()  );
//  m_backupFlag = subtype_and_backup & 0x0f;

  SetDSN( i.ReadNtohU64() );

  return 12;
}

uint32_t
TcpOptionMpTcpFallback::GetSerializedSize (void) const
{
  return 12;
}



} // namespace ns3
