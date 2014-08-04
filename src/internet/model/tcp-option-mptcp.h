
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
 * Author: Matthieu Coudron <matthieu.coudron@lip6.fr>
 */

#ifndef TCP_OPTION_MPTCP_PERMITTED_H
#define TCP_OPTION_MPTCP_PERMITTED_H

#include "tcp-option.h"

namespace ns3 {

/**
 * Defines the TCP option of kind 30 (Multipath TCP) as in RFC6824
http://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
 0x0 	MP_CAPABLE 	Multipath Capable
0x1 	MP_JOIN 	Join Connection
0x2 	DSS 	Data Sequence Signal (Data ACK and data sequence mapping)
0x3 	ADD_ADDR 	Add Address
0x4 	REMOVE_ADDR 	Remove Address
0x5 	MP_PRIO 	Change Subflow Priority
0x6 	MP_FAIL 	Fallback
0x7 	MP_FASTCLOSE 	Fast Close
0xf 	(PRIVATE) 	Private Use within controlled testbe
 */

  enum SubType {
    MP_CAPABLE,
    MP_JOIN,
    DSS,
    ADD_ADDR,
    REMOVE_ADDR,
    MP_PRIO,
    MP_FAIL,
    MP_FASTCLOSE
  };

// TODO transofrmer en template
template<unsigned int SUBTYPE>
class TcpOptionMpTcp : public TcpOption
{
public:

  TcpOptionMpTcp () : TcpOption () {};
  virtual ~TcpOptionMpTcp () {};





  static TypeId GetTypeId (void)
  {
    static TypeId tid = TypeId ("ns3::TcpOptionMpTcp")
      .SetParent<TcpOption> ()
  //    .AddConstructor<TcpOptionMpTcp> ()
    ;
    return tid;
  }


  virtual TypeId GetInstanceTypeId (void) const
{
  return GetTypeId ();
}
  virtual void Print (std::ostream &os) const {
  }
  virtual void Serialize (Buffer::Iterator start) const
  {
    Buffer::Iterator i = start;
    i.WriteU8 (GetKind ()); // Kind
    i.WriteU8 (2); // Length

    // TODO may be an error otherwise here !

    i.WriteU8 ( ( (GetSubType() << 4 ) && 0xf0) + (GetLength() && 0x0f)  ); // Subtype TODO should write U4 only
    //i.WriteU8 ( GetLength() ); // Subtype TODO should write U4 only

  }

  virtual uint32_t Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  uint8_t size = i.ReadU8 ();
  NS_ASSERT (size == 2);
  return 2;
}

  virtual uint8_t GetLength (void) const {
    return 2;
  };

  virtual uint8_t GetKind (void) const
  {
    /* TODO ideally would refer to the enum in TcpOption::
    Hardcoded here to keep patch self-contained
    */
  return 30;
}


  virtual uint32_t GetSerializedSize (void) const
{
  return 2;
}


  virtual uint8_t GetSubType (void) const {
    return SUBTYPE;
  };

protected:

};


/**
The MP_CAPABLE option is carried on the SYN, SYN/ACK, and ACK packets
   that start the first subflow of an MPTCP connection
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +---------------+---------------+-------+-------+---------------+
      |     Kind      |    Length     |Subtype|Version|A|B|C|D|E|F|G|H|
      +---------------+---------------+-------+-------+---------------+
      |                   Option Sender's Key (64 bits)               |
      |                                                               |
      |                                                               |
      +---------------------------------------------------------------+
      |                  Option Receiver's Key (64 bits)              |
      |                     (if option Length == 20)                  |
      |                                                               |
      +---------------------------------------------------------------+
**/
class TcpOptionMpTcpCapable : public TcpOptionMpTcp<MP_CAPABLE>
{
public:
  TcpOptionMpTcpCapable(uint64_t senderKey);
  virtual ~TcpOptionMpTcpCapable ();

  enum SubTypes
  {
    CHECKSUM,
    CRYPTO
  };


  virtual void Print (std::ostream &os) const;
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);

  virtual uint8_t GetLength (void) const;

protected:
    uint8_t m_version; //!< MPTCP version (4 bytes

  /*
A: The leftmost bit, labeled "A", SHOULD be set to 1 to indicate
      "Checksum Required"

   B: The second bit, labeled "B", is an extensibility flag, and MUST be
      set to 0 for current implementations.

   C through H:  The remaining bits, labeled "C" through "H", are used
      for crypto algorithm negotiation.

*/
    uint8_t m_flags; //!< 8 bits bitfield (unused for now)

    //! Keys may be less than 64 bits
    uint64_t m_senderKey;
    uint64_t m_receiverKey;
};



/**
  MP_JOIN subtype:
      +---------------+---------------+-------+-----+-+---------------+
      |     Kind      |  Length = 12  |Subtype|     |B|   Address ID  |
      +---------------+---------------+-------+-----+-+---------------+
      |                   Receiver's Token (32 bits)                  |
      +---------------------------------------------------------------+
      |                Sender's Random Number (32 bits)               |
      +---------------------------------------------------------------+
**/
class TcpOptionMpTcpJoin : public TcpOptionMpTcp<MP_JOIN>
{

public:


  virtual void Print (std::ostream &os) const;
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);
  virtual uint8_t GetLength (void) const;
protected:
  uint8_t m_pathId;
  uint32_t m_receiverToken;
  uint32_t m_senderToken;

};

#if 0
class TcpOptionMpTcpDSS : public TcpOptionMpTcp<DSS>
{

public:

/**


**/
  virtual void Print (std::ostream &os) const;
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);
  virtual uint8_t GetLength (void) const;
protected:
}


class TcpOptionMpTcpAddAddress : public TcpOptionMpTcp<ADD_ADDR>
{

public:

/**

**/
  virtual void Print (std::ostream &os) const;
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);
  virtual uint8_t GetLength (void) const;
protected:
}
#endif


} // namespace ns3

#endif /* TCP_OPTION_SACK_PERMITTED_H */
