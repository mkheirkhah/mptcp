
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

#ifndef TCP_OPTION_MPTCP_H
#define TCP_OPTION_MPTCP_H

#include "tcp-option.h"
#include "mp-tcp-typedefs.h"
#include <vector>

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
// TODO rename to MpTcpSubType
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


class TcpOptionMpTcpCapable;

// TODO transofrmer en template
/**
 * \class TcpOptionMpTcp
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +---------------+---------------+-------+-----------------------+
      |     Kind      |    Length     |Subtype|                       |
      +---------------+---------------+-------+                       |
      |                     Subtype-specific data                     |
      |                       (variable length)                       |
      +---------------------------------------------------------------+

TODO should be composed ?
*/
template<unsigned int SUBTYPE>
class TcpOptionMpTcp : public TcpOption
{
public:

  TcpOptionMpTcp () : TcpOption () {};
  virtual ~TcpOptionMpTcp () {};

// Prevents compilation & useless for now
//  TypeId
//  GetTypeId (void)
//  {
//    static TypeId tid = TypeId ("ns3::TcpOptionMpTcp")
//      .SetParent<TcpOption> ()
////      .AddConstructor<TcpOptionMSS> ()
//    ;
//    return tid;
//  }
//
//  TypeId
//  GetInstanceTypeId (void) const
//  {
//    return GetTypeId ();
//  }


static Ptr<TcpOption> CreateOption(uint8_t kind)
{
  return CreateObject<TcpOptionMpTcpCapable>();

}


  virtual void
  Print (std::ostream &os) const {
    NS_ASSERT_MSG(false, " You should override TcpOptionMpTcp::Print function");
    os << "MPTCP option. You should override";
  }


  virtual void
  Serialize (Buffer::Iterator start) const = 0;

  /** Let children write the subtype since Buffer iterators can't write less than 1 byte
  */
  virtual void
  SerializeRef (Buffer::Iterator& i) const
  {
//    Buffer::Iterator& i = start;
    i.WriteU8 (GetKind ()); // Kind
    i.WriteU8 ( GetSerializedSize() ); // Length


    // TODO may be an error otherwise here !

//    i.WriteU8 ( ( (GetSubType() << 4 ) && 0xf0) ); // Subtype TODO should write U4 only
    //i.WriteU8 ( GetSerializedSize() ); // Subtype TODO should write U4 only

  }

  // TODO later
  // Assume in subclasses that
//  virtual uint32_t
//  Deserialize (Buffer::Iterator i)
//  {
    // Devrait etre appelé par createOption avec l'itereateur qui commence sur la
    // longueur
//    uint8_t subType = i.ReadU8( );

//    Deserialize()
//  }


  // TODO
  virtual uint32_t
  DeserializeSize (Buffer::Iterator& i)
  {
    return i.ReadU8 ();
  }

  /*
  TODO make purely virtual ? but would need to pass
  Buffer::Iterator as a reference
  */
  virtual uint32_t
  GetSerializedSize (void) const =0;
//  {
//    return 2;
//  };

  /**
   \return TCP option type
  */
  virtual uint8_t
  GetKind (void) const
  {
    /* TODO ideally would refer to the enum in TcpOption::
    Hardcoded here to keep patch self-contained
    */
    return TcpOption::MPTCP;
  }


//  virtual uint32_t GetSerializedSize (void) const
//{
//  return 2;
//}


  virtual uint8_t
  GetSubType (void) const {
    return SUBTYPE;
  };

protected:

};


/**
The MP_CAPABLE option is carried on the SYN, SYN/ACK, and ACK packets
   that start the first subflow of an MPTCP connection
   A => checksum required
   B is for extensibility
   C to H = crypto algorithms

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
  TcpOptionMpTcpCapable();
  virtual ~TcpOptionMpTcpCapable ();

  enum SubTypes
  {
    CHECKSUM,
    CRYPTO
  };
  enum CryptoAlgorithms
  {
    NONE = 0,
    HMAC_SHA1 = 1

    // more may come - check the Standard
  };

//  static TypeId GetTypeId (void)
//  {
//    static TypeId tid = TypeId ("ns3::TcpOptionMpTcpCapable")
//      .SetParent<TcpOption> ()
//  //    .AddConstructor<TcpOptionMpTcp> ()
//    ;
//    return tid;
//  }
//
//
//  virtual TypeId GetInstanceTypeId (void) const
//{
//  return GetTypeId ();
//}

  /**
  * \ brief For now only version 0 exists
  */
  virtual uint8_t GetVersion() const { return 0;}
  /**
  Quoting RFC6284 The leftmost bit, labeled "A", SHOULD be set to 1 to indicate "Checksum Required"
  */
  virtual bool IsChecksumRequired() const;
  // setters
  virtual void SetSenderKey(uint64_t senderKey);
  virtual void SetRemoteKey(uint64_t remoteKey);


  virtual bool HasPeerKey() const { return GetSerializedSize() == 20; };

  virtual uint64_t GetLocalKey() const { return m_senderKey;}
  virtual uint64_t GetPeerKey() const { return m_remoteKey;}

  // TODO SetCryptoAlgorithm(

  virtual void Print (std::ostream &os) const;

  // OK
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);

  virtual uint32_t GetSerializedSize (void) const;

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
    uint8_t m_flags;    //!< 8 bits bitfield (unused for now)


    //! Keys may be less than 64 bits
    uint64_t m_senderKey;
    uint64_t m_remoteKey;

    uint32_t m_length;
};



/**

  MP_JOIN subtype:
  -For Initial SYN
      +---------------+---------------+-------+-----+-+---------------+
      |     Kind      |  Length = 12  |Subtype|     |B|   Address ID  |
      +---------------+---------------+-------+-----+-+---------------+
      |                   Receiver's Token (32 bits)                  |
      +---------------------------------------------------------------+
      |                Sender's Random Number (32 bits)               |
      +---------------------------------------------------------------+

      Figure 5: Join Connection (MP_JOIN) Option (for Initial SYN)
**/
class TcpOptionMpTcpJoinInitialSyn : public TcpOptionMpTcp<MP_JOIN>
{

public:

  TcpOptionMpTcpJoinInitialSyn();
  virtual ~TcpOptionMpTcpJoinInitialSyn();

  // Setters
  virtual void SetPeerToken(uint32_t token) { m_peerToken = token; }
  virtual void SetLocalToken(uint32_t token) { m_localToken = token; }

  // Getters
  virtual uint32_t GetPeerToken() const { return m_peerToken; }
  virtual uint32_t GetLocalToken() const { return m_localToken; }
  virtual uint8_t GetAddressId() const { return m_addressId; }

  virtual void Print (std::ostream &os) const;
  // Ok
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);
  virtual uint32_t GetSerializedSize (void) const;

protected:
  uint8_t m_addressId;    //!< Mandatory
  uint32_t m_peerToken;
  uint32_t m_localToken;

};


/**
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +---------------+---------------+-------+-----+-+---------------+
      |     Kind      |  Length = 16  |Subtype|     |B|   Address ID  |
      +---------------+---------------+-------+-----+-+---------------+
      |                                                               |
      |                Sender's Truncated HMAC (64 bits)              |
      |                                                               |
      +---------------------------------------------------------------+
      |                Sender's Random Number (32 bits)               |
      +---------------------------------------------------------------+

    Figure 6: Join Connection (MP_JOIN) Option (for Responding SYN/ACK)
*/
class TcpOptionMpTcpJoinSynReceived : public TcpOptionMpTcp<MP_JOIN>
{

public:

  TcpOptionMpTcpJoinSynReceived();
  virtual ~TcpOptionMpTcpJoinSynReceived();

  virtual void Print (std::ostream &os) const;
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);
  virtual uint32_t GetSerializedSize (void) const;

protected:
  uint8_t m_pathId;
  uint32_t m_receiverToken;
  uint32_t m_senderToken;

};
/**
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +---------------+---------------+-------+-----------------------+
      |     Kind      |  Length = 24  |Subtype|      (reserved)       |
      +---------------+---------------+-------+-----------------------+
      |                                                               |
      |                                                               |
      |                   Sender's HMAC (160 bits)                    |
      |                                                               |
      |                                                               |
      +---------------------------------------------------------------+

        Figure 7: Join Connection (MP_JOIN) Option (for Third ACK)
*/
class TcpOptionMpTcpJoinSynAckReceived : public TcpOptionMpTcp<MP_JOIN>
{

public:

  TcpOptionMpTcpJoinSynAckReceived();
  virtual ~TcpOptionMpTcpJoinSynAckReceived();

  virtual void Print (std::ostream &os) const;
  virtual void Serialize (Buffer::Iterator ) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);
  virtual uint32_t GetSerializedSize (void) const;

protected:
  uint8_t m_pathId;
  uint32_t m_receiverToken;
  uint32_t m_senderToken;

};



/**

                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +--------------------------------------------------------------+
   |                                                              |
   |                Data Sequence Number (8 octets)               |
   |                                                              |
   +--------------------------------------------------------------+
   |              Subflow Sequence Number (4 octets)              |
   +-------------------------------+------------------------------+
   |  Data-Level Length (2 octets) |        Zeros (2 octets)      |
   +-------------------------------+------------------------------+
*/
class TcpOptionMpTcpDSN : public TcpOptionMpTcp<DSS>
{

public:

  TcpOptionMpTcpDSN();
  virtual ~TcpOptionMpTcpDSN();

  // setter
  void SetMapping(MpTcpMapping mapping);
  MpTcpMapping GetMapping( ) const;
//  virtual void Configure(uint64_t, uint32_t, uint16_t);

  // getters
//  virtual uint64_t
//  GetDataSequenceNumber() const { return m_dataSequenceNumber; }
//  virtual uint32_t
//  GetSubflowSequenceNumber() const { return m_subflowSequenceNumber; }
//  virtual uint16_t
//  GetDataLevelLength() const { return m_dataLevelLength; }

  virtual void Print (std::ostream &os) const;
  // OK
  virtual void Serialize (Buffer::Iterator ) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);
  virtual uint32_t GetSerializedSize (void) const;

protected:
  MpTcpMapping m_mapping;
//  uint64_t m_dataSequenceNumber;
//  uint32_t m_subflowSequenceNumber;
//  uint16_t m_dataLevelLength;
};




/**

Should be valid for add/rem addr.
Though the port is optional in the RFC, ns3 implementation always include it, even if
it's 0.
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +---------------+---------------+-------+-------+---------------+
      |     Kind      |     Length    |Subtype| IPVer |  Address ID   |
      +---------------+---------------+-------+-------+---------------+
      |          Address (IPv4 - 4 octets / IPv6 - 16 octets)         |
      +-------------------------------+-------------------------------+
      |   Port (2 octets, optional)   |
      +-------------------------------+

                 Figure 12: Add Address (ADD_ADDR) Option
*/
class TcpOptionMpTcpAddAddress : public TcpOptionMpTcp<ADD_ADDR>
{

public:

  TcpOptionMpTcpAddAddress();
  virtual ~TcpOptionMpTcpAddAddress();

  /**
  we always send the port, even if it's 0 ?

   "port is specified, MPTCP SHOULD attempt to connect to the specified
   address on the same port as is already in use by the subflow on which
   the ADD_ADDR signal was sent"
  */
//  virtual bool IsPortEmbedded() ;

  virtual void SetAddress(InetSocketAddress, uint8_t addrId);
//  virtual void SetAddress(Ipv6Address);

  /**
  * Only IPv4 is supported
  * \return IPversion
  */
  virtual void GetAddress( InetSocketAddress& address) const;
  virtual uint8_t GetAddressId() const;
//  virtual void IsIpv6() const { return (m_length == 26); };
  virtual void Print (std::ostream &os) const;
  //ok
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);
  virtual uint32_t GetSerializedSize (void) const;

protected:
//  uint8_t m_length;

  uint8_t m_addressVersion; //!< IPver
  uint8_t m_addrId;
  uint8_t m_port;

  Ipv4Address m_address;
  Ipv6Address m_address6; //!< unused
//  InetSocketAddress m_address;
//  Inet6SocketAddress  m_address6;


};

/**
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------+---------------+-------+-------+---------------+
   |     Kind      |  Length = 3+n |Subtype|(resvd)|   Address ID  | ...
   +---------------+---------------+-------+-------+---------------+
                              (followed by n-1 Address IDs, if required)

          Figure 13: Remove Address (REMOVE_ADDR) Option
*/
class TcpOptionMpTcpRemoveAddress : public TcpOptionMpTcp<REMOVE_ADDR>
{

public:
  TcpOptionMpTcpRemoveAddress ();
  virtual ~TcpOptionMpTcpRemoveAddress ();

  void GetAddresses(std::vector<uint8_t>& addresses);
  void AddAddressId( uint8_t );

  virtual void Print (std::ostream &os) const;
  // OK
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);
  virtual uint32_t GetSerializedSize (void) const;
protected:
//  uint8_t m_length;
  std::vector<uint8_t> m_addressesId;
};


/**
RFC 6824 a subflow where the
   receiver has indicated B=1 SHOULD NOT be used to send data unless
   there are no usable subflows where B=0

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +---------------+---------------+-------+-----+-+--------------+
      |     Kind      |     Length    |Subtype|     |B| AddrID (opt) |
      +---------------+---------------+-------+-----+-+--------------+

            Figure 11: Change Subflow Priority (MP_PRIO) Option

  Note that the B option is unidirectional so one emitter may ask not to receive data
  on a subflow while transmitting on it.

  Length may be 3 or 4 (if addrId present).

*/
class TcpOptionMpTcpChangePriority : public TcpOptionMpTcp<MP_PRIO>
{

public:
  TcpOptionMpTcpChangePriority();
  virtual ~TcpOptionMpTcpChangePriority() {};


  virtual void SetAddressId(uint8_t addrId);

  // Helper function : could be inlined
  virtual bool EmbeddedAddressId() const;
  virtual bool GetAddressId(uint8_t& addrId) const;


  /**

  */
  virtual void Print (std::ostream &os) const;

  // OK
  virtual void Serialize (Buffer::Iterator start) const;

  // TODO
  virtual uint32_t Deserialize (Buffer::Iterator start);

  /** Length may be 3 or 4 (if addrId present)
  */
  virtual uint32_t GetSerializedSize (void) const;


protected:
  uint8_t m_length;   //!< Length of this option

  uint8_t m_addrId;   //!< May be unset
  bool m_backupFlag;  //!<
};

} // namespace ns3

#endif /* TCP_OPTION_SACK_PERMITTED_H */
