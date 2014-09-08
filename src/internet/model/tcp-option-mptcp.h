
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
#include "ns3/log.h"
#include <vector>

namespace ns3 {

/**
 * Defines the TCP option of kind 30 (Multipath TCP) as in RFC6824
http://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
 0x0 	MP_CAPABLE 	Multipath Capable
0x1 	MP_JOIN 	Join Connection
0x2 	MP_DSS 	Data Sequence Signal (Data ACK and data sequence mapping)
0x3 	MP_ADD_ADDR 	Add Address
0x4 	MP_REMOVE_ADDR 	Remove Address
0x5 	MP_PRIO 	Change Subflow Priority
0x6 	MP_FAIL 	Fallback
0x7 	MP_FASTCLOSE 	Fast Close
0xf 	(PRIVATE) 	Private Use within controlled testbe
 */
// TODO rename to MpTcpSubType

class TcpOptionMpTcpCapable;


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
TODO rename to TcpOptionMpTcp and the other ones as TcpOptionMpTcpDerivatives/SubTyped
*/
class TcpOptionMpTcpMain : public TcpOption
{
public:
  enum SubType {
    MP_CAPABLE,
    MP_JOIN,
    MP_DSS,
    MP_ADD_ADDR,
    MP_REMOVE_ADDR,
    MP_PRIO,
    MP_FAIL,
    MP_FASTCLOSE
  };


  TcpOptionMpTcpMain(void);
  virtual ~TcpOptionMpTcpMain(void);


  static TypeId GetTypeId (void);

  virtual TypeId GetInstanceTypeId (void) const;

  virtual void
  Print (std::ostream &os) const;

  /**
  * \brief
  */
  static std::string
  SubTypetoString(uint8_t flags, char delimiter);


  static Ptr<TcpOption> CreateMpTcpOption(uint8_t kind);

  virtual uint32_t
  GetSerializedSize (void) const =0;

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


  virtual void
  Serialize (Buffer::Iterator start) const = 0;

//  std::ostream & operator << (std::ostream &os) const;

  /**
  *
  * \return length of the option
  */
//  virtual uint32_t
//  StartDeserializing (Buffer::Iterator& i)
//  {
//     return i.ReadU8 ();
//  }

  virtual uint8_t
  GetSubType (void) const = 0;

protected:
  /**
  Serialize TCP option type & length of the option
  Let children write the subtype since Buffer iterators
  can't write less than 1 byte
  should be  called by children
  */
  virtual void
  SerializeRef (Buffer::Iterator& i) const;
};
// TODO transofrmer en template


// TODO do also for TCP option
//std::ostream & operator << (std::ostream &os, TypeId tid);


template<unsigned int SUBTYPE>
class TcpOptionMpTcp : public TcpOptionMpTcpMain
{
public:

  TcpOptionMpTcp () : TcpOptionMpTcpMain ()
  {
    // can't use arguments since would compel to declare a logging component
//    NS_LOG_FUNCTION_NOARGS();
  };
  virtual ~TcpOptionMpTcp (void) {
//    NS_LOG_FUNCTION_NOARGS();
  };

//  static TypeId GetTypeId (void)
//  {
//  static TypeId tid = TypeId ("ns3::TcpOptionMpTcp")
//    .SetParent<TcpOptionMpTcpMain> ()
//      ;
//    return tid;
//  }
//
//  virtual TypeId GetInstanceTypeId (void) const
//  {
//    return GetTypeId();
//  }

  uint8_t
  GetSubType (void) const {
    return SUBTYPE;
  };


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
class TcpOptionMpTcpCapable : public TcpOptionMpTcp<TcpOptionMpTcpMain::MP_CAPABLE>
{
public:
  TcpOptionMpTcpCapable(void);
  virtual ~TcpOptionMpTcpCapable (void);

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

  bool operator==(const TcpOptionMpTcpCapable&) const;
  /**
  * \ brief For now only version 0 exists
  */
  virtual uint8_t GetVersion(void) const { return 0;}
  /**
  Quoting RFC6284 The leftmost bit, labeled "A", SHOULD be set to 1 to indicate "Checksum Required"
  */
  virtual bool IsChecksumRequired(void) const;
  // setters
  virtual void SetSenderKey(const uint64_t& senderKey);
  virtual void SetRemoteKey(const uint64_t& remoteKey);


  virtual bool HasReceiverKey(void) const { return GetSerializedSize() == 20; };

  virtual uint64_t GetSenderKey(void) const { return m_senderKey;}
  virtual uint64_t GetPeerKey(void) const { return m_remoteKey;}

  // TODO SetCryptoAlgorithm(

  virtual void Print (std::ostream &os) const;
//  void  const
//  {
//    Print(os);
//  }

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

//std::ostream& operator<<(std::ostream &os, const TcpOption&);

/**
  TODO allow to set back up flag
  MP_JOIN subtype:
\verbatim

  -For Initial SYN
      +---------------+---------------+-------+-----+-+---------------+
      |     Kind      |  Length = 12  |Subtype|     |B|   Address ID  |
      +---------------+---------------+-------+-----+-+---------------+
      |                   Receiver's Token (32 bits)                  |
      +---------------------------------------------------------------+
      |                Sender's Random Number (32 bits)               |
      +---------------------------------------------------------------+

      Figure 5: Join Connection (MP_JOIN) Option (for Initial SYN)

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
**/
class TcpOptionMpTcpJoin : public TcpOptionMpTcp<TcpOptionMpTcpMain::MP_JOIN>
{

public:
  /**
  \enum State
  \brief The MPTCP standard assigns only one MP_JOIN subtype but depending on
  **/
  enum State {
  Uninitialized = 0,
  Syn    = 12,
  SynAck = 16,
  Ack    = 24
  };

  TcpOptionMpTcpJoin(void);
  virtual ~TcpOptionMpTcpJoin(void);

  virtual bool operator==(const TcpOptionMpTcpJoin&) const;


  State GetState(void) const { return m_state;}

  /**
  this part is for SYN
  **/
  virtual uint32_t
  GetNonce(void) const;
  virtual void
  SetNonce(uint32_t) ;


  /**
  this part is for SYN/ACK
  **/
  virtual void SetTruncatedHmac(uint64_t ) ;
  virtual uint64_t GetTruncatedHmac(void) const;


  /**
  this part is for ACK. Not implemented yet. Always 0
  **/
  virtual const uint8_t* GetHmac(void) const;
  virtual void SetHmac(uint8_t hmac[20]) ;


  // Setters
  virtual void
  SetPeerToken(uint32_t token);
//  virtual void SetLocalToken(uint32_t token) { m_localToken = token; }

//  virtual void SetBackupFlag
  // Getters
  virtual uint32_t
  GetPeerToken(void) const ;

//  virtual uint32_t GetLocalToken(void) const { return m_localToken; }
  virtual uint8_t
  GetAddressId(void) const;

  virtual void
  SetAddressId(uint8_t addrId);



  virtual void Print (std::ostream &os) const;

//  virtual bool SetStateFromFlags(const State& state);
  // Ok
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);
  virtual uint32_t GetSerializedSize (void) const;
  virtual void SetState(State s);




protected:
  State m_state;  //!<  3 typs of MP_JOIN. Members will throw an exception if used in wrong mode.

  uint8_t m_addressId;    //!< Mandatory
  uint8_t m_flags;
//  uint64_t m_nonce;
//  uint32_t m_peerToken;
//  uint32_t m_nonce;  //!< Rename to *nonce* . Should be a random number
  uint32_t m_buffer[5];  //!< To deal with the various data
};



/**

     The maximum
   length of this option, with all flags set, is 28 octets.
For now DataAck always 4 bytes
For now DSN always 4 bytes
should be improved to support uint64_t

we don't do the checksum either

                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +---------------+---------------+-------+----------------------+
     |     Kind      |    Length     |Subtype| (reserved) |F|m|M|a|A|
     +---------------+---------------+-------+----------------------+
     |           Data ACK (4 or 8 octets, depending on flags)       |
     +--------------------------------------------------------------+
     |   Data sequence number (4 or 8 octets, depending on flags)   |
     +--------------------------------------------------------------+
     |              Subflow Sequence Number (4 octets)              |
     +-------------------------------+------------------------------+
     |  Data-Level Length (2 octets) |      Checksum (2 octets)     |
     +-------------------------------+------------------------------+

                Figure 9: Data Sequence Signal (DSS) Option

*/
class TcpOptionMpTcpDSS : public TcpOptionMpTcp<TcpOptionMpTcpMain::MP_DSS>
{

public:
  /**

  */
  enum FLAG {
    DataAckPresent  = 1,   //!< matches the "A" in previous packet format
    DataAckOf8Bytes = 2, //!< a  (should not be used for now)
    DSNMappingPresent = 4,  //!< M
    DSNOfEightBytes   = 8,      //!< m  (should not be used for now)
    DataFin           = 16 //!< F . what's the datafin ?

  };

  TcpOptionMpTcpDSS(void);
  virtual ~TcpOptionMpTcpDSS(void);

  // setter
  void SetMapping(MpTcpMapping mapping);
  MpTcpMapping GetMapping(void) const;
  uint8_t GetFlags(void) const { return m_flags;};
//  virtual void Configure(uint64_t, uint32_t, uint16_t);

  virtual bool operator==(const TcpOptionMpTcpDSS&) const;

  /**
  * \brief Set seq nb of acked data at MPTP level
  */
  virtual void SetDataAck(uint32_t);
  virtual uint32_t GetDataAck(void) const { return m_dataAck; };


  virtual void Print (std::ostream &os) const;
  // OK
  virtual void Serialize (Buffer::Iterator ) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);
  virtual uint32_t GetSerializedSize (void) const;

protected:
  MpTcpMapping m_mapping;
  uint8_t m_flags;
//  uint64_t m_dataAck; //!< Can be On 32 bits dependings on the flags
  uint32_t m_dataAck; //!< Can be On 32 bits dependings on the flags. Data Acked by this option
};




/**

Should be valid for add/rem addr.
Though the port is optional in the RFC, ns3 implementation always include it, even if
it's 0 for the sake of simplicity.
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
class TcpOptionMpTcpAddAddress : public TcpOptionMpTcp<TcpOptionMpTcpMain::MP_ADD_ADDR>
{

public:

  TcpOptionMpTcpAddAddress(void);
  virtual ~TcpOptionMpTcpAddAddress(void);

  /**
  we always send the port, even if it's 0 ?

   "port is specified, MPTCP SHOULD attempt to connect to the specified
   address on the same port as is already in use by the subflow on which
   the MP_ADD_ADDR signal was sent"
  */
//  virtual bool IsPortEmbedded(void) ;

  /**
  * Expects InetXSocketAddress
  */
  virtual void SetAddress(const Address& address, uint8_t addrId);
//  virtual void SetAddress(Ipv6Address);

  virtual bool operator==(const TcpOptionMpTcpAddAddress&) const;

  /**
  * Only IPv4 is supported
  * \return IPversion
  */
  virtual uint8_t GetAddressVersion(void) const;
  virtual InetSocketAddress GetAddress(void) const;
  virtual Inet6SocketAddress GetAddress6(void) const;
  virtual uint8_t GetAddressId(void) const;

//  virtual void IsIpv6(void) const { return (m_length == 26); };
  virtual void Print (std::ostream &os) const;
  //ok
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);
  virtual uint32_t GetSerializedSize (void) const;

protected:
//  uint8_t m_length;

  uint8_t m_addressVersion; //!< IPversion (4 or 6)
  uint8_t m_addrId;
  uint8_t m_port;
//  Address m_address;
//  union {};
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

          Figure 13: Remove Address (MP_REMOVE_ADDR) Option
*/
class TcpOptionMpTcpRemoveAddress : public TcpOptionMpTcp<TcpOptionMpTcpMain::MP_REMOVE_ADDR>
{

public:
  TcpOptionMpTcpRemoveAddress (void);
  virtual ~TcpOptionMpTcpRemoveAddress (void);

  void GetAddresses(std::vector<uint8_t>& addresses);
  void AddAddressId( uint8_t );


  virtual bool operator==(const TcpOptionMpTcpRemoveAddress&) const;
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
class TcpOptionMpTcpChangePriority : public TcpOptionMpTcp<TcpOptionMpTcpMain::MP_PRIO>
{

public:
  TcpOptionMpTcpChangePriority(void);
  virtual ~TcpOptionMpTcpChangePriority(void) {};

  virtual void SetBackupFlag(bool value) { m_backupFlag = value; }
  virtual void SetAddressId(uint8_t addrId);

  // Helper function : could be inlined
  virtual bool EmbeddedAddressId(void) const;
  virtual bool GetAddressId(uint8_t& addrId) const;

  virtual bool GetPriority(void) const { return m_backupFlag;};

  virtual bool operator==(const TcpOptionMpTcpChangePriority& ) const;


//  static TypeId GetTypeId (void);
//  virtual TypeId GetInstanceTypeId (void) const;

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
private:

  /**
   * \brief Copy constructor
   *
   * Defined and unimplemented to avoid misuse
   */
  TcpOptionMpTcpChangePriority (const TcpOptionMpTcpChangePriority&);

  /**
   * \brief Copy constructor
   *
   * Defined and unimplemented to avoid misuse
   * \returns
   */
  TcpOptionMpTcpChangePriority& operator= (const TcpOptionMpTcpChangePriority&);

  uint8_t m_length;   //!< Length of this option

  uint8_t m_addrId;   //!< May be unset
  bool m_backupFlag;  //!<
};

/**
\verbatim

                            1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +---------------+---------------+-------+-----------------------+
       |     Kind      |    Length     |Subtype|      (reserved)       |
       +---------------+---------------+-------+-----------------------+
       |                      Option Receiver's Key                    |
       |                            (64 bits)                          |
       |                                                               |
       +---------------------------------------------------------------+

                Figure 14: Fast Close (MP_FASTCLOSE) Option


  If Host A wants to force the closure of an MPTCP connection, the
   MPTCP Fast Close procedure is as follows:

   o  Host A sends an ACK containing the MP_FASTCLOSE option on one
      subflow, containing the key of Host B as declared in the initial
      connection handshake.  On all the other subflows, Host A sends a
      regular TCP RST to close these subflows, and tears them down.
      Host A now enters FASTCLOSE_WAIT state.

   o  Upon receipt of an MP_FASTCLOSE, containing the valid key, Host B
      answers on the same subflow with a TCP RST and tears down all
      subflows.  Host B can now close the whole MPTCP connection (it
      transitions directly to CLOSED state).

   o  As soon as Host A has received the TCP RST on the remaining
      subflow, it can close this subflow and tear down the whole
      connection (transition from FASTCLOSE_WAIT to CLOSED states).  If
      Host A receives an MP_FASTCLOSE instead of a TCP RST, both hosts
      attempted fast closure simultaneously.  Host A should reply with a
      TCP RST and tear down the connection.

   o  If Host A does not receive a TCP RST in reply to its MP_FASTCLOSE
      after one retransmission timeout (RTO) (the RTO of the subflow
      where the MPTCP_RST has been sent), it SHOULD retransmit the
      MP_FASTCLOSE.  The number of retransmissions SHOULD be limited to
      avoid this connection from being retained for a long time, but
      this limit is implementation specific.  A RECOMMENDED number is 3.

**/
class TcpOptionMpTcpFastClose : public TcpOptionMpTcp<TcpOptionMpTcpMain::MP_PRIO>
{

public:
  TcpOptionMpTcpFastClose(void);
  virtual ~TcpOptionMpTcpFastClose(void) {};



  virtual bool operator==(const TcpOptionMpTcpFastClose& ) const;


//  static TypeId GetTypeId (void);
//  virtual TypeId GetInstanceTypeId (void) const;

  virtual void SetPeerKey(const uint64_t& remoteKey);
  virtual uint64_t GetPeerKey(void) const { return m_peerKey;}
  /**

  */
  virtual void Print (std::ostream &os) const;

  // OK
  virtual void Serialize (Buffer::Iterator start) const;

  // TODO
  virtual uint32_t Deserialize (Buffer::Iterator start);

  /**
  */
  virtual uint32_t GetSerializedSize (void) const;


protected:
private:
  uint64_t m_peerKey;



};


class TcpOptionMpTcpFallback : public TcpOptionMpTcp<TcpOptionMpTcpMain::MP_FAIL>
{

public:
  TcpOptionMpTcpFallback(void);
  virtual ~TcpOptionMpTcpFallback(void) {};



  virtual bool operator==(const TcpOptionMpTcpFallback& ) const;


//  static TypeId GetTypeId (void);
//  virtual TypeId GetInstanceTypeId (void) const;

  virtual void SetDSN(const uint64_t& dsn);
  virtual uint64_t GetDSN(void) const { return m_dsn;}
  /**

  */
  virtual void Print (std::ostream &os) const;

  // OK
  virtual void Serialize (Buffer::Iterator start) const;

  // TODO
  virtual uint32_t Deserialize (Buffer::Iterator start);

  /**
  */
  virtual uint32_t GetSerializedSize (void) const;


protected:
private:
  uint64_t m_dsn;



};

template<class T>
bool
GetMpTcpOption(const TcpHeader& header, Ptr<T>& ret)
{
  TcpHeader::TcpOptionList l;
  header.GetOptions(l);
  for(TcpHeader::TcpOptionList::const_iterator it = l.begin(); it != l.end(); ++it)
  {
    if( (*it)->GetKind() == TcpOption::MPTCP)
    {
      Ptr<TcpOptionMpTcpMain> opt = DynamicCast<TcpOptionMpTcpMain>(*it);
      NS_ASSERT(opt);
      T temp;
      if( opt->GetSubType() == temp.GetSubType()  )
      {
        //!
        ret = DynamicCast<T>(opt);
        return true;
      }
    }
  }
  return false;
}




} // namespace ns3

#endif /* TCP_OPTION_SACK_PERMITTED_H */
