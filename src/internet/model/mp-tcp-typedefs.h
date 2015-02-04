#ifndef MP_TCP_TYPEDEFS_H
#define MP_TCP_TYPEDEFS_H

#include <stdint.h>
#include <vector>
#include <queue>
#include <list>
#include <set>
#include <map>
#include "ns3/object.h"
#include "ns3/uinteger.h"
#include "ns3/traced-value.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/sequence-number.h"
#include "ns3/rtt-estimator.h"
#include "ns3/event-id.h"
#include "ns3/packet.h"
#include "ns3/tcp-socket.h"
#include "ns3/ipv4-end-point.h"
#include "ns3/ipv4-address.h"
#include "ns3/tcp-tx-buffer.h"
#include "ns3/tcp-rx-buffer.h"

namespace ns3
{

/*
Only sha1 standardized for now
*/
typedef enum {
MPTCP_SHA1
} mptcp_crypto_t;

#if 0
typedef enum
{
  Uncoupled_TCPs,       // 0
  Linked_Increases,     // 1 also called coupled
  RTT_Compensator,      // 2
  Fully_Coupled         // 3
} CongestionCtrl_t;

// TODO to remove, replaced by external callback/class
typedef enum
{
  Round_Robin
} DataDistribAlgo_t;
#endif


/**
TODO rename later into MpTcpDSNMapping
if we were in C++11 could be a tuple
DSN=Data Sequence Number (mptcp option level)
SSN=Subflow Sequence Number (TCP legacy seq nb)

\todo dataSeqNb should be a uint64_t but that has implications over a lot of code,
especially TCP buffers so it should be thought out with ns3 people beforehand
*/
class MpTcpMapping
{
public:
  MpTcpMapping(void);


  /**

  **/
  void Configure( SequenceNumber32  dataSeqNb, uint16_t mappingSize);

  void MapToSSN( SequenceNumber32 const& seq);

  virtual ~MpTcpMapping(void) {};

  /**
  \return True if mappings share DSN space
  Check if there is an overlap over DSN space or SSN space
  Decline to DSN and SSN ?
  */
  bool
  Intersect(const MpTcpMapping&) const;

  void
  SetDSN(SequenceNumber32 const&);

  void
  SetMappingSize(uint16_t const&);

  /**
  * \param dsn Data seqNb
  */
  bool IsSSNInRange(SequenceNumber32 const& ssn) const;

  /**
  * \param dsn Data seqNb
  */
  bool IsDSNInRange(SequenceNumber32 const& dsn) const;

  /**
  * \param ssn Subflow sequence number
  * \param dsn Data Sequence Number
  * \return True if ssn belonged to this mapping, then a dsn would have been computed
  *
  */
  bool
  TranslateSSNToDSN(const SequenceNumber32& ssn,SequenceNumber32& dsn) const;

  /**
   *  <= X <= TailDSN dsn
   */
  SequenceNumber32 TailDSN (void) const;
  SequenceNumber32 TailSSN (void) const;

  /**

  **/



  /**
  * Necessary for std::set to sort mappings
  * Compares data seq nb
  */
  bool operator<(MpTcpMapping const& ) const;


  // getters
  virtual
  //uint64_t
  SequenceNumber32
  HeadDSN() const; // { return m_dataSequenceNumber; }

  // TODO rename into GetMappedSSN Head ?
  virtual SequenceNumber32
  HeadSSN() const; // { return m_subflowSequenceNumber; }

  virtual uint16_t
  GetLength() const ; //{ return m_dataLevelLength; }

  /**

  */
  virtual bool operator==( const MpTcpMapping&) const;
  virtual bool operator!=( const MpTcpMapping& mapping) const;


  // TODO should be SequenceNumber64
protected:
//  SequenceNumber64 m_dataSequenceNumber;   //!< MPTCP level
  SequenceNumber32 m_dataSequenceNumber;   //!< MPTCP level
  SequenceNumber32 m_subflowSequenceNumber;  //!<
  uint16_t m_dataLevelLength;  //!< mapping length / size
//  bool m_send;  //!< Set to true if mapping already sent & acknowledged ?
};


typedef std::set<MpTcpMapping> MappingList;


/**
Depending on modifications allowed in upstream ns3, it may some day inherit from TcpTxbuffer etc ...
Meanwhile we have a pointer towards the buffers.
* \class MpTcpMappingContainer
* Mapping handling
Once a mapping has been advertised on a subflow, it must be honored. If the remote host already received the data
(because it was sent in parallel over another subflow), then the received data must be discarded.

*/
class MpTcpMappingContainer
{
  public:
    MpTcpMappingContainer(void);
    virtual ~MpTcpMappingContainer(void);

    /**
    **/
    bool
    TranslateSSNtoDSN(const SequenceNumber32& ssn,SequenceNumber32 &dsn);

    /**
    * Removes all mappings that covered dataspace seq nbs strictly lower than "dsn"
    * \param dsn
    */
//    virtual void
//    DiscardMappingsUpToDSN(const SequenceNumber32& dsn) ;


  /**
  SequenceNumber32 ?

  This can be called only when dsn is in the meta socket Rx buffer and in order
  (since it may renegate some data when out of order).
  The mapping should also have been thoroughly fulfilled at the subflow level.


  \return Number of mappings discarded. >= 0
  **/
  int
  DiscardMappingsUpToSN(const SequenceNumber32& dsn, const SequenceNumber32& ssn);


  /**
  When Buffers work in non renegotiable mode,
  it should be possible to remove them one by one
  **/
  bool
  DiscardMapping(const MpTcpMapping& mapping);

  /**
  return lowest SSN number
  \return SSN
  Makes no sense
  */
//  SequenceNumber32 FirstMappedSSN (void) const;

  /**
  REturn last mapped SSN.
  If Empty will take the one from the buff.
  */
  SequenceNumber32 FirstUnmappedSSN(void) const;

//  TcpRxBuffer
//  TcpTxBuffer

    /**
    For debug purpose. Dump all registered mappings
    **/
    void
    Dump();


  /**
  TODO this one generates disturbing logs, we should do it otherwise

  Will map the mapping to the first unmapped SSN
  \return Same value as for AddMappingEnforceSSN
  */
  int
  AddMappingLooseSSN(MpTcpMapping&);

  /**
  Check for overlap.
  \return < 0 if the mapping overlaps with an existing one, 0 otherwise
  **/
  int
  AddMappingEnforceSSN(const MpTcpMapping&);

  /**
  * \param l list
  * \param m pass on the mapping you want to retrieve
  */
  bool
  GetMappingForSSN( const SequenceNumber32& ssn, MpTcpMapping& m);


//  TracedValue<SequenceNumber32> m_highestMappedSSN; //!<

    bool m_receiveMode;
    TcpTxBuffer* m_txBuffer;
    TcpRxBuffer* m_rxBuffer;
  protected:
    MappingList m_mappings;     //!<
};

/**
This should be a set to prevent duplication and keep it ordered
*/

std::ostream& operator<<(std::ostream &os, const MpTcpMapping& mapping);



//class MpTcpTxBuffer : public TcpTxBuffer
//{
//  protected:
//    //Ajouter les mappings
//};
//
//class MpTcpRxBuffer : public TcpRxBuffer
//{
//};


} //namespace ns3
#endif //MP_TCP_TYPEDEFS_H
