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

/**
MP kinds
TODO remove ?
**/
#if 0
typedef enum
{
  MP_NONE,        // 0
  MP_MPC,         // 1
  MP_ADDADDR,        // 2
  MP_JOIN
} MpStates_t;
#endif

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

typedef enum
{
  NoPR_Algo,
} PacketReorder_t;

typedef enum
{
  Slow_Start,
  Congestion_Avoidance,
} Phase_t;

//typedef enum
//{
//  NO_ACTION,
//  ADDR_TX,
//  INIT_SUBFLOWS
//} MpActions_t;



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
  MpTcpMapping();

  void Configure( SequenceNumber32  dataSeqNb, uint16_t mappingSize);
  void MapToSSN( SequenceNumber32 seq);
  virtual ~MpTcpMapping() {};


  void
  SetDSN(SequenceNumber32);
  void
  SetMappingSize(uint16_t);

  /**
  * \param dsn Data seqNb
  */
  bool IsInRange(SequenceNumber32 const& dsn) const;

  /**
  * \param ssn Subflow sequence number
  * \param dsn Data Sequence Number
  * \return True if ssn belonged to this mapping, then a dsn would have been computed
  *
  */
  bool TranslateSSNToDSN(const SequenceNumber32& ssn,SequenceNumber32& dsn) const;

  /**
   * Select the max it can accept
   */
  SequenceNumber32 MaxDataSequence (void) const;

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
  GetDSN() const { return m_dataSequenceNumber; }

  // TODO rename into GetMappedSSN Head ?
  virtual SequenceNumber32
  GetSSN() const { return m_subflowSequenceNumber; }

  virtual uint16_t
  GetDataLevelLength() const { return m_dataLevelLength; }

  virtual bool operator==( const MpTcpMapping&) const;



  // TODO should be SequenceNumber64
protected:
//  SequenceNumber64 m_dataSequenceNumber;   //!< MPTCP level
  SequenceNumber32 m_dataSequenceNumber;   //!< MPTCP level
  SequenceNumber32 m_subflowSequenceNumber;  //!<
  uint16_t m_dataLevelLength;  //!< mapping length / size

};

/**
This should be a set to prevent duplication and keep it ordered
*/
typedef std::set<MpTcpMapping> MappingList;

std::ostream& operator<<(std::ostream &os, const MpTcpMapping& mapping);

/**
TODO remove
**/
#if 0
class DSNMapping
{
public:
  // TODO remove that constructor ? since never used
//  DSNMapping();
  /**
  **/
  DSNMapping(
    uint8_t sFlowIdx,
  uint64_t dSeqNum, uint16_t dLvlLen, uint32_t sflowSeqNum, uint32_t ack, Ptr<Packet> pkt
    );

  //DSNMapping (const DSNMapping &res);
  virtual ~DSNMapping();
  bool operator <(const DSNMapping& rhs) const;

  // TODO replace with SequenceNumber32 class ?
  uint64_t dataSeqNumber;   //!< DATA ACK (MPTCP level)
  uint16_t dataLevelLength; //!<
  uint32_t subflowSeqNumber;  //!< Subflow
  uint32_t acknowledgement; //!<
  uint32_t dupAckCount; //!<

  /* If DSN mappings are registered in the subflow, then it becomes useless ? unless it is referenced by meta
  looks like it, in case meta needs to resend data. But then the subflowIndex must be always valid wich is not true
  in the current implementation.
  */
  uint8_t subflowIndex; //!< Used twice
  uint8_t *packet;      //!<
};

//typedef std::list<DSNMapping*> MappingList;

/*
class MpTcpAddressInfo
{
public:
  MpTcpAddressInfo();
  ~MpTcpAddressInfo();
  uint8_t addrID;
  Ipv4Address ipv4Addr;
  Ipv4Mask mask;
};
*/



class MpTcpTxBuffer : public TcpTxBuffer
{
  protected:
    //Ajouter les mappings
};

class MpTcpRxBuffer : public TcpRxBuffer
{
};

/**
\todo replace with TcpRxBuffer etc... TcpTxBuffer ? why not Extend ?
MpTcpTxBuffer ?

*/
class DataBuffer
{
public:
  DataBuffer();
  DataBuffer(uint32_t size);
  ~DataBuffer();
  std::queue<uint8_t> buffer;
  uint32_t bufMaxSize;
  uint32_t Add(uint8_t* buf, uint32_t size);
  uint32_t Retrieve(uint8_t* buf, uint32_t size);
  Ptr<Packet> CreatePacket(uint32_t size);
  uint32_t ReadPacket(Ptr<Packet> pkt, uint32_t dataLen);
  bool Empty();
  bool Full();
  uint32_t PendingData();
  uint32_t FreeSpaceSize();
};
#endif

} //namespace ns3
#endif //MP_TCP_TYPEDEFS_H
