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

using namespace std;

namespace ns3
{

typedef enum
{
  MP_NONE,        // 0
  MP_MPC,         // 1
  MP_ADDR,        // 2
  MP_JOIN
} MpStates_t;
// Multipath actions

// congestion control algorithm
typedef enum
{
  Uncoupled_TCPs,       // 0
  Linked_Increases,     // 1
  RTT_Compensator,      // 2
  Fully_Coupled         // 3
} CongestionCtrl_t;

// connection phase
typedef enum
{
  Slow_Start,                   // 0
  Congestion_Avoidance,         // 1
} Phase_t;

typedef enum
{
  Round_Robin        // 0
} DataDistribAlgo_t;

typedef enum
{
  NoPR_Algo,    // 0
} PacketReorder_t;


class DSNMapping
{
public:
  DSNMapping();
  DSNMapping(uint8_t sFlowIdx, uint64_t dSeqNum, uint16_t dLvlLen, uint32_t sflowSeqNum, uint32_t ack, Ptr<Packet> pkt);
  //DSNMapping (const DSNMapping &res);
  virtual
  ~DSNMapping();
  uint64_t dataSeqNumber;
  uint16_t dataLevelLength;
  uint32_t subflowSeqNumber;
  uint32_t acknowledgement;
  uint32_t dupAckCount;
  uint8_t subflowIndex;
  uint8_t *packet;

  bool
  operator <(const DSNMapping& rhs) const;

  // variables for reordering simulation
  // Eifel Algorithm
  bool retransmited;
  uint64_t tsval; // TimesTamp value

  /*
   private:/
   bool original;
   */
};

typedef enum
{
  NO_ACTION,       // 0
  ADDR_TX,
  INIT_SUBFLOWS
} MpActions_t;

class MpTcpAddressInfo
{
public:
  MpTcpAddressInfo();
  ~MpTcpAddressInfo();

  uint8_t addrID;
  Ipv4Address ipv4Addr;
  Ipv4Mask mask;
};

class DataBuffer
{
public:
  DataBuffer();
  DataBuffer(uint32_t size);
  ~DataBuffer();

  queue<uint8_t> buffer;
  uint32_t bufMaxSize;

  uint32_t
  Add(uint8_t* buf, uint32_t size);
  uint32_t
  Retrieve(uint8_t* buf, uint32_t size);
  Ptr<Packet>
  CreatePacket(uint32_t size);
  uint32_t
  ReadPacket(Ptr<Packet> pkt, uint32_t dataLen);
  bool
  Empty();
  bool
  Full();
  uint32_t
  PendingData();
  uint32_t
  FreeSpaceSize();
};

} //namespace ns3
#endif //MP_TCP_TYPEDEFS_H
