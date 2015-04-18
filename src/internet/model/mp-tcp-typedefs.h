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

typedef enum
{
  Uncoupled_TCPs,         // 0
  Linked_Increases,       // 1
  RTT_Compensator,        // 2
  Fully_Coupled,          // 3
  COUPLED_SCALABLE_TCP,   // 4
  UNCOUPLED,              // 5
  COUPLED_EPSILON,        // 6
  COUPLED_INC,            // 7
  COUPLED_FULLY           // 8
} CongestionCtrl_t;

typedef enum
{
  Round_Robin
} DataDistribAlgo_t;

typedef enum
{
  Default,
  FullMesh,
  NdiffPorts
} PathManager_t;


class DSNMapping
{
public:
  DSNMapping();
  DSNMapping(uint8_t sFlowIdx, uint64_t dSeqNum, uint16_t dLvlLen, uint32_t sflowSeqNum, uint32_t ack/*, Ptr<Packet> pkt*/);
  //DSNMapping (const DSNMapping &res);
  virtual ~DSNMapping();
  bool operator <(const DSNMapping& rhs) const;
  uint64_t dataSeqNumber;
  uint16_t dataLevelLength;
  uint32_t subflowSeqNumber;
  uint32_t acknowledgement;
  uint32_t dupAckCount;
  uint8_t subflowIndex;
  //uint8_t *packet;
};

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
  //uint32_t Add(uint8_t* buf, uint32_t size);
  uint32_t Add(uint32_t size);
  //uint32_t Retrieve(uint8_t* buf, uint32_t size);
  uint32_t Retrieve(uint32_t size);
  Ptr<Packet> CreatePacket(uint32_t size);
  uint32_t ReadPacket(Ptr<Packet> pkt, uint32_t dataLen);
  bool Empty();
  bool Full();
  bool ClearBuffer();
  uint32_t PendingData();
  uint32_t FreeSpaceSize();
  void SetBufferSize(uint32_t size);
};

} //namespace ns3
#endif //MP_TCP_TYPEDEFS_H
