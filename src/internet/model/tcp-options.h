#ifndef TCP_OPTIONS_H
#define TCP_OPTIONS_H

#include <stdint.h>
#include <vector>
#include "ns3/ipv4-address.h"


using namespace std;

namespace ns3
{

typedef enum
{
  OPT_NONE = 0,
  OPT_DSACK = 5,
  OPT_TT = 8,      // Time Stamp
  OPT_MPC = 30,
  OPT_JOIN = 31,
  OPT_ADDR = 32,
  OPT_REMADR = 33,
  OPT_DSN = 34
} TcpOption_t;

class TcpOptions
{
public:
  TcpOptions();
  virtual
  ~TcpOptions();

  TcpOption_t optName;
  uint8_t Length;
};

class OptMultipathCapable : public TcpOptions
{
public:
  virtual
  ~OptMultipathCapable();
  uint32_t senderToken;
  OptMultipathCapable(TcpOption_t oName, uint32_t TxToken);
};

class OptJoinConnection : public TcpOptions
{
public:
  virtual
  ~OptJoinConnection();
  uint32_t receiverToken;
  uint8_t addrID;
  OptJoinConnection(TcpOption_t oName, uint32_t RxToken, uint8_t aID);
};

class OptAddAddress : public TcpOptions
{
public:
  virtual
  ~OptAddAddress();
  uint8_t addrID;
  Ipv4Address addr;
  OptAddAddress(TcpOption_t oName, uint8_t aID, Ipv4Address address);
};

class OptRemoveAddress : public TcpOptions
{
public:
  virtual
  ~OptRemoveAddress();
  uint8_t addrID;
  OptRemoveAddress(TcpOption_t oName, uint8_t aID);
};

class OptDataSeqMapping : public TcpOptions
{
public:
  virtual
  ~OptDataSeqMapping();
  uint64_t dataSeqNumber;
  uint16_t dataLevelLength;
  uint32_t subflowSeqNumber;
  OptDataSeqMapping(TcpOption_t oName, uint64_t dSeqNum, uint16_t dLevelLength, uint32_t sfSeqNum);
};

class OptTimesTamp : public TcpOptions
{
public:
  virtual
  ~OptTimesTamp();
  uint64_t TSval;     // TS Value      in milliseconds
  uint64_t TSecr;     // TS Echo Reply in milliseconds

  OptTimesTamp(TcpOption_t oName, uint64_t tsval, uint64_t tsecr);
};

class OptDSACK : public TcpOptions
{
public:
  virtual
  ~OptDSACK();
  std::vector<uint64_t> blocks;     // a vector of 4-bytes fields, representing the DSACK block's edge
  // the size of the vector is a multiple of 2 (a block has to limits, upper and lower) representing the length of the table
  OptDSACK(TcpOption_t oName);
  void
  AddBlock(uint64_t leftEdge, uint64_t rightEdge);
  void
  AddfstBlock(uint64_t leftEdge, uint64_t rightEdge);
};

}
#endif /* TCP_OPTIONS */
