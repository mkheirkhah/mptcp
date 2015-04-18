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
  OPT_MPC = 30,
  OPT_JOIN = 31,
  OPT_ADDR = 32,
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

}
#endif /* TCP_OPTIONS */
