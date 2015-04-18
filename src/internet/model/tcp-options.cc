#include <stdint.h>
#include <iostream>
#include "ns3/log.h"
#include "tcp-options.h"

NS_LOG_COMPONENT_DEFINE ("TcpOptions");

namespace ns3{

//NS_OBJECT_ENSURE_REGISTERED(TcpOptions);

TcpOptions::TcpOptions(void) :
    optName(OPT_NONE)
{
  NS_LOG_FUNCTION_NOARGS();
}

TcpOptions::~TcpOptions(void)
{
  NS_LOG_FUNCTION_NOARGS();
  optName = OPT_NONE;
}

OptMultipathCapable::OptMultipathCapable(TcpOption_t oName, uint32_t TxToken)
{
  NS_LOG_FUNCTION(this << oName << TxToken);
  optName = oName;
  Length = 5; // field "length" is not insert in the packet
  senderToken = TxToken;
}

OptMultipathCapable::~OptMultipathCapable()
{
  NS_LOG_FUNCTION_NOARGS();
  optName = OPT_NONE;
  Length = 0; // field "length" is not insert in the packet
  senderToken = 0;
}

OptJoinConnection::OptJoinConnection(TcpOption_t oName, uint32_t RxToken, uint8_t aID)
{
  NS_LOG_FUNCTION(this << oName << RxToken << aID);
  optName = oName;
  Length = 6;
  receiverToken = RxToken;
  addrID = aID;
}

OptJoinConnection::~OptJoinConnection()
{
  NS_LOG_FUNCTION_NOARGS();
  optName = OPT_NONE;
  Length = 0;
  receiverToken = 0;
  addrID = 0;
}

OptAddAddress::OptAddAddress(TcpOption_t oName, uint8_t aID, Ipv4Address address)
{
  NS_LOG_FUNCTION(this << oName << aID << address);
  optName = oName;
  Length = 6;
  addrID = aID;
  addr = address;
}

OptAddAddress::~OptAddAddress()
{
  NS_LOG_FUNCTION_NOARGS();
  optName = OPT_NONE;
  Length = 0;
  addrID = 0;
  addr = Ipv4Address::GetZero();
}

OptDataSeqMapping::OptDataSeqMapping(TcpOption_t oName, uint64_t dSeqNum, uint16_t dLevelLength, uint32_t sfSeqNum)
{
  NS_LOG_FUNCTION(this << oName << dSeqNum << dLevelLength << sfSeqNum);
  optName = oName;
  Length = 11;
  dataSeqNumber = dSeqNum;
  dataLevelLength = dLevelLength;
  subflowSeqNumber = sfSeqNum;
}

OptDataSeqMapping::~OptDataSeqMapping()
{
  NS_LOG_FUNCTION_NOARGS();
  optName = OPT_NONE;
  Length = 0;
  dataSeqNumber = 0;
  dataLevelLength = 0;
  subflowSeqNumber = 0;
}
}
