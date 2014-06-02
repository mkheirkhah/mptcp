#include <iostream>
#include "ns3/mp-tcp-typedefs.h"
#include "ns3/simulator.h"
#include "ns3/log.h"
//#include "ns3/address-utils.h"
//#include "ns3/buffer.h"
//#include <stdint.h>
//#include <stdlib.h>
//#include <queue>
//#include "ns3/traced-value.h"
//#include "ns3/trace-source-accessor.h"
//#include <ns3/object-base.h>
//#include "time.h"

NS_LOG_COMPONENT_DEFINE("MpTcpTypeDefs");
namespace ns3
{

//NS_OBJECT_ENSURE_REGISTERED(MpTcpSubFlow);

DSNMapping::DSNMapping()
{
  subflowIndex = 255;
  acknowledgement = 0;
  dataSeqNumber = 0;
  dataLevelLength = 0;
  subflowSeqNumber = 0;
  dupAckCount = 0;
  packet = 0;
  //original         = true;
  retransmited = false;
  tsval = Simulator::Now().GetMilliSeconds(); // set the current time as a TimesTamp
}

DSNMapping::DSNMapping(uint8_t sFlowIdx, uint64_t dSeqNum, uint16_t dLvlLen, uint32_t sflowSeqNum, uint32_t ack, Ptr<Packet> pkt)
{
  subflowIndex = sFlowIdx;
  dataSeqNumber = dSeqNum;
  dataLevelLength = dLvlLen;
  subflowSeqNumber = sflowSeqNum;
  acknowledgement = ack;
  dupAckCount = 0;
  packet = new uint8_t[dLvlLen];
  pkt->CopyData(packet, dLvlLen);

  retransmited = false;
  tsval = Simulator::Now().GetMilliSeconds(); // set the current time as a TimesTamp
  //original         = true;
}
/*
 DSNMapping::DSNMapping (const DSNMapping &res)
 {
 subflowIndex     = res.subflowIndex;
 acknowledgement  = res.acknowledgement;
 dataSeqNumber    = res.dataSeqNumber;
 dataLevelLength  = res.dataLevelLength;
 subflowSeqNumber = res.subflowSeqNumber;
 dupAckCount      = res.dupAckCount;
 packet           = res.packet;
 original         = false;
 }
 */
DSNMapping::~DSNMapping()
{
  /*
   if ( original == false )
   return;
   */
  dataSeqNumber = 0;
  dataLevelLength = 0;
  subflowSeqNumber = 0;
  dupAckCount = 0;
  if (packet != 0)
    delete[] packet;
}

bool
DSNMapping::operator <(const DSNMapping& rhs) const
{
  return this->dataSeqNumber < rhs.dataSeqNumber;
}

DataBuffer::DataBuffer()
{
  bufMaxSize = 0;
}

DataBuffer::DataBuffer(uint32_t size)
{
  bufMaxSize = size;
}

DataBuffer::~DataBuffer()
{
  bufMaxSize = 0;
}

uint32_t
DataBuffer::Add(uint8_t* buf, uint32_t size)
{
  // read data from buf and insert it into the DataBuffer instance
  NS_LOG_FUNCTION (this << (int) size << (int) (bufMaxSize - (uint32_t) buffer.size()) );
  uint32_t toWrite = std::min(size, (bufMaxSize - (uint32_t) buffer.size()));

  if (buffer.empty() == true)
    {
      NS_LOG_INFO("DataBuffer::Add -> buffer is empty !");
    }
  else
    NS_LOG_INFO("DataBuffer::Add -> buffer was not empty !");

  uint32_t qty = 0;

  while (qty < toWrite)
    {
      buffer.push(buf[qty]);
      qty++;
    }NS_LOG_INFO("DataBuffer::Add -> amount of data = "<< qty);NS_LOG_INFO("DataBuffer::Add -> freeSpace Size = "<< (bufMaxSize - (uint32_t) buffer.size()) );
  return qty;
}

uint32_t
DataBuffer::Retrieve(uint8_t* buf, uint32_t size)
{
  NS_LOG_FUNCTION (this << (int) size << (int) (bufMaxSize - (uint32_t) buffer.size()) );
  uint32_t quantity = std::min(size, (uint32_t) buffer.size());
  if (quantity == 0)
    {
      NS_LOG_INFO("DataBuffer::Retrieve -> No data to read from buffer reception !");
      return 0;
    }

  for (uint32_t i = 0; i < quantity; i++)
    {
      buf[i] = buffer.front();
      buffer.pop();
    }

  NS_LOG_INFO("DataBuffer::Retrieve -> freeSpaceSize == "<< bufMaxSize - (uint32_t) buffer.size() );
  return quantity;
}

Ptr<Packet>
DataBuffer::CreatePacket(uint32_t size)
{
  NS_LOG_FUNCTION (this << (int) size << (int) ( bufMaxSize - (uint32_t) buffer.size()) );
  uint32_t quantity = std::min(size, (uint32_t) buffer.size());
  if (quantity == 0)
    {
      NS_LOG_INFO("DataBuffer::CreatePacket -> No data ready for sending !");
      return 0;
    }
  // Copy from front of Buffer to a new uint8_t array pointer
  uint8_t *ptrBuffer = new uint8_t[quantity];
  for (uint32_t i = 0; i < quantity; i++)
    {
      ptrBuffer[i] = buffer.front();
      buffer.pop();
    }
  // Create packet from a data pointer and its size
  Ptr<Packet> pkt = new Packet(ptrBuffer, quantity);
  delete[] ptrBuffer;

  NS_LOG_INFO("DataBuffer::CreatePacket -> freeSpaceSize == "<< bufMaxSize - (uint32_t) buffer.size() );
  return pkt;
}

uint32_t
DataBuffer::ReadPacket(Ptr<Packet> pkt, uint32_t dataLen)
{
  NS_LOG_FUNCTION (this << (int) (bufMaxSize - (uint32_t) buffer.size()) );

  uint32_t toWrite = std::min(dataLen, (bufMaxSize - (uint32_t) buffer.size()));

  if (buffer.empty() == true)
    {
      NS_LOG_INFO("DataBuffer::ReadPacket -> buffer is empty !");
    }
  else
    NS_LOG_INFO("DataBuffer::ReadPacket -> buffer was not empty !");

  uint8_t *ptrBuffer = new uint8_t[toWrite];
  pkt->CopyData(ptrBuffer, toWrite);

  for (uint32_t i = 0; i < toWrite; i++)
    buffer.push(ptrBuffer[i]);
  delete[] ptrBuffer;

  NS_LOG_INFO("DataBuffer::ReadPacket -> data   readed == "<< toWrite );NS_LOG_INFO("DataBuffer::ReadPacket -> freeSpaceSize == "<< bufMaxSize - (uint32_t) buffer.size() );
  return toWrite;
}

uint32_t
DataBuffer::PendingData()
{
  return ((uint32_t) buffer.size());
}

uint32_t
DataBuffer::FreeSpaceSize()
{
  return (bufMaxSize - (uint32_t) buffer.size());
}

bool
DataBuffer::Empty()
{
  return buffer.empty(); // ( freeSpaceSize == bufMaxSize );
}

bool
DataBuffer::Full()
{
  return (bufMaxSize == (uint32_t) buffer.size()); //( freeSpaceSize == 0 );
}
/*
 MpTcpStateMachine::MpTcpStateMachine()
 {
 NS_LOG_FUNCTION_NOARGS();
 aT[CLOSED][APP_LISTEN] = SA(LISTEN, NO_ACT);
 aT[CLOSED][APP_CONNECT] = SA(SYN_SENT, SYN_TX);
 aT[CLOSED][APP_SEND] = SA(CLOSED, NO_ACT);
 aT[CLOSED][SEQ_RECV] = SA(CLOSED, NO_ACT);
 aT[CLOSED][APP_CLOSE] = SA(CLOSED, NO_ACT);
 aT[CLOSED][TIMEOUT] = SA(CLOSED, NO_ACT);
 aT[CLOSED][ACK_RX] = SA(CLOSED, NO_ACT);
 aT[CLOSED][SYN_RX] = SA(CLOSED, NO_ACT);
 aT[CLOSED][SYN_ACK_RX] = SA(CLOSED, NO_ACT);
 aT[CLOSED][FIN_RX] = SA(CLOSED, NO_ACT);
 aT[CLOSED][FIN_ACK_RX] = SA(CLOSED, NO_ACT);
 aT[CLOSED][RST_RX] = SA(CLOSED, NO_ACT);
 aT[CLOSED][BAD_FLAGS] = SA(CLOSED, NO_ACT);

 aT[LISTEN][APP_CLOSE] = SA(CLOSING, FIN_TX);
 aT[LISTEN][SEQ_RECV] = SA(LISTEN, NEW_SEQ_RX);
 aT[LISTEN][ACK_RX] = SA(LISTEN, NEW_SEQ_RX);  // assert in case where no syn has been received
 aT[LISTEN][SYN_RX] = SA(SYN_RCVD, SYN_ACK_TX);  // stay in listen and do fork
 aT[LISTEN][FIN_RX] = SA(CLOSED, FIN_ACK_TX);
 aT[LISTEN][FIN_ACK_RX] = SA(CLOSED, NO_ACT);

 aT[SYN_RCVD][APP_SEND] = SA(SYN_RCVD, NO_ACT);
 aT[SYN_RCVD][SEQ_RECV] = SA(SYN_RCVD, NO_ACT);
 aT[SYN_RCVD][APP_CLOSE] = SA(SYN_RCVD, NO_ACT);
 aT[SYN_RCVD][TIMEOUT] = SA(SYN_RCVD, NO_ACT);
 aT[SYN_RCVD][ACK_RX] = SA(LISTEN, SERV_NOTIFY);
 aT[SYN_RCVD][SYN_RX] = SA(SYN_RCVD, NO_ACT);
 aT[SYN_RCVD][SYN_ACK_RX] = SA(SYN_RCVD, NO_ACT);
 aT[SYN_RCVD][FIN_RX] = SA(SYN_RCVD, NO_ACT);
 aT[SYN_RCVD][FIN_ACK_RX] = SA(SYN_RCVD, NO_ACT);
 aT[SYN_RCVD][RST_RX] = SA(SYN_RCVD, NO_ACT);
 aT[SYN_RCVD][BAD_FLAGS] = SA(SYN_RCVD, NO_ACT);

 aT[SYN_SENT][APP_SEND] = SA(SYN_SENT, NO_ACT);
 aT[SYN_SENT][APP_CLOSE] = SA(CLOSED, NO_ACT);
 aT[SYN_SENT][SYN_ACK_RX] = SA(ESTABLISHED, ACK_TX_1); // send ack to confirm connection establishment
 aT[SYN_SENT][FIN_RX] = SA(CLOSED, FIN_ACK_TX);
 aT[SYN_SENT][FIN_ACK_RX] = SA(CLOSED, NO_ACT);

 aT[ESTABLISHED][APP_LISTEN] = SA(ESTABLISHED, NO_ACT);
 aT[ESTABLISHED][APP_CONNECT] = SA(ESTABLISHED, NO_ACT);
 aT[ESTABLISHED][APP_SEND] = SA(ESTABLISHED, TX_DATA);
 aT[ESTABLISHED][SEQ_RECV] = SA(ESTABLISHED, NEW_SEQ_RX);
 aT[ESTABLISHED][APP_CLOSE] = SA(CLOSING, FIN_TX);
 aT[ESTABLISHED][TIMEOUT] = SA(ESTABLISHED, RETX);
 aT[ESTABLISHED][ACK_RX] = SA(ESTABLISHED, NEW_ACK);
 aT[ESTABLISHED][FIN_RX] = SA(CLOSED, FIN_ACK_TX);

 aT[CLOSING][FIN_ACK_RX] = SA(CLOSED, NO_ACT);

 // Create the flags lookup table
 eV[0x00] = SEQ_RECV;  // No flags
 eV[0x01] = FIN_RX;    // Fin
 eV[0x02] = SYN_RX;    // Syn
 eV[0x03] = BAD_FLAGS; // Illegal
 eV[0x04] = RST_RX;    // Rst
 eV[0x05] = BAD_FLAGS; // Illegal
 eV[0x06] = BAD_FLAGS; // Illegal
 eV[0x07] = BAD_FLAGS; // Illegal
 eV[0x08] = SEQ_RECV;  // Psh flag is not used
 eV[0x09] = FIN_RX;    // Fin
 eV[0x0a] = SYN_RX;    // Syn
 eV[0x0b] = BAD_FLAGS; // Illegal
 eV[0x0c] = RST_RX;    // Rst
 eV[0x0d] = BAD_FLAGS; // Illegal
 eV[0x0e] = BAD_FLAGS; // Illegal
 eV[0x0f] = BAD_FLAGS; // Illegal
 eV[0x10] = ACK_RX;    // Ack
 eV[0x11] = FIN_ACK_RX;    // Fin/Ack
 eV[0x12] = SYN_ACK_RX;    // Syn/Ack
 eV[0x13] = BAD_FLAGS; // Illegal
 eV[0x14] = RST_RX;    // Rst
 eV[0x15] = BAD_FLAGS; // Illegal
 eV[0x16] = BAD_FLAGS; // Illegal
 eV[0x17] = BAD_FLAGS; // Illegal
 eV[0x18] = ACK_RX;    // Ack
 eV[0x19] = FIN_ACK_RX;    // Fin/Ack
 eV[0x1a] = SYN_ACK_RX;    // Syn/Ack
 eV[0x1b] = BAD_FLAGS; // Illegal
 eV[0x1c] = RST_RX;    // Rst
 eV[0x1d] = BAD_FLAGS; // Illegal
 eV[0x1e] = BAD_FLAGS; // Illegal
 eV[0x1f] = BAD_FLAGS; // Illegal
 eV[0x20] = SEQ_RECV;  // No flags (Urgent not presently used)
 eV[0x21] = FIN_RX;    // Fin
 eV[0x22] = SYN_RX;    // Syn
 eV[0x23] = BAD_FLAGS; // Illegal
 eV[0x24] = RST_RX;    // Rst
 eV[0x25] = BAD_FLAGS; // Illegal
 eV[0x26] = BAD_FLAGS; // Illegal
 eV[0x27] = BAD_FLAGS; // Illegal
 eV[0x28] = SEQ_RECV;  // Psh flag is not used
 eV[0x29] = FIN_RX;    // Fin
 eV[0x2a] = SYN_RX;    // Syn
 eV[0x2b] = BAD_FLAGS; // Illegal
 eV[0x2c] = RST_RX;    // Rst
 eV[0x2d] = BAD_FLAGS; // Illegal
 eV[0x2e] = BAD_FLAGS; // Illegal
 eV[0x2f] = BAD_FLAGS; // Illegal
 eV[0x30] = ACK_RX;    // Ack (Urgent not used)
 eV[0x31] = FIN_ACK_RX;    // Fin/Ack
 eV[0x32] = SYN_ACK_RX;    // Syn/Ack
 eV[0x33] = BAD_FLAGS; // Illegal
 eV[0x34] = RST_RX;    // Rst
 eV[0x35] = BAD_FLAGS; // Illegal
 eV[0x36] = BAD_FLAGS; // Illegal
 eV[0x37] = BAD_FLAGS; // Illegal
 eV[0x38] = ACK_RX;    // Ack
 eV[0x39] = FIN_ACK_RX;    // Fin/Ack
 eV[0x3a] = SYN_ACK_RX;    // Syn/Ack
 eV[0x3b] = BAD_FLAGS; // Illegal
 eV[0x3c] = RST_RX;    // Rst
 eV[0x3d] = BAD_FLAGS; // Illegal
 eV[0x3e] = BAD_FLAGS; // Illegal
 eV[0x3f] = BAD_FLAGS; // Illegal
 }

 MpTcpStateMachine::~MpTcpStateMachine()
 {
 }

 string
 MpTcpStateMachine::printEvent(Events_t e)
 {
 switch (e)
 {
 case APP_LISTEN:
 return "APP_LISTEN";   // 0
 case APP_CONNECT:
 return "APP_CONNECT";  // 1
 case APP_SEND:
 return "APP_SEND";     // 2
 case SEQ_RECV:
 return "SEQ_RECV";     // 3
 case APP_CLOSE:
 return "APP_CLOSE";    // 4
 case TIMEOUT:
 return "TIMEOUT";      // 5
 case ACK_RX:
 return "ACK_RX";       // 6
 case SYN_RX:
 return "SYN_RX";       // 7
 case SYN_ACK_RX:
 return "SYN_ACK_RX";   // 8
 case FIN_RX:
 return "FIN_RX";       // 9
 case FIN_ACK_RX:
 return "FIN_ACK_RX";   // 10
 case RST_RX:
 return "RST_RX";       // 11
 case BAD_FLAGS:
 return "BAD_FLAGS";    // 12
 case LAST_EVENT:
 return "LAST_EVENT";
 default:
 return "Unrecognized event";
 }
 }

 string
 MpTcpStateMachine::printAction(Actions_t a)
 {
 switch (a)
 {
 case NO_ACT:
 return "NO_ACT";       // 0
 case ACK_TX:
 return "ACK_TX";       // 1
 case ACK_TX_1:
 return "ACK_TX_1";     // 2 - ACK response to syn
 case RST_TX:
 return "RST_TX";       // 3
 case SYN_TX:
 return "SYN_TX";       // 4
 case SYN_ACK_TX:
 return "SYN_ACK_TX";   // 5
 case FIN_TX:
 return "FIN_TX";       // 6
 case FIN_ACK_TX:
 return "FIN_ACK_TX";   // 7
 case NEW_ACK:
 return "NEW_ACK";      // 8
 case NEW_SEQ_RX:
 return "NEW_SEQ_RX";   // 9
 case RETX:
 return "RETX";         // 10
 case TX_DATA:
 return "TX_DATA";      // 11
 case PEER_CLOSE:
 return "PEER_CLOSE";   // 12
 case APP_CLOSED:
 return "APP_CLOSED";   // 13
 case CANCEL_TM:
 return "CANCEL_TM";    // 14
 case APP_NOTIFY:
 return "APP_NOTIFY";   // 15 - Notify app that connection failed
 case SERV_NOTIFY:
 return "SERV_NOTIFY";  // 16 - Notify server tcp that connection completed
 case LAST_ACTION:
 return "LAST_ACTION";
 default:
 return "Unrecognized action";
 }
 }

 string
 MpTcpStateMachine::printState(TcpStates_t s) // Morteza Kheirkhah
 {
 switch (s)
 {
 case CLOSED:
 return "CLOSED";       // 0
 case LISTEN:
 return "LISTEN";       // 1
 case SYN_SENT:
 return "SYN_SENT";     // 2
 case SYN_RCVD:
 return "SYN_RCVD";     // 3
 case ESTABLISHED:
 return "ESTABLISHED";  // 4
 case CLOSE_WAIT:
 return "CLOSE_WAIT";   // 5
 case LAST_ACK:
 return "LAST_ACK";     // 6
 case FIN_WAIT_1:
 return "FIN_WAIT_1";   // 7
 case FIN_WAIT_2:
 return "FIN_WAIT_2";   // 8
 case CLOSING:
 return "CLOSING";      // 9
 case TIME_WAIT:
 return "TIME_WAIT";   // 10
 case LAST_STATE:
 return "LAST_STATE";
 default:
 return "state unrecognized";
 }
 }
 */
/*
 MpTcpSubFlow::MpTcpSubFlow(uint32_t TxSeqNb) :
 routeId(0), state(CLOSED), phase(Slow_Start), sAddr(Ipv4Address::GetZero()), sPort(0), dAddr(Ipv4Address::GetZero()), dPort(
 0), oif(0), mapDSN(0), lastMeasuredRtt(Seconds(0.0))
 {
 connected = false;
 TxSeqNumber = TxSeqNb;
 RxSeqNumber = 0;
 bandwidth = 0;
 cwnd = 1;                   // congestion window is initialized to one segment
 scwnd = 0;
 ssthresh = 65535;               // initial value for a TCP connexion
 maxSeqNb = TxSeqNumber - 1;     // the subflow is created after receiving 'SYN ACK' segment
 highestAck = 0;
 rtt = new RttMeanDeviation();
 //    rtt->gain   = 0.1; //1.0
 rtt->Gain(0.1);       // Morteza Kheirkhah
 cnRetries = 3;
 initialSequnceNumber = 0;

 // variables used for simulating drops
 LostThreshold = 0.0;
 CanDrop = true;
 PktCount = 0;
 MaxPktCount = rand() % 100 + 100;
 DropedPktCount = 0;
 MaxDropedPktCount = 1;

 m_retxThresh = 3;   //< Fast Retransmit threshold
 m_inFastRec = false;    //< currently in fast recovery
 m_limitedTx = false;    //< perform limited transmit
 m_dupAckCount = 0;     //< Dupack counter

 // variables used for reordering simulation
 savedCWND = 0.0;
 savedSSThresh = 0;
 SpuriousRecovery = false;
 recover = 0;
 m_recover = SequenceNumber32(0);
 ackCount = 0;
 ReTxSeqNumber = 0;
 m_gotFin = false;
 }
 */


MpTcpAddressInfo::MpTcpAddressInfo() :
    addrID(0), ipv4Addr(Ipv4Address::GetZero()), mask(Ipv4Mask::GetZero())
{
}

MpTcpAddressInfo::~MpTcpAddressInfo()
{
  addrID = 0;
  ipv4Addr = Ipv4Address::GetZero();
}

} // namespace ns3
