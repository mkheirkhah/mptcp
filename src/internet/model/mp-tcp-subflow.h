#ifndef MP_TCP_SUBFLOW_H
#define MP_TCP_SUBFLOW_H

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

namespace ns3{

class MpTcpSubFlow : public Object
{
public:
  static TypeId
  GetTypeId(void);

  MpTcpSubFlow();
  ~MpTcpSubFlow();
  //MpTcpSubFlow(uint32_t TxSeqNb);

  void
  StartTracing(string traced);
  void
  CwndTracer(uint32_t oldval, uint32_t newval);
  void
  AddDSNMapping(uint8_t sFlowIdx, uint64_t dSeqNum, uint16_t dLvlLen, uint32_t sflowSeqNum, uint32_t ack, Ptr<Packet> pkt);
  void
  updateRTT(uint32_t ack, Time current);
  DSNMapping *
  GetunAckPkt();
  bool
  Finished();

  uint16_t routeId;
  bool connected;
  TcpStates_t state;     // Morteza Kheirkhah
  Phase_t phase;
  Ipv4Address sAddr;
  uint16_t sPort;
  Ipv4Address dAddr;
  uint16_t dPort;
  uint32_t oif;

  EventId retxEvent;
  EventId m_lastAckEvent;
  EventId m_timewaitEvent;
  uint32_t MSS;             // Maximum Segment Size

  uint32_t cnCount;         //< Count of remaining connection retries
  uint32_t cnRetries;       //< Number of connection retries before giving up
  Time     cnTimeout;       //< Timeout for connection retry

  //double   cwnd;
  //TracedValue<double> cwnd;
  TracedValue<uint32_t> cwnd;
  double scwnd;         // smoothed congestion window
  uint32_t ssthresh;
  uint32_t maxSeqNb; // it represent the highest sequence number of a sent byte. In general it's egual to ( TxSeqNumber - 1 ) until a retransmission happen
  uint32_t highestAck;   // hightest received ACK for the subflow level sequence number
  uint64_t bandwidth;
  uint32_t initialSequnceNumber;

//    TracedValue<uint32_t>  m_cWnd;         //< Congestion window
//    uint32_t               m_ssThresh;     //< Slow Start Threshold
  uint32_t m_initialCWnd;  //< Initial cWnd value
  SequenceNumber32 m_recover;      //< Previous highest Tx seqnum for fast recovery
  uint32_t m_retxThresh;   //< Fast Retransmit threshold
  bool m_inFastRec;    //< currently in fast recovery
  bool m_limitedTx;    //< perform limited transmit
  uint32_t m_dupAckCount;     //< Dupack counter
  Ipv4EndPoint* m_endPoint;

  vector<pair<double, uint32_t> > cwndTracer;

  vector<pair<double, double> > ssthreshtrack;
  vector<pair<double, double> > CWNDtrack;
//    vector<pair<double, double> > UnOrderSize;
  vector<pair<double, uint32_t> > DATA;
  vector<pair<double, uint32_t> > ACK;
  vector<pair<double, uint32_t> > DROP;
  vector<pair<double, uint32_t> > RETRANSMIT;
  vector<pair<double, uint32_t> > DUPACK;

  vector<pair<double, double> > _ss;
  vector<pair<double, double> > _ca;
  vector<pair<double, double> > _FR_FA;
  vector<pair<double, double> > _FR_PA;
  vector<pair<double, double> > _FReTx;
  vector<pair<double, double> > _TimeOut;
  vector<pair<double, double> > _RTT;
  vector<pair<double, double> > _AvgRTT;
  vector<pair<double, double> > _RTO;

  list<DSNMapping *> mapDSN;
  multiset<double> measuredRTT;
  //list<double> measuredRTT;
  Ptr<RttMeanDeviation> rtt;
  Time lastMeasuredRtt;
  uint32_t TxSeqNumber;
  uint32_t RxSeqNumber;

  // for losses simulation
  double LostThreshold;
  bool CanDrop;
  uint64_t PktCount;
  uint64_t MaxPktCount;
  uint32_t DropedPktCount;
  uint32_t MaxDropedPktCount;

  // Reordering simulation
  double savedCWND;
  uint32_t savedSSThresh;
  bool SpuriousRecovery;
  uint32_t recover;
  uint8_t ackCount;      // count of received acknowledgement after an RTO expiration
  uint32_t ReTxSeqNumber; // higher sequence number of the retransmitted segment
  int nbRecvAck;

  //Teardown mptcp subflow params
  bool m_gotFin;
  SequenceNumber32 m_finSeq;
  void
  SetFinSequence(const SequenceNumber32& s);
};

}
#endif /* MP_TCP_SUBFLOW */
