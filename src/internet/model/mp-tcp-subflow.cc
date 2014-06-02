#include <iostream>
#include "ns3/mp-tcp-typedefs.h"
#include "ns3/simulator.h"
#include "ns3/log.h"
#include "mp-tcp-subflow.h"

NS_LOG_COMPONENT_DEFINE("MpTcpSubflow");

namespace ns3{

NS_OBJECT_ENSURE_REGISTERED(MpTcpSubFlow);

TypeId
MpTcpSubFlow::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::MpTcpSubFlow")
      .SetParent<Object>()
      .AddConstructor<MpTcpSubFlow>()
      .AddTraceSource("cWindow",
          "The congestion control window to trace.",
           MakeTraceSourceAccessor(&MpTcpSubFlow::cwnd));
  return tid;
}

MpTcpSubFlow::MpTcpSubFlow() :
    routeId(0), state(CLOSED), phase(Slow_Start), sAddr(Ipv4Address::GetZero()), sPort(0), dAddr(Ipv4Address::GetZero()), dPort(
        0), oif(0), mapDSN(0), lastMeasuredRtt(Seconds(0.0))
{
  connected = false;
  TxSeqNumber = rand() % 1000;
  RxSeqNumber = 0;
  bandwidth = 0;
  cwnd = 0;                  // congestion window is initialized to one segment
  scwnd = 0;
  ssthresh = 65535;              // initial value for a TCP connexion
  maxSeqNb = TxSeqNumber - 1;    // thus we suppose that SYN & ACK segments has been acked correctly, for subflow n° 0
  highestAck = 0;
  //rtt = new RttMeanDeviation();
  rtt = CreateObject<RttMeanDeviation>();
//    rtt->gain   = 0.1; // 1.0
  rtt->Gain(0.1);

  Time estimate;
  estimate = Seconds(1.5);
  rtt->SetCurrentEstimate(estimate);
  cnRetries = 3;
  Time est = MilliSeconds(200);
  cnTimeout = est;
  initialSequnceNumber = 0;

  // Congestion control variable
  m_retxThresh = 3;   //< Fast Retransmit threshold
  m_inFastRec = false;    //< currently in fast recovery
  m_limitedTx = false;    //< perform limited transmit
  m_dupAckCount = 0;     //< Dupack counter

  // variables used for simulating drops
  LostThreshold = 0.0;
  CanDrop = true;
  PktCount = 0;
  MaxPktCount = rand() % 100 + 50;
  DropedPktCount = 0;
  MaxDropedPktCount = 1;

  // variables used for reordering simulation
  savedCWND = 0.0;
  savedSSThresh = 0;
  SpuriousRecovery = false;
  recover = 0;
  m_recover = SequenceNumber32(0);
  ackCount = 0;
  ReTxSeqNumber = 0;
  nbRecvAck = -1;
  m_gotFin = false;
}

MpTcpSubFlow::~MpTcpSubFlow()
{
  m_endPoint = 0; // deAllocate the endPoint
  routeId = 0;
  sAddr = Ipv4Address::GetZero();
  oif = 0;
  state = CLOSED;
  bandwidth = 0;
  cwnd = 0;
  maxSeqNb = 0;
  highestAck = 0;
  for (list<DSNMapping *>::iterator it = mapDSN.begin(); it != mapDSN.end(); ++it)
    {
      DSNMapping * ptrDSN = *it;
      delete ptrDSN;
    }
  mapDSN.clear();
}


bool
MpTcpSubFlow::Finished(void)
{
  return (m_gotFin && m_finSeq.GetValue() < RxSeqNumber);
}

void
MpTcpSubFlow::StartTracing(string traced)
{
  //NS_LOG_UNCOND("("<< routeId << ") MpTcpSubFlow -> starting tracing of: "<< traced);
  TraceConnectWithoutContext(traced, MakeCallback(&MpTcpSubFlow::CwndTracer, this)); //"CongestionWindow"
}

void
MpTcpSubFlow::CwndTracer(uint32_t oldval, uint32_t newval)
{
  //NS_LOG_UNCOND("Subflow "<< routeId <<": Moving cwnd from " << oldval << " to " << newval);
  cwndTracer.push_back(make_pair(Simulator::Now().GetSeconds(), newval));
}

void
MpTcpSubFlow::AddDSNMapping(uint8_t sFlowIdx, uint64_t dSeqNum, uint16_t dLvlLen, uint32_t sflowSeqNum, uint32_t ack,
    Ptr<Packet> pkt)
{
  NS_LOG_FUNCTION_NOARGS();
  mapDSN.push_back(new DSNMapping(sFlowIdx, dSeqNum, dLvlLen, sflowSeqNum, ack, pkt));
}

void
MpTcpSubFlow::updateRTT(uint32_t ack, Time current)
{
  NS_LOG_FUNCTION( this << ack << current );
  rtt->AckSeq(SequenceNumber32(ack));
  NS_LOG_INFO ("MpTcpSubFlow::updateRTT -> time from last RTT measure = " << (current - lastMeasuredRtt).GetSeconds() );
  /*
   rtt->Measurement ( current - lastMeasuredRtt );
   lastMeasuredRtt = current;
   measuredRTT.insert(measuredRTT.end(), rtt->Estimate().GetSeconds ());
   */
//    measuredRTT.insert(measuredRTT.end(), rtt->est.GetSeconds ());
  measuredRTT.insert(measuredRTT.end(), rtt->GetCurrentEstimate().GetSeconds());
  NS_LOG_INFO ("MpTcpSubFlow::updateRTT -> estimated RTT = " << rtt->GetCurrentEstimate().GetSeconds ());
}

void
MpTcpSubFlow::SetFinSequence(const SequenceNumber32& s)
{
  NS_LOG_FUNCTION (this);
  m_gotFin = true;
  m_finSeq = s;
  if (RxSeqNumber == m_finSeq.GetValue())
    ++RxSeqNumber;
}

DSNMapping *
MpTcpSubFlow::GetunAckPkt()
{
  NS_LOG_FUNCTION(this);
  DSNMapping * ptrDSN = 0;
  for (list<DSNMapping *>::iterator it = mapDSN.begin(); it != mapDSN.end(); ++it)
    {
      DSNMapping * ptr = *it;
      NS_LOG_ERROR ("Subflow ("<<(int) routeId<<") Subflow Seq N° = " << ptr->subflowSeqNumber);
      if ((ptr->subflowSeqNumber == highestAck + 1) /*|| (ptr->subflowSeqNumber == highestAck + 2) */)
        {
          // we added 2, for the case in wich the fst pkt of a subsequent subflow is lost, because the highest ack is the one included in 'SYN | ACK' which is 2 less than the current TxSeq
          NS_LOG_INFO ("MpTcpSubFlow::GetunAckPkt -> packet to retransmit found: sFlowSeqNum = " << ptr->subflowSeqNumber);
          ptrDSN = ptr;
          break;
        }
    }
  return ptrDSN;
}
}
