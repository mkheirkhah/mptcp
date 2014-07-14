/*
 * MultiPath-TCP (MPTCP) implementation.
 * Programmed by Morteza Kheirkhah from University of Sussex.
 * Some codes here are modeled from ns3::TCPNewReno implementation.
 * Email: m.kheirkhah@sussex.ac.uk
 */
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
    routeId(0),
    state(CLOSED),
    sAddr(Ipv4Address::GetZero()),
    sPort(0),
    dAddr(Ipv4Address::GetZero()),
    dPort(0),
    oif(0),
    mapDSN(0),
    lastMeasuredRtt(Seconds(0.0))
{
  connected = false;
  TxSeqNumber = rand() % 1000;
  RxSeqNumber = 0;
  bandwidth = 0;
  cwnd = 0;
  ssthresh = 65535;
  maxSeqNb = TxSeqNumber - 1;
  highestAck = 0;
  rtt = CreateObject<RttMeanDeviation>();
  rtt->Gain(0.1);
  Time estimate;
  estimate = Seconds(1.5);
  rtt->SetCurrentEstimate(estimate);
  cnRetries = 3;
  Time est = MilliSeconds(200);
  cnTimeout = est;
  initialSequnceNumber = 0;
  m_retxThresh = 3;
  m_inFastRec = false;
  m_limitedTx = false;
  m_dupAckCount = 0;
  PktCount = 0;
  m_recover = SequenceNumber32(0);
  m_gotFin = false;
}

MpTcpSubFlow::~MpTcpSubFlow()
{
  m_endPoint = 0;
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


void 
MpTcpSubFlow::AdvertiseAddress(uint8_t addrId, Address addr, uint16_t port)
{
  NS_LOG_FUNCTION(m_node->GetId());

  // TODO check subflow is established !!
  
      // there is at least one subflow
//      Ptr<MpTcpSubFlow> sFlow = subflows[0];
//      NS_ASSERT(sFlow!=0);

      // Change the MPTCP send state to MP_ADDADDR
//      mpSendState = MP_ADDADDR;
//      MpTcpAddressInfo * addrInfo;
      Ptr<Packet> pkt = Create<Packet>();

      TcpHeader header;
      header.SetFlags(TcpHeader::ACK);
      header.SetSequenceNumber(SequenceNumber32(sFlow->TxSeqNumber));
      header.SetAckNumber(SequenceNumber32(sFlow->RxSeqNumber));
      
      header.SetSourcePort(sPort); // m_endPoint->GetLocalPort()
      header.SetDestinationPort(dPort);
      uint8_t hlen = 0;
      uint8_t olen = 0;

      #if 0 
      // TODO That should go into a helper
      // Object from L3 to access to routing protocol, Interfaces and NetDevices and so on.
      Ptr<Ipv4L3Protocol> ipv4 = m_node->GetObject<Ipv4L3Protocol>();
      for (uint32_t i = 0; i < ipv4->GetNInterfaces(); i++)
        {
          //Ptr<NetDevice> device = m_node->GetDevice(i);
          Ptr<Ipv4Interface> interface = ipv4->GetInterface(i);
          Ipv4InterfaceAddress interfaceAddr = interface->GetAddress(0);

          // Skip the loop-back
          if (interfaceAddr.GetLocal() == Ipv4Address::GetLoopback())
            continue;

          addrInfo = new MpTcpAddressInfo();
          addrInfo->addrID = i;
          addrInfo->ipv4Addr = interfaceAddr.GetLocal();
          addrInfo->mask = interfaceAddr.GetMask();
      header.AddOptADDR(OPT_ADDR, addrInfo->addrID, addrInfo->ipv4Addr);
      olen += 6;
          m_localAddrs.insert(m_localAddrs.end(), addrInfo);
        }
      #endif 

      header.AddOptADDR(OPT_ADDR, addrId, addr );
      olen += 6;
          
      uint8_t plen = (4 - (olen % 4)) % 4;
      header.SetWindowSize(AdvertisedWindowSize());
      olen = (olen + plen) / 4;
      hlen = 5 + olen;
      header.SetLength(hlen);
      header.SetOptionsLength(olen);
      header.SetPaddingLength(plen);

      //m_mptcp->SendPacket(pkt, header, m_endPoint->GetLocalAddress(), m_remoteAddress);
      m_mptcp->SendPacket(pkt, header, m_localAddress, m_remoteAddress, FindOutputNetDevice(m_localAddress) );
      NS_LOG_INFO("Advertise  Addresses-> "<< header);
    }
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
      if (ptr->subflowSeqNumber == highestAck + 1)
        {
          ptrDSN = ptr;
          break;
        }
    }
  return ptrDSN;
}
}
