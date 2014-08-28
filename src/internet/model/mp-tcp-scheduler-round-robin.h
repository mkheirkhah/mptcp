
#ifndef MPTCP_SCHEDULER_ROUND_ROBIN_H
#define MPTCP_SCHEDULER_ROUND_ROBIN_H


//#include "ns3/mp-tcp-scheduler.h"
//#include "ns3/mp-tcp-socket-base.h"
#include "ns3/mp-tcp-typedefs.h"
#include "ns3/object.h"
#include "ns3/ptr.h"
#include <vector>
#include <list>

/**
The MPTCP scheduler is in charge of selecting the
TODO: move to helpers ?
*/

namespace ns3
{

class MpTcpSocketBase;
class MpTcpSubFlow;


//typedef std::vector< std::pair<uint8_t, std::pair< SequenceNumber32,uint32_t > > > MappingVector;
//
typedef std::vector< std::pair< SequenceNumber32,uint32_t > > MappingVector;


class MpTcpSchedulerRoundRobin : public Object
//: public MpTcpScheduler
{

public:
  MpTcpSchedulerRoundRobin(Ptr<MpTcpSocketBase> metaSock);
  virtual ~MpTcpSchedulerRoundRobin ();

  //Ptr<MpTcpSocketBase> metaSock
  //            std::pair<int,
            // DSNMapping
//              std::pair<SequenceNumber32,SequenceNumber32>
//            >

  /**
  subflowId: pair(start,size)
  */
  virtual int
  GenerateMappings(
//      MappingList&
//  std::vector< std::pair<uint8_t, std::pair< SequenceNumber32, uint32_t > > >
  MappingVector
  &
    );

  /**
  */
  // TODO
  // chooseSubflowForRetransmit

  /**
  Return Index of subflow to use
  */
  virtual Ptr<MpTcpSubFlow> GetSubflowToUseForEmptyPacket();

protected:
  uint8_t  m_lastUsedFlowId;  //!< keep track of last used subflow
  Ptr<MpTcpSocketBase> m_metaSock;  //!<
};


} // end of 'ns3'

#endif /* MPTCP_SCHEDULER_ROUND_ROBIN_H */
