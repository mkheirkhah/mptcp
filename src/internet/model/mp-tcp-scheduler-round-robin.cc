
#include "ns3/mp-tcp-scheduler-round-robin.h"
#include "ns3/mp-tcp-subflow.h"
#include "ns3/mp-tcp-socket-base.h"
#include "ns3/log.h"

NS_LOG_COMPONENT_DEFINE("MpTcpSchedulerRoundRobin");

namespace ns3
{

TypeId
MpTcpSchedulerRoundRobin::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::MpTcpSchedulerRoundRobin")
    .SetParent<Object> ()
    //
    .AddConstructor<MpTcpSchedulerRoundRobin> ()
  ;
//  NS_LOG_UNCOND("TcpOptionMpTcpMain::GetTypeId called !");
  return tid;
}


//Ptr<MpTcpSocketBase> metaSock
MpTcpSchedulerRoundRobin::MpTcpSchedulerRoundRobin() :
  m_lastUsedFlowId(0),
  m_metaSock(0)
{
  NS_LOG_FUNCTION(this);
//  NS_ASSERT(m_metaSock);
}

MpTcpSchedulerRoundRobin::~MpTcpSchedulerRoundRobin (void)
{
  NS_LOG_FUNCTION(this);
}


void
MpTcpSchedulerRoundRobin::SetMeta(Ptr<MpTcpSocketBase> metaSock)
{
  NS_ASSERT(metaSock);
  NS_ASSERT_MSG(m_metaSock == 0,"SetMeta already called");
  m_metaSock = metaSock;
}

//uint16_t
Ptr<MpTcpSubflow>
MpTcpSchedulerRoundRobin::GetSubflowToUseForEmptyPacket()
{
  NS_ASSERT(m_metaSock->GetNActiveSubflows() > 0 );
  return  m_metaSock->GetSubflow(0);
//  m_lastUsedFlowId = (m_lastUsedFlowId + 1) % m_metaSock->GetNActiveSubflows();
//  return m_metaSock->GetSubFlow(m_lastUsedFlowId);
}

// We assume scheduler can't send data on subflows, so it can just generate mappings
//std::vector< std::pair<uint8_t, MappingList>
// std::pair< start,size , subflow>
// ca génère les mappings ensuite
int
MpTcpSchedulerRoundRobin::GenerateMappings(MappingVector& mappings)
{
  NS_LOG_FUNCTION(this);
  NS_ASSERT_MSG(m_metaSock,"Call SetMeta() before generating a mapping");

  // THis is worng since it depends on what's next
//  if( m_metaSock->m_txBuffer.Size() == 0) {
//    NS_LOG_LOGIC("Nothing to send");
//    return 0;
//  }

//  uint32_t amountOfDataToSend     = m_metaSock->m_txBuffer.SizeFromSequence(m_metaSock->m_nextTxSequence);
  SequenceNumber32 metaNextTxSeq = m_metaSock->m_nextTxSequence;
//  uint8_t i = 0;
  uint32_t amountOfDataToSend = 0;
  uint32_t window = m_metaSock->AvailableWindow();

  if(window <= 0)
  {
    NS_LOG_DEBUG("No window available [" << window << "] (TODO shoulb be in persist state ?)");
    return -1; // TODO ?
  }

//  NS_LOG_DEBUG()metaNextTxSeq

  // TODO rewrite pr que cela fasse comme dans
//  int testedSf = 0;
  int i = 0;
  for(
      ;
    i < (int)m_metaSock->GetNActiveSubflows()
    ;
    i++, m_lastUsedFlowId = (m_lastUsedFlowId + 1) % m_metaSock->GetNActiveSubflows()
    )
  {
    uint32_t left = m_metaSock->m_txBuffer.SizeFromSequence( metaNextTxSeq );
    if(left <= 0)
    {
      NS_LOG_DEBUG("Nothing to send from meta");
      return 0;
    }

    NS_LOG_DEBUG("Meta Tx to send:" << left
              << " over [" << (int)m_metaSock->GetNActiveSubflows() << "] active subflow(s)"
              );


    // TODO check how the windows work
    //m_metaSock->
    Ptr<MpTcpSubflow> sf = m_metaSock->GetSubflow(m_lastUsedFlowId);
    uint32_t window = sf->AvailableWindow(); // Get available window size
//    sf->DumpInfo();

      NS_LOG_LOGIC ("MpTcpSubflow " << sf << " SendPendingData" <<
//          " w " << w <<
//          " rxwin " << sf->m_rWnd <<
//          " segsize " << sf->m_segmentSize <<
          " nextTxSeq " << sf->m_nextTxSequence <<
          " highestRxAck " << sf->m_txBuffer.HeadSequence () <<
          " pd->Size " << sf->m_txBuffer.Size () <<
          " pd->SFS " << sf->m_txBuffer.SizeFromSequence (sf->m_nextTxSequence)
          );

      // Quit if send disallowed
//    if (sf->m_shutdownSend)
//      {
//        continue;
////          m_errno = ERROR_SHUTDOWN;
////          return false;
//      }
      // Stop sending if we need to wait for a larger Tx window (prevent silly window syndrome)
//      if (w < sf->m_segmentSize && m_txBuffer.SizeFromSequence(m_nextTxSequence) > w)
//        {
//          break; // No more
//        }

    amountOfDataToSend = 0;
    MpTcpMapping mapping;
//    //is protected

//    if( window > 0)
//    {
    NS_LOG_DEBUG("subflow Window available [" << window << "]");
    amountOfDataToSend = std::min( window, left );
    NS_LOG_DEBUG("Amount of data to send [" << amountOfDataToSend  << "]");
    if(amountOfDataToSend <= 0)
    {
      NS_LOG_DEBUG("Most likely window is equal to 0 which should not happen");
      continue;
    }
    NS_ASSERT_MSG(amountOfDataToSend > 0, "Most likely window is equal to 0 which should not happen");
//    }
//    else {
//        NS_LOG_DEBUG("No window available [" << window << "]");
//      continue;
//    }

    mapping.Configure( metaNextTxSeq , amountOfDataToSend);
    mappings.push_back( std::make_pair( i, mapping) );
    metaNextTxSeq += amountOfDataToSend;
//    m_lastUsedFlowId = (m_lastUsedFlowId + 1) %m_metaSock->GetNActiveSubflows();
  }


  return 0;
}




} // end of 'ns3'
