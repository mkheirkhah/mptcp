
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
Ptr<MpTcpSubFlow>
MpTcpSchedulerRoundRobin::GetSubflowToUseForEmptyPacket()
{
  NS_ASSERT(m_metaSock->GetNSubflows() > 0 );
  return  m_metaSock->GetSubflow(0);
//  m_lastUsedFlowId = (m_lastUsedFlowId + 1) % m_metaSock->GetNSubflows();
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


//  uint32_t amountOfDataToSend     = m_metaSock->m_txBuffer.SizeFromSequence(m_metaSock->m_nextTxSequence);
  SequenceNumber32 metaNextTxSeq  = m_metaSock->m_nextTxSequence;
//  uint8_t i = 0;
  uint32_t amountOfDataToSend = 0;

  for(int i = 0; i < (int)m_metaSock->GetNSubflows(); ++i)
  {
    Ptr<MpTcpSubFlow> sf = m_metaSock->GetSubflow(i);
    uint32_t window = sf->AvailableWindow();
    amountOfDataToSend = 0;
    MpTcpMapping mapping;
//    //is protected

    if( window > 0)
    {

      amountOfDataToSend = std::min( window, m_metaSock->m_txBuffer.SizeFromSequence( metaNextTxSeq ) );
    }
    mapping.Configure( metaNextTxSeq , amountOfDataToSend);
    mappings.push_back(  mapping );
    metaNextTxSeq += amountOfDataToSend;
  }

    #if 0
  // MATT this should be done into subflows
  // This is a condition when main mptcp sendingBuffer is empty but they are some packets in a subflow's buffer
  // and also sub-flow is recovering from time-out.
  // this may be a decision to let to the CC
  if (sendingBuffer->Empty())
    {

    // TODO that part should be moved into subflows
      Ptr<MpTcpSubFlow> sF = m_subflows[sFlowIdx];
      NS_LOG_WARN("(" << (int) sFlowIdx << ") main SendingBuffer is EMPTY, but SubflowBuffer is: "
          << sF->m_mapDSN.size()
        );

      // Sub-flow state is established, SendingBuffer is empty
      // but subflowBuffer (m_mapDSN) is not empty and sub-flow is recovering from timeOut
      // Note that the algorithm used for detecting whether sub-flow is in timeout need to be studied further.
      if ( (sF->m_state == ESTABLISHED) &&
          (sF->m_mapDSN.size() > 0) &&
          (sF->maxSeqNb > sF->TxSeqNumber)
          )
        {
          uint32_t window = std::min(AvailableWindow(sFlowIdx), sF->GetSegSize());
          NS_LOG_ERROR("SendingBuffer Empty!, Sub-flow (" << (int)sFlowIdx << ") AvailableWindow" << window);

          // Send all data packets in subflowBuffer (m_mapDSN) until subflow's available window is full.
          while (window != 0 && window >= sF->GetSegSize())
            { // In case case more than one packet can be sent, if subflow's window allow
              if (SendDataPacket(sF->m_routeId, window, false) == 0)
                return false;
              window = std::min(AvailableWindow(sFlowIdx), sF->GetSegSize());
            }
        }

      else
        { // SendingBuffer & SubflowBuffer are EMPTY!!
          NS_LOG_WARN ("MpTcpSocketBase::SendPendingData: SubflowBuffer is empty");
          return false; // Nothing to re-send!!
        }
    }
  #endif

  #if 0
  std::pair<SequenceNumber32, uint32_t> mapping;
  while(amountOfDataToSend > 0)
  {

    if(i >= m_metaSock->GetNSubflows())
    {
//      NS_LOG_DEBUG("reached limit of number of subflows");
      break;
    }

    Ptr<MpTcpSubFlow> sf = m_metaSock->GetSubflow(i);
    uint32_t window = sf->GetTxAvailable(); //AvailableWindow is protected

    if( window > 0)
    {
      // generate mapping
      std::pair<SequenceNumber32, uint32_t> mapping = std::make_pair( m_metaSock->m_nextTxSequence, window );


      // update value
      m_metaSock->m_nextTxSequence += window;
      amountOfDataToSend = m_metaSock->m_txBuffer.SizeFromSequence(m_metaSock->m_nextTxSequence);
    }
    mappings.push_back( std::make_pair(i,mapping ) );
    i++;
  }



  for(int i = 0; i < m_metaSock->GetNSubflows(); i++ )
  {
    Ptr<MpTcpSubFlow> sf = m_metaSock->GetSubflow(i);
    //std::min(
    uint32_t window = sf->AvailableWindow();


    m_nextTxSequence
  }


  uint32_t nOctetsSent = 0;
  Ptr<MpTcpSubFlow> sFlow;

  // TODO let scheduler generate a mapping then send data according to the mapping
  DataBuffer* sendingBuffer =

  uint16_t availableWin = m_metaSock->AvailableWindow();
  uint16_t availableWin = m_metaSock->AvailableWindow();

  // Send data as much as possible (it depends on subflows AvailableWindow and data in sending buffer)
  while (!availableWin)
    {
      uint8_t count = 0;
//      uint32_t window = 0;
      // Search for a subflow with available windows
      while (count < m_metaSock->GetNSubflows())
        {
          count++;
          window = std::min(
                m_metaSock->GetTxAvailable(),
//                AvailableWindow(m_lastUsedFlowId),
                sendingBuffer->PendingData()
                ); // Get available window size

          if (window == 0)
            {  // No more available window in the current subflow, try with another one
              NS_LOG_WARN("SendPendingData-> No window available on (" << (int)m_lastUsedFlowId << ")");
              m_lastUsedFlowId = getSubflowToUse();
            }
          else
            {
              NS_LOG_LOGIC ("MpTcpSocketBase::SendPendingData -> PendingData (" << sendingBuffer->PendingData() << ") Available window ("<<AvailableWindow (m_lastUsedFlowId)<<")");
              break;
            }
        }

      // No available window for transmission in all subflows, abort sending
      if (count == m_subflows.size() && window == 0)
        break;

      // Take a pointer to the subflow with available window.
//      sFlow = m_algoCC->Get
      sFlow = m_subflows[m_lastUsedFlowId];

      // By this condition only connection initiator can send data need to be change though!
      if (sFlow->state == ESTABLISHED)
        {
//          m_currentSublow = sFlow->m_routeId;
          uint32_t s = std::min(window, sFlow->GetSegSize());  // Send no more than window
          if (sFlow->maxSeqNb > sFlow->TxSeqNumber && sendingBuffer->PendingData() <= sFlow->GetSegSize())
            s = sFlow->GetSegSize();
          uint32_t amountSent = SendDataPacket(sFlow->m_routeId, s, false);
          nOctetsSent += amountSent;  // Count total bytes sent in this loop
        } // end of if statement
      m_lastUsedFlowId = getSubflowToUse();
    } // end of main while loop

  NS_LOG_LOGIC ("SendPendingData -> amount data sent = " << nOctetsSent << "... Notify application.");
  NotifyDataSent(GetTxAvailable());
  return (nOctetsSent > 0);
  #endif
  return 0;
}




} // end of 'ns3'
