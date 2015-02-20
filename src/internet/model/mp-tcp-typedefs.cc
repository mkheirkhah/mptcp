#include <iostream>
#include <set>
#include "ns3/mp-tcp-typedefs.h"
#include "ns3/simulator.h"
#include "ns3/log.h"


NS_LOG_COMPONENT_DEFINE("MpTcpMapping");

namespace ns3
{

MpTcpMapping::MpTcpMapping() :
  m_dataSequenceNumber(0),
  m_subflowSequenceNumber(0),
  m_dataLevelLength(0)
{
  NS_LOG_FUNCTION(this);
}

MpTcpMapping::~MpTcpMapping(void)
{
  NS_LOG_FUNCTION(this);
};

void
MpTcpMapping::SetMappingSize(uint16_t const& length)
{
  NS_LOG_DEBUG(this << " length=" << length);
  m_dataLevelLength = length;
}

bool
MpTcpMapping::TranslateSSNToDSN(const SequenceNumber32& ssn, SequenceNumber32& dsn) const
{
  if(IsSSNInRange(ssn))
  {
//      dsn =
//    NS_FATAL_ERROR("TODO");
  // TODO check for seq wrapping ? PAWS
    dsn = SequenceNumber32(ssn - HeadSSN()) + HeadDSN();
    return true;
  }

  return false;
}


std::ostream&
operator<<(std::ostream& os, const MpTcpMapping& mapping)
{
  //
  os << "DSN [" << mapping.HeadDSN() << "-" << mapping.TailDSN ()
  //of size [" << mapping.GetLength() <<"] from DSN [" << mapping.HeadDSN()
    << "] mapped to SSN [" <<  mapping.HeadSSN() << "-" <<  mapping.TailSSN() << "]";
  return os;
}

void
MpTcpMapping::SetHeadDSN(SequenceNumber32 const& dsn)
{
  NS_LOG_DEBUG(this << " headDSN=" << dsn);
  m_dataSequenceNumber = dsn;
}


void
MpTcpMapping::MapToSSN( SequenceNumber32 const& seq)
{
  NS_LOG_DEBUG(this << " mapping to ssn=" << seq);
  m_subflowSequenceNumber = seq;
}

// n'est jamais utilisé en fait
//bool
//MpTcpMapping::Intersect(const MpTcpMapping& mapping) const
//{
//  //!
//  return( IsSSNInRange( mapping.HeadSSN()) || IsSSNInRange( mapping.TailSSN())
//         || IsDSNInRange( mapping.HeadDSN()) || IsDSNInRange( mapping.TailDSN()) );
//}

bool
MpTcpMapping::operator==(const MpTcpMapping& mapping) const
{
  //!
  return (
    GetLength() == mapping.GetLength()
    && HeadDSN() == mapping.HeadDSN()
    && HeadSSN() == mapping.HeadSSN()
//    && GetLength()  == GetLength()
    );
}

bool
MpTcpMapping::operator!=( const MpTcpMapping& mapping) const
{
  //!
  return !( *this == mapping);
}


SequenceNumber32
MpTcpMapping::HeadDSN() const
{
  return m_dataSequenceNumber;
}


SequenceNumber32
MpTcpMapping::HeadSSN() const
{
  return m_subflowSequenceNumber;
}

uint16_t
MpTcpMapping::GetLength() const
{
//  NS_LOG_FUNCTION(this);
  return m_dataLevelLength;
}


SequenceNumber32
MpTcpMapping::TailDSN(void) const
{
  return(HeadDSN()+GetLength()-1);
}

SequenceNumber32
MpTcpMapping::TailSSN(void) const
{
  return(HeadSSN()+GetLength()-1);
}

bool
MpTcpMapping::operator<(MpTcpMapping const& m) const
{

  return (HeadDSN() < m.HeadDSN());
}


bool
MpTcpMapping::IsSSNInRange(SequenceNumber32 const& ssn) const
{
//  return OverlapRangeSSN(ssn,0);
  return ( (HeadSSN() <= ssn) && (TailSSN() >= ssn) );
}

bool
MpTcpMapping::IsDSNInRange(SequenceNumber32 const& dsn) const
{
//  return OverlapRangeDSN(dsn,0);
  return ( (HeadDSN() <= dsn) && (TailDSN() >= dsn) );
}


//SequenceNumber32 subflowSeqNb
//void
//MpTcpMapping::Configure(SequenceNumber32  dataSeqNb, uint16_t mappingSize)
////  m_dataSeqNumber(dataSeqNb),
////  m_size(mappingSize)
//{
//  NS_LOG_LOGIC(this << "dsn [" << dataSeqNb << "], mappingSize [" << mappingSize << "]");
//  m_dataSequenceNumber = dataSeqNb;
//  m_dataLevelLength = mappingSize;
//}


bool
MpTcpMapping::OverlapRangeSSN(const SequenceNumber32& headSSN, const uint16_t& len) const
{
  SequenceNumber32 tailSSN = headSSN + len-1;
  //!
  if( HeadSSN() >  tailSSN || TailSSN() < headSSN) {
    return false;
  }
  NS_LOG_DEBUG("SSN overlap");
  return true;
}

bool
MpTcpMapping::OverlapRangeDSN(const SequenceNumber32& headDSN, const uint16_t& len) const
{
  SequenceNumber32 tailDSN = headDSN + len-1;
  //!
  if( HeadDSN() >  tailDSN || TailDSN() < headDSN) {

    return false;
  }

  NS_LOG_DEBUG("DSN overlap");
  return true;
}

///////////////////////////////////////////////////////////
///// MpTcpMappingContainer
/////
MpTcpMappingContainer::MpTcpMappingContainer(void)
//:  m_txBuffer(0)
  //,
//  m_rxBuffer(0)
{
  NS_LOG_LOGIC(this);
}

MpTcpMappingContainer::~MpTcpMappingContainer(void)
{
  NS_LOG_LOGIC(this);
}

void
MpTcpMappingContainer::Dump() const
{
  NS_LOG_UNCOND("\n==== Dumping list of mappings ====");
  for( MappingList::const_iterator it = m_mappings.begin(); it != m_mappings.end(); it++ )
  {
    NS_LOG_UNCOND( *it );
  }
  NS_LOG_UNCOND("==== End of dump ====\n");
}
//
//void
//MpTcpMappingContainer::DiscardMappingsUpToSSN(const SequenceNumber32& ssn)
//{
//  //!
//  for( MappingList::iterator it = m_mappings.begin(); it != m_mappings.end(); it++ )
//  {
//
//    NS_LOG_UNCOND( *it );
//
//  }
//
//}

//bool
//MpTcpMappingContainer::CheckIfMappingCovered(std::vector<MpTcpMapping>& mappings) {
//
//
//}


//bool
//MpTcpMappingContainer::FindOverlappingMapping(SequenceNumber32 start, uint32_t len,  MpTcpMapping& ret)
//{
//
//}


// This is wrong
bool
//MpTcpMappingContainer::FindOverlappingMapping(SequenceNumber32 headSSN, uint32_t len,  MpTcpMapping& ret) const
MpTcpMappingContainer::FindOverlappingMapping(const MpTcpMapping& mapping, bool ignore_identical, MpTcpMapping& ret) const
{
//  SequenceNumber32 tailSSN = headSSN + SequenceNumber32(len);
  NS_LOG_DEBUG("Looking for a mapping that overlaps with " << mapping );
  for( MappingList::const_iterator it = m_mappings.begin(); it != m_mappings.end(); it++ )
  {
    // Check if mappings overlap
//    if(it->IsSSNInRange(mapping) && mapping != *it )
  // Faux si le mapping est encore plus petit
    if(it->OverlapRangeSSN(mapping.HeadSSN(), mapping.GetLength())
      || it->OverlapRangeDSN(mapping.HeadDSN(), mapping.GetLength()) )
    {
      if( ignore_identical && (*it == mapping))
      {
        NS_LOG_DEBUG("Ignoring identical mapping " << *it);
        continue;
      }

      // Intersect, il devrait continuer ptet qu'il y en a un autre
      NS_LOG_WARN("Mapping " << mapping << " intersects with " << *it );
      ret = *it;
      return true;
    }

  }
  return false;
}

#if 0
//MpTcpMappingContainer::FindOverlappingMapping(SequenceNumber32 headSSN, uint32_t len,  MpTcpMapping& ret) const
MpTcpMappingContainer::FindOverlappingMapping(const MpTcpMapping& mapping,  MpTcpMapping& ret) const
{
  SequenceNumber32 tailSSN = headSSN + SequenceNumber32(len);
  NS_LOG_DEBUG("Looking for a mapping that overlaps with [" << headSSN << "- " << tailSSN << "]");
  for( MappingList::const_iterator it = m_mappings.begin(); it != m_mappings.end(); it++ )
  {
    // Check if mappings overlap
//    if(it->IsSSNInRange(mapping) && mapping != *it )
  // Faux si le mapping est encore plus petit
    if(it->IsSSNInRange(headSSN) || it->IsSSNInRange(tailSSN) )
    {

      // Intersect
      NS_LOG_DEBUG("Mapping intersects with " << *it );
      ret = *it;
      return true;
    }

  }
  return false;
}
#endif



//! should return a boolean
bool
MpTcpMappingContainer::AddMapping(const MpTcpMapping& mapping)
//MpTcpMappingContainer::AddMappingEnforceSSN(const MpTcpMapping& mapping)
{
  NS_LOG_LOGIC("Adding mapping " << mapping);
  MpTcpMapping temp;

  // pr l'instant ca le fait sur le
//  if(FindOverlappingMapping(mapping.HeadSSN(), mapping.GetLength(), temp) && (temp != mapping) )
  if(FindOverlappingMapping(mapping, true, temp))
  {

    // the mappings may be similar
//    if(temp == mapping)
//    {
//      NS_LOG_WARN("Trying to add twice the same mapping " << mapping << " (=" << temp);
//      return true;
//    }
    NS_LOG_WARN("Mapping " << mapping << " conflicts with existing " << temp);
    Dump();
    return false;
  }


//  std::pair<iterator,bool> =
  m_mappings.insert(mapping);
  return true;
}

/*
TODO remove
*/
//int
//MpTcpMappingContainer::AddMappingLooseSSN(MpTcpMapping& mapping)
//{
//  NS_ASSERT_MSG(m_txBuffer,"m_txBuffer not set");
//  // TODO look for duplicatas
//  mapping.MapToSSN( FirstUnmappedSSN() );
//
//  return AddMappingEnforceSSN(mapping);
//
//}

//SequenceNumber32
//MpTcpMappingContainer::FirstMappedSSN(void) const
//{
//  //!
//}

//SequenceNumber32
//MpTcpMappingContainer::FirstUnmappedSSN(void) const
//{
//  NS_ASSERT(m_txBuffer);
//  if(m_mappings.empty())
//  {
////    if(m_rxBuffer){
////      return m_rxBuffer->TailSequence();
////    }
////    else {
////      NS_ASSERT
//      // associate to first byte in buffer. This should never happen ?
//      return m_txBuffer->HeadSequence();
////    }
//  }
//    // they are sorted
////  NS_LOG_INFO("\n\n====================\n\n");
//  return m_mappings.rbegin()->TailSSN() + 1;
//}

//bool
//MpTcpMappingContainer::TranslateSSNtoDSN(const SequenceNumber32& ssn, SequenceNumber32 &dsn)
//{
//  // first find if a mapping exists
//  MpTcpMapping mapping;
//  if(!GetMappingForSSN(ssn, mapping) )
//  {
//    //!
//    return false;
//  }
//
//  return mapping.TranslateSSNToDSN(ssn,dsn);
//}

bool
MpTcpMappingContainer::DiscardMapping(const MpTcpMapping& mapping)
{
  NS_LOG_LOGIC("discard mapping "<< mapping);
//  MappingList::iterator it = l.begin(); it != l.end(); it++)
//  std::size_type count = m_mappings.erase(mapping);
//  return count != 0;
  return m_mappings.erase(mapping);
}

int
MpTcpMappingContainer::DiscardMappingsUpToSN(const SequenceNumber32& dsn,const SequenceNumber32& ssn)
{
  NS_LOG_LOGIC("Discarding mappings up with TailDSN < " << dsn << " AND TailSSN < " << ssn);

  MappingList& l = m_mappings;
  int erasedMappingCount = 0;
  // TODO use reverse iterator and then clear from first found to the begin
  for(MappingList::iterator it = l.begin(); it != l.end(); it++)
  {
    // check that meta socket
//    if( it->TailDSN() < dsn && it->TailSSN() < m_rxBuffer->NextRxSequence() )
    if( it->TailDSN() < dsn && it->TailSSN() < ssn)
    {
      //it =
//      NS_ASSERT( );
      // TODO check mapping transfer was completed on this subflow
//      if( m_txBuffer.HeadSequence() <  )
//      {
//
//      }
      erasedMappingCount++;
      l.erase(it);

      // TODO that should work
//      l.erase(m_mappings.begin(), it);
//      break;
    }
  }

  return erasedMappingCount;
}

#if 0
void
MpTcpMappingContainer::DiscardMappingsUpToDSN(const SequenceNumber32& dsn)
{
  NS_LOG_INFO("Discarding mappings up to " << dsn);
  MappingList& l = m_mappings;
  for( MappingList::iterator it = l.begin(); it != l.end(); it++ )
  {
    //HeadDSN
    if( it->TailDSN() < dsn )
    {
      //it =
//      NS_ASSERT( );
      // TODO check mapping transfer was completed on this subflow
//      if( m_txBuffer.HeadSequence() <  )
//      {
//
//      }
      l.erase(it);
    }
  }
}

#endif

bool
MpTcpMappingContainer::GetMappingForSSN(const SequenceNumber32& ssn, MpTcpMapping& mapping)
{
  MappingList& l = m_mappings;
  for( MappingList::const_iterator it = l.begin(); it != l.end(); it++ )
  {
    // check seq nb is within the DSN range
    if (
      it->IsSSNInRange( ssn )
//    (subflowSeqNb >= it->HeadSSN() ) &&
//      (subflowSeqNb < it->HeadSSN() + it->GetLength())
    )
    {
      mapping = *it;
      return true;
    }
  }

  return false;
}



} // namespace ns3
