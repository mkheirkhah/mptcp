#include <iostream>
#include "ns3/mp-tcp-typedefs.h"
#include "ns3/simulator.h"
#include "ns3/log.h"


NS_LOG_COMPONENT_DEFINE("MpTcpTypeDefs");

namespace ns3
{

MpTcpMapping::MpTcpMapping() :
  m_dataSequenceNumber(0),
  m_subflowSequenceNumber(0),
  m_dataLevelLength(0)
{
  NS_LOG_FUNCTION(this);
}

void
MpTcpMapping::SetMappingSize(uint16_t length)
{
  m_dataLevelLength = length;
}

bool
MpTcpMapping::TranslateSSNToDSN(SequenceNumber32 ssn,SequenceNumber32& dsn) const
{
  if(IsInRange(ssn))
  {
//      dsn =
    NS_FATAL_ERROR("TODO");
    return true;
  }

  return false;
}


std::ostream&
operator<<(std::ostream& os, const MpTcpMapping& mapping)
{
  //
  os << "Mapping [" << mapping.GetDSN() << "-" << mapping.MaxDataSequence ()
  //of size [" << mapping.GetDataLevelLength() <<"] from DSN [" << mapping.GetDSN()
    << "] to SSN [" <<  mapping.GetSSN() << "]";
  return os;
}

void
MpTcpMapping::SetDSN(SequenceNumber32 seq)
{
  m_dataSequenceNumber = seq;
}


void
MpTcpMapping::MapToSSN( SequenceNumber32 seq)
{
  m_subflowSequenceNumber = seq;
}


bool
MpTcpMapping::operator==( const MpTcpMapping& mapping) const
{
  //!
  return (
    GetDataLevelLength() == mapping.GetDataLevelLength()
    && GetDSN() == mapping.GetDSN()
//    && GetDataLevelLength()  == GetDataLevelLength()
    );
}

SequenceNumber32
MpTcpMapping::MaxDataSequence  (void) const
{
  return ( GetDSN() + GetDataLevelLength() );
}

bool
MpTcpMapping::operator<(MpTcpMapping const& m) const
{

  return (GetDSN() < m.GetDSN() );
}


bool
MpTcpMapping::IsInRange(SequenceNumber32 const& ack) const
{

  return (
    GetDSN() <= ack &&
    // TODO >= ou > ?
     MaxDataSequence() >= ack
  );
}


//SequenceNumber32 subflowSeqNb
void
MpTcpMapping::Configure( SequenceNumber32  dataSeqNb, uint16_t mappingSize)
//  m_dataSeqNumber(dataSeqNb),
//  m_size(mappingSize)
{
  m_dataSequenceNumber = dataSeqNb;
  m_dataLevelLength = mappingSize;
}



/*
MpTcpAddressInfo::MpTcpAddressInfo() :
    addrID(0), ipv4Addr(Ipv4Address::GetZero()), mask(Ipv4Mask::GetZero())
{
}

MpTcpAddressInfo::~MpTcpAddressInfo()
{
  addrID = 0;
  ipv4Addr = Ipv4Address::GetZero();
}
*/

} // namespace ns3
