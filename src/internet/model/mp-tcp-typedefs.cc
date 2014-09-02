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


std::ostream&
operator<<(std::ostream& os, const MpTcpMapping& mapping)
{
  //
  os << "Mapping [" << mapping.GetDataSequenceNumber() << "-" << mapping.MaxDataSequence ()
  //of size [" << mapping.GetDataLevelLength() <<"] from DSN [" << mapping.GetDataSequenceNumber()
    << "] to SSN [" <<  mapping.GetSubflowSequenceNumber() << "]";
  return os;
}

void
MpTcpMapping::SetDataSequenceNumber(SequenceNumber32 seq)
{
  m_dataSequenceNumber = seq;
}


bool
MpTcpMapping::operator==( const MpTcpMapping& mapping) const
{
  //!
  return (
    GetDataLevelLength() == mapping.GetDataLevelLength()
    && GetDataSequenceNumber() == mapping.GetDataSequenceNumber()
    && GetDataLevelLength()  == GetDataLevelLength()
    );
}

SequenceNumber32
MpTcpMapping::MaxDataSequence  (void) const
{
  return ( GetDataSequenceNumber() + GetDataLevelLength() );
}

bool
MpTcpMapping::operator<(MpTcpMapping const& m) const
{

  return (GetDataSequenceNumber() < m.GetDataSequenceNumber() );
}


bool
MpTcpMapping::IsInRange(SequenceNumber32 const& ack) const
{

  return (
    GetDataSequenceNumber() <= ack &&
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
