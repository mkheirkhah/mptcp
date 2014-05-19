//#include "mp-tcp-header.h"
////#include "ns3/tcp-header"
//
//#include "ns3/address-utils.h"
//
//#include "ns3/log.h"
//
//#include <vector>
//
//
//NS_LOG_COMPONENT_DEFINE ("MpTcpHeader");
//
//using namespace std;
//
//namespace ns3 {
//
//NS_OBJECT_ENSURE_REGISTERED (MpTcpHeader);
//
//TypeId
//MpTcpHeader::GetInstanceTypeId (void) const
//{
//  return GetTypeId ();
//}
//
//void MpTcpHeader::Print (std::ostream &os)
//{
//  uint8_t flags = GetFlags();
//  os << GetSourcePort() << " > " << GetDestinationPort();
//  if(flags!=0)
//  {
//    os<<" [";
//    if((flags & FIN) != 0)
//    {
//      os<<" FIN ";
//    }
//    if((flags & SYN) != 0)
//    {
//      os<<" SYN ";
//    }
//    if((flags & RST) != 0)
//    {
//      os<<" RST ";
//    }
//    if((flags & PSH) != 0)
//    {
//      os<<" PSH ";
//    }
//    if((flags & ACK) != 0)
//    {
//      os<<" ACK ";
//    }
//    if((flags & URG) != 0)
//    {
//      os<<" URG ";
//    }
//    os<<"]";
//  }
//  os<<" Seq="<< GetSequenceNumber() <<" Ack="<< GetAckNumber() <<" Win="<< GetWindowSize();
//
//  //         write options in head
//
//  for(uint32_t j=0; j < m_option.size(); j++)
//  {
//      TcpOptions *opt = m_option[j];
//      OptMultipathCapable *optMPC;
//      OptJoinConnection *optJOIN;
//      OptAddAddress *optADDR;
//      OptRemoveAddress *optREMADR;
//      OptDataSeqMapping *optDSN;
//      OptTimesTamp *optTT;
//
//      os << opt->optName;
//
//      if (opt->optName == OPT_MPC)
//      {
//          optMPC = (OptMultipathCapable *) opt;
//          os << optMPC->senderToken;
//      }else if(opt->optName == OPT_JOIN)
//      {
//          optJOIN = (OptJoinConnection *) opt;
//          os << optJOIN->receiverToken;
//          os << optJOIN->addrID;
//      }else if(opt->optName == OPT_ADDR)
//      {
//          optADDR = (OptAddAddress *) opt;
//          os << optADDR->addrID;
//          optADDR->addr.Print( os );
//      }else if(opt->optName == OPT_REMADR)
//      {
//          optREMADR = (OptRemoveAddress *) opt;
//          os << optREMADR->addrID;
//      }else if(opt->optName == OPT_DSN)
//      {
//          optDSN = (OptDataSeqMapping *) opt;
//          os << optDSN->dataSeqNumber;
//          os << optDSN->dataLevelLength;
//          os << optDSN->subflowSeqNumber;
//      }else if(opt->optName == OPT_TT)
//      {
//          optTT = (OptTimesTamp *) opt;
//          os << optTT->TSval;
//          os << optTT->TSecr;
//      }else if(opt->optName == OPT_DSACK)
//      {
//          OptDSACK* optDSACK = (OptDSACK *) opt;
//          os << optDSACK->blocks[0]; // left Edge  of the first block
//          os << optDSACK->blocks[1]; // right Edge of the first block
//          os << optDSACK->blocks[2]; // left Edge  of the second block
//          os << optDSACK->blocks[3]; // right Edge of the second block
//      }
//  }
//}
//
//void
//MpTcpHeader::SetOptionsLength(uint8_t length)
//{
//    oLen = length;
//}
//
//vector< TcpOptions* >
//MpTcpHeader::GetOptions(void) const
//{
//    return m_option;
//}
//
//void
//MpTcpHeader::SetOptions(vector<TcpOptions*> opt)
//{
//    m_option = opt;
//}
//
//uint8_t
//MpTcpHeader::GetOptionsLength() const
//{
//  uint8_t length = 0;
//  TcpOptions *opt;
//
//  for(uint32_t j = 0; j < m_option.size(); j++)
//  {
//      opt = m_option[j];
//
//      if (opt->optName == OPT_MPC)
//      {
//          length += 5;
//      }else if(opt->optName == OPT_JOIN)
//      {
//          length += 6;
//      }else if(opt->optName == OPT_ADDR)
//      {
//          length += 6;
//      }else if(opt->optName == OPT_REMADR)
//      {
//          length += 2;
//      }else if(opt->optName == OPT_DSN)
//      {
//          length += 15;
//      }
//  }
//  //return oLen;
//  return length;
//}
//
//void
//MpTcpHeader::SetPaddingLength(uint8_t length)
//{
//    pLen = length;
//}
//
//uint8_t
//MpTcpHeader::GetPaddingLength() const
//{
//    return pLen;
//}
//
//uint32_t MpTcpHeader::GetSerializedSize (void) const
//{
//    NS_LOG_FUNCTION_NOARGS();
//  return 4 * GetLength() + GetOptionsLength();
//}
//
//uint8_t
//MpTcpHeader::TcpOptionToUint(TcpOption_t opt) const
//{
//    NS_LOG_FUNCTION_NOARGS();
//    uint8_t i = 0;
//
//    if(opt == OPT_MPC)
//        i = 30;
//    else if(opt == OPT_JOIN)
//        i = 31;
//    else if(opt == OPT_ADDR)
//        i = 32;
//    else if(opt == OPT_REMADR)
//        i = 33;
//    else if(opt == OPT_DSN)
//        i = 34;
//    else if(opt == OPT_DSACK)
//        i = 5;
//    else if(opt == OPT_NONE)
//        i = 0;
//    else if(opt == OPT_TT)
//        i = 8; // IANA value is 8
//
//    return i;
//}
//
//TcpOption_t
//MpTcpHeader::UintToTcpOption(uint8_t kind) const
//{
//    NS_LOG_FUNCTION_NOARGS();
//    TcpOption_t i = OPT_NONE;
//
//    if(kind == 30)
//        i = OPT_MPC;
//    else if(kind == 31)
//        i = OPT_JOIN;
//    else if(kind == 32)
//        i = OPT_ADDR;
//    else if(kind == 33)
//        i = OPT_REMADR;
//    else if(kind == 34)
//        i = OPT_DSN;
//    else if(kind == 5)
//        i = OPT_DSACK;
//    else if(kind == 0)
//        i = OPT_NONE;
//    else if(kind == 8)
//        i = OPT_TT; // IANA value is 8
//
//    return i;
//}
//
//void MpTcpHeader::Serialize (Buffer::Iterator start) const
//{
//    NS_LOG_FUNCTION(this);
//  Buffer::Iterator i = start;
//  i.WriteHtonU16 (GetSourcePort());
//  i.WriteHtonU16 (GetDestinationPort());
//  i.WriteHtonU32 (GetSequenceNumber().GetValue()); // WriteHtonU32(uint32_t) so use GetValue()
//  i.WriteHtonU32 (GetAckNumber().GetValue());      // WriteHtonU32(uint32_t) so use GetValue()
//  i.WriteHtonU16 ((GetLength() << 12) | GetFlags()); //reserved bits are all zero
//  i.WriteHtonU16 (GetWindowSize());
//  i.WriteHtonU16 (0);
//  i.WriteHtonU16 (GetUrgentPointer());
//
//  /*if(m_calcChecksum)
//  {
//    uint16_t headerChecksum = CalculateHeaderChecksum (start.GetSize ());
//    i = start;
//    uint16_t checksum = i.CalculateIpChecksum(start.GetSize (), headerChecksum);
//
//    i = start;
//    i.Next(16);
//    i.WriteU16(checksum);
//  } */
//
//  //         write options in head
//  for(uint32_t j=0; j < m_option.size(); j++)
//  {
//      TcpOptions *opt = m_option[j];
//      OptMultipathCapable *optMPC;
//      OptJoinConnection *optJOIN;
//      OptAddAddress *optADDR;
//      OptRemoveAddress *optREMADR;
//      OptDataSeqMapping  *optDSN;
//      OptTimesTamp *optTT;
//      NS_LOG_INFO("MpTcpHeader: optName == " << opt->optName);
//      i.WriteU8(TcpOptionToUint (opt->optName));
//
//      if (opt->optName == OPT_MPC)
//      {
//          optMPC = (OptMultipathCapable *) opt;
//          i.WriteHtonU32(optMPC->senderToken);
//      }else if(opt->optName == OPT_JOIN)
//      {
//          optJOIN = (OptJoinConnection *) opt;
//          i.WriteHtonU32(optJOIN->receiverToken);
//          i.WriteU8(optJOIN->addrID);
//      }else if(opt->optName == OPT_ADDR)
//      {
//          optADDR = (OptAddAddress *) opt;
//          i.WriteU8(optADDR->addrID);
//          i.WriteHtonU32(optADDR->addr.Get());
//      }else if(opt->optName == OPT_REMADR)
//      {
//          optREMADR = (OptRemoveAddress *) opt;
//          i.WriteU8(optREMADR->addrID);
//      }else if(opt->optName == OPT_DSN)
//      {
//          optDSN = (OptDataSeqMapping *) opt;
//          i.WriteU64(optDSN->dataSeqNumber);
//          i.WriteHtonU16(optDSN->dataLevelLength);
//          i.WriteHtonU32(optDSN->subflowSeqNumber);
//      }else if(opt->optName == OPT_TT) // Option TCP TimesTamp
//      {
//          optTT = (OptTimesTamp *) opt;
//          i.WriteU64(optTT->TSval);
//          i.WriteU64(optTT->TSecr);
//      }else if(opt->optName == OPT_DSACK) // Option Duplicate SACK
//      {
//          OptDSACK *dsak = (OptDSACK *) opt;
//          i.WriteU64(dsak->blocks[0]);  // left Edge  of the first block
//          i.WriteU64(dsak->blocks[1]);  // right Edge  of the first block
//          i.WriteU64(dsak->blocks[2]);  // left Edge  of the second block
//          i.WriteU64(dsak->blocks[3]);  // right Edge  of the second block
//          NS_LOG_LOGIC("Serialize -> fstLeft ("<< dsak->blocks[0] <<") fstRight ("<< dsak->blocks[1] <<") sndLeft ("<< dsak->blocks[2] <<") sndRight ("<< dsak->blocks[3] <<")");
//      }
//  }
//  for(int j = 0; j < (int)pLen; j++)
//      i.WriteU8(255);
//NS_LOG_INFO("MpTcpHeader::Serialize options length  olen = " << (int)oLen);
//NS_LOG_INFO("MpTcpHeader::Serialize padding length  plen = " << (int)pLen);
//}
//
//uint32_t MpTcpHeader::Deserialize (Buffer::Iterator start)
//{
//    NS_LOG_FUNCTION(this);
//    uint8_t hlen = 0;
//    uint8_t plen = 0;
//  Buffer::Iterator i = start;
//  SetSourcePort (i.ReadNtohU16 ());
//  SetDestinationPort (i.ReadNtohU16 ());
//  SetSequenceNumber (SequenceNumber32(i.ReadNtohU32 ()));   // Morteza Kheirkhah
//  SetAckNumber (SequenceNumber32(i.ReadNtohU32 ()));        // Morteza Kheirkhah
//  uint16_t field = i.ReadNtohU16 ();
//  SetFlags (field & 0x3F);
//  hlen = (field>>12);
//  SetLength (hlen);
//  SetWindowSize (i.ReadNtohU16 ());
//  i.Next (2);
//  SetUrgentPointer (i.ReadNtohU16 ());
//
//  hlen = (hlen - 5) * 4;
//
//  /*if(m_calcChecksum)
//    {
//      uint16_t headerChecksum = CalculateHeaderChecksum (start.GetSize ());
//      i = start;
//      uint16_t checksum = i.CalculateIpChecksum(start.GetSize (), headerChecksum);
//      m_goodChecksum = (checksum == 0);
//    }*/
//
//  // handle options field
//NS_LOG_INFO("MpTcpHeader::Deserialize looking for options");
//  while( ! i.IsEnd() && hlen > 0)
//  {
//      TcpOptions *opt;
//
//      TcpOption_t kind = (TcpOption_t) i.ReadU8();
//NS_LOG_INFO("MpTcpHeader::Deserialize options found: " << kind << ", hlen = " << (int)hlen);
//      if (kind == OPT_MPC)
//      {
//          opt = new OptMultipathCapable (kind, i.ReadNtohU32());
//          plen = (plen + 5) % 4;
//          hlen -= 5;
//      }else if(kind == OPT_JOIN)
//      {
//          opt = new OptJoinConnection (kind, i.ReadNtohU32(), i.ReadU8());
//          plen = (plen + 6) % 4;
//          hlen -= 6;
//      }else if(kind == OPT_ADDR)
//      {
//          opt = new OptAddAddress (kind, i.ReadU8(), Ipv4Address(i.ReadNtohU32()));
//          plen = (plen + 6) % 4;
//          hlen -= 6;
//      }else if(kind == OPT_REMADR)
//      {
//          opt = new OptRemoveAddress (kind, i.ReadU8());
//          plen = (plen + 2) % 4;
//          hlen -= 2;
//      }else if(kind == OPT_DSN)
//      {
//          opt = new OptDataSeqMapping (kind, i.ReadU64(), i.ReadNtohU16(), i.ReadNtohU32());
//          plen = (plen + 15) % 4;
//          hlen -= 15;
//      }else if(kind == OPT_TT)
//      {
//          opt = new OptTimesTamp (kind, i.ReadU64(), i.ReadU64());
//          plen = (plen + 17) % 4;
//          hlen -= 17;
//      }else if(kind == OPT_DSACK)
//      {
//          OptDSACK *dsak = new OptDSACK(kind);
//          uint64_t fstLeft = i.ReadU64(), fstRight = i.ReadU64();
//          uint64_t sndLeft = i.ReadU64(), sndRight = i.ReadU64();
//          dsak->AddfstBlock(fstLeft, fstRight);
//          dsak->AddBlock(sndLeft, sndRight);
//          NS_LOG_LOGIC("Deserialize -> fstLeft ("<< dsak->blocks[0] <<") fstRight ("<< dsak->blocks[1] <<") sndLeft ("<< dsak->blocks[2] <<") sndRight ("<< dsak->blocks[3] <<")");
//          opt = dsak;
//          plen = (plen + 33) % 4;
//          hlen -= 33;
//      }else
//      {
//          // the rest are pending octets, so leave
//          hlen = 0;
//          break;
//      }
//
//      m_option.insert(m_option.end(), opt);
//
//  }
//  i.Next (plen);
//  NS_LOG_INFO("MpTcpHeader::Deserialize leaving this method");
//
//  return GetSerializedSize ();
//}
//
//TcpOptions::TcpOptions(void)
//    : optName (OPT_NONE)
//{
//    //NS_LOG_FUNCTION_NOARGS();
//}
//
//TcpOptions::~TcpOptions(void)
//{
//    //NS_LOG_FUNCTION_NOARGS();
//    optName = OPT_NONE;
//}
//
//OptMultipathCapable::OptMultipathCapable(TcpOption_t oName, uint32_t TxToken)
//{
//    NS_LOG_FUNCTION(this << oName << TxToken);
//    optName     = oName;
//    Length      = 5; // field "length" is not insert in the packet
//    senderToken = TxToken;
//}
//
//OptMultipathCapable::~OptMultipathCapable()
//{
//    NS_LOG_FUNCTION_NOARGS();
//    optName     = OPT_NONE;
//    Length      = 0; // field "length" is not insert in the packet
//    senderToken = 0;
//}
//
//OptJoinConnection::OptJoinConnection(TcpOption_t oName, uint32_t RxToken, uint8_t aID)
//{
//    NS_LOG_FUNCTION(this << oName << RxToken << aID);
//    optName       = oName;
//    Length        = 6;
//    receiverToken = RxToken;
//    addrID        = aID;
//}
//
//OptJoinConnection::~OptJoinConnection()
//{
//    NS_LOG_FUNCTION_NOARGS();
//    optName       = OPT_NONE;
//    Length        = 0;
//    receiverToken = 0;
//    addrID        = 0;
//}
//
//OptAddAddress::OptAddAddress(TcpOption_t oName, uint8_t aID, Ipv4Address address)
//{
//    NS_LOG_FUNCTION(this << oName << aID << address);
//    optName  = oName;
//    Length   = 6;
//    addrID   = aID;
//    addr     = address;
//}
//
//OptAddAddress::~OptAddAddress()
//{
//    NS_LOG_FUNCTION_NOARGS();
//    optName  = OPT_NONE;
//    Length   = 0;
//    addrID   = 0;
//    addr     = Ipv4Address::GetZero();
//}
//
//OptRemoveAddress::OptRemoveAddress(TcpOption_t oName, uint8_t aID)
//{
//    NS_LOG_FUNCTION(this << oName << aID);
//    optName  = oName;
//    Length   = 5;
//    addrID   = aID;
//}
//
//OptRemoveAddress::~OptRemoveAddress()
//{
//    NS_LOG_FUNCTION_NOARGS();
//    optName  = OPT_NONE;
//    Length   = 0;
//    addrID   = 0;
//}
//
//OptDataSeqMapping::OptDataSeqMapping(TcpOption_t oName, uint64_t dSeqNum, uint16_t dLevelLength, uint32_t sfSeqNum)
//{
//    NS_LOG_FUNCTION(this << oName << dSeqNum << dLevelLength << sfSeqNum);
//    optName  = oName;
//    Length      = 11;
//    dataSeqNumber   = dSeqNum;
//    dataLevelLength = dLevelLength;
//    subflowSeqNumber = sfSeqNum;
//}
//
//OptDataSeqMapping::~OptDataSeqMapping()
//{
//    NS_LOG_FUNCTION_NOARGS();
//    optName  = OPT_NONE;
//    Length      = 0;
//    dataSeqNumber  = 0;
//    dataLevelLength = 0;
//    subflowSeqNumber = 0;
//}
//
//OptTimesTamp::OptTimesTamp(TcpOption_t oName, uint64_t tsval, uint64_t tsecr)
//{
//    NS_LOG_FUNCTION(this << oName << tsval << tsecr);
//    optName = oName;
//    Length  = 17;
//    TSval   = tsval;
//    TSecr   = tsecr;
//}
//
//OptTimesTamp::~OptTimesTamp()
//{
//    NS_LOG_FUNCTION_NOARGS();
//    optName  = OPT_NONE;
//    TSval    = 0;
//    TSecr    = 0;
//}
//
//OptDSACK::OptDSACK(TcpOption_t oName)
//  : blocks (0)
//{
//    optName = oName;
//}
//
//void
//OptDSACK::AddBlock (uint64_t leftEdge, uint64_t rightEdge)
//{
//    blocks.insert (blocks.end(), leftEdge);
//    blocks.insert (blocks.end(), rightEdge);
//}
//
//void
//OptDSACK::AddfstBlock (uint64_t leftEdge, uint64_t rightEdge)
//{
//    // we first insert the right edge in the begining then the left edge to keep the order
//    blocks.insert (blocks.begin(), rightEdge);
//    blocks.insert (blocks.begin(), leftEdge);
//}
//
//OptDSACK::~OptDSACK()
//{
//    NS_LOG_FUNCTION_NOARGS();
//    blocks.clear ();
//}
//
//TypeId
//MpTcpHeader::GetTypeId (void)
//{
//    static TypeId tid = TypeId("ns3::MpTcpHeader")
//                    .SetParent<TcpHeader>();
//    return tid;
//}
//
//MpTcpHeader::MpTcpHeader ()
//  : m_option (0), oLen (0), pLen(0), original (true)
//{
//    NS_LOG_FUNCTION_NOARGS();
//}
//
//MpTcpHeader::MpTcpHeader (const MpTcpHeader &res)
//{
//    NS_LOG_FUNCTION_NOARGS();
//    SetSourcePort      ( res.GetSourcePort () );
//    SetDestinationPort ( res.GetDestinationPort () );
//    SetFlags           ( res.GetFlags () );
//    SetSequenceNumber  ( res.GetSequenceNumber () );
//    SetAckNumber       ( res.GetAckNumber () );
//    SetWindowSize      ( res.GetWindowSize () );
//    //SetOptions         ( res.GetOptions () );
//    SetLength          ( res.GetLength () );
//    SetOptionsLength   ( res.GetOptionsLength () );
//    SetPaddingLength   ( res.GetPaddingLength () );
//    SetOptions         ( res.GetOptions () );
//    original           = false;
//}
//
//MpTcpHeader
//MpTcpHeader::Copy ()
//{
//    MpTcpHeader l4Header;
//    NS_LOG_FUNCTION_NOARGS();
//    l4Header.SetSourcePort      ( GetSourcePort () );
//    l4Header.SetDestinationPort ( GetDestinationPort () );
//    l4Header.SetFlags           ( GetFlags () );
//    l4Header.SetSequenceNumber  ( GetSequenceNumber () );
//    l4Header.SetAckNumber       ( GetAckNumber () );
//    l4Header.SetWindowSize      ( GetWindowSize () );
//    l4Header.SetOptions         ( GetOptions () );
//    l4Header.SetLength          ( GetLength () );
//    l4Header.SetOptionsLength   ( GetOptionsLength () );
//    l4Header.SetPaddingLength   ( GetPaddingLength () );
//    return l4Header;
//}
//
//MpTcpHeader::~MpTcpHeader ()
//{
//    if ( original == false )
//        return;
//    NS_LOG_FUNCTION_NOARGS();
//    for(uint32_t i=0; i < m_option.size() ; i++)
//    {
//        if ( m_option[i] != 0 )
//        switch( m_option[i]->optName )
//        {
//            case OPT_MPC:
//                delete (OptMultipathCapable*) m_option[i];
//                break;
//            case OPT_JOIN:
//                delete (OptJoinConnection*) m_option[i];
//                break;
//            case OPT_ADDR:
//                delete (OptAddAddress*) m_option[i];
//                break;
//            case OPT_REMADR:
//                delete (OptRemoveAddress*) m_option[i];
//                break;
//            case OPT_DSN:
//                delete (OptDataSeqMapping*) m_option[i];
//                break;
//            case OPT_TT:
//                delete (OptTimesTamp*) m_option[i];
//                break;
//            default:
//                break;
//        }
//    }
//    m_option.clear();
//    oLen = 0;
//}
//
//bool
//MpTcpHeader::AddOptMPC(TcpOption_t optName, uint32_t TxToken)
//{
//    NS_LOG_FUNCTION(this);
//    if (optName == OPT_MPC)
//    {
//        OptMultipathCapable* opt = new OptMultipathCapable(optName, TxToken);
//
//        m_option.insert(m_option.end(), opt);
//
//        return true;
//    }
//    return false;
//}
//
//bool
//MpTcpHeader::AddOptJOIN(TcpOption_t optName, uint32_t RxToken, uint8_t addrID)
//{
//    NS_LOG_FUNCTION(this);
//    if (optName == OPT_JOIN)
//    {
//        OptJoinConnection* opt = new OptJoinConnection(optName, RxToken, addrID);
//
//        m_option.insert(m_option.end(), opt);
//        return true;
//    }
//    return false;
//}
//
//bool
//MpTcpHeader::AddOptADDR(TcpOption_t optName, uint8_t addrID, Ipv4Address addr)
//{
//    NS_LOG_FUNCTION(this);
//    if (optName == OPT_ADDR)
//    {
//        OptAddAddress* opt = new OptAddAddress(optName, addrID, addr);
//
//        m_option.insert(m_option.end(), opt);
//        return true;
//    }
//    return false;
//}
//
//bool
//MpTcpHeader::AddOptREMADR(TcpOption_t optName, uint8_t addrID)
//{
//    NS_LOG_FUNCTION(this);
//    if (optName == OPT_REMADR)
//    {
//        OptRemoveAddress* opt = new OptRemoveAddress(optName, addrID);
//
//        m_option.insert(m_option.end(), opt);
//        return true;
//    }
//    return false;
//}
//
//bool
//MpTcpHeader::AddOptDSN(TcpOption_t optName, uint64_t dSeqNum, uint16_t dLevelLength, uint32_t sfSeqNum)
//{
//    NS_LOG_FUNCTION(this);
//    if (optName == OPT_DSN)
//    {
//        OptDataSeqMapping* opt = new OptDataSeqMapping(optName, dSeqNum, dLevelLength, sfSeqNum);
//
//        m_option.insert(m_option.end(), opt);
//        return true;
//    }
//    return false;
//}
//
//bool
//MpTcpHeader::AddOptTT(TcpOption_t optName, uint64_t tsval, uint64_t tsecr)
//{
//    NS_LOG_FUNCTION(this);
//    if (optName == OPT_TT)
//    {
//        OptTimesTamp* opt = new OptTimesTamp(optName, tsval, tsecr);
//
//        m_option.insert(m_option.end(), opt);
//        return true;
//    }
//    return false;
//}
//
//bool
//MpTcpHeader::AddOptDSACK(TcpOption_t optName, OptDSACK *ptrDSAK)
//{
//    NS_LOG_FUNCTION(this);
//    if (optName == OPT_DSACK)
//    {
//        m_option.insert(m_option.end(), ptrDSAK);
//        return true;
//    }
//    return false;
//}
//}
