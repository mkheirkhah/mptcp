//#ifndef MP_TCP_HEADER_H
//#define MP_TCP_HEADER_H
//
//#include <stdint.h>
//#include <string>
//#include "ns3/header.h"
//#include "ns3/tcp-header.h"       //Morteza Kheirkhah
//#include "ns3/ipv4-address.h"
//
//#include <vector>
//
//
//using namespace std;
//
//
//namespace ns3 {
//
//typedef enum {
//    OPT_NONE   = 0,
//    OPT_DSACK  = 5,
//    OPT_TT     = 8,      // Times Tamp
//    OPT_MPC    = 30,
//    OPT_JOIN   = 31,
//    OPT_ADDR   = 32,
//    OPT_REMADR = 33,
//    OPT_DSN    = 34
//    } TcpOption_t;
//
//class TcpOptions
//{
//public:
//    TcpOptions();
//    virtual ~TcpOptions();
//
//    TcpOption_t optName;
//    uint8_t Length;
//};
//
//class OptMultipathCapable : public TcpOptions
//{
//public:
//    virtual ~OptMultipathCapable();
//    uint32_t senderToken;
//    OptMultipathCapable(TcpOption_t oName, uint32_t TxToken);
//};
//
//class OptJoinConnection : public TcpOptions
//{
//public:
//    virtual ~OptJoinConnection();
//    uint32_t receiverToken;
//    uint8_t addrID;
//    OptJoinConnection(TcpOption_t oName, uint32_t RxToken, uint8_t aID);
//};
//
//class OptAddAddress : public TcpOptions
//{
//public:
//    virtual ~OptAddAddress();
//    uint8_t addrID;
//    Ipv4Address addr;
//    OptAddAddress(TcpOption_t oName, uint8_t aID, Ipv4Address address);
//};
//
//class OptRemoveAddress : public TcpOptions
//{
//public:
//    virtual ~OptRemoveAddress();
//    uint8_t addrID;
//    OptRemoveAddress(TcpOption_t oName, uint8_t aID);
//};
//
//class OptDataSeqMapping : public TcpOptions
//{
//public:
//    virtual ~OptDataSeqMapping();
//    uint64_t dataSeqNumber;
//    uint16_t dataLevelLength;
//    uint32_t subflowSeqNumber;
//    OptDataSeqMapping(TcpOption_t oName, uint64_t dSeqNum, uint16_t dLevelLength, uint32_t sfSeqNum);
//};
//
//class OptTimesTamp : public TcpOptions
//{
//public:
//    virtual ~OptTimesTamp();
//    uint64_t TSval;     // TS Value      in milliseconds
//    uint64_t TSecr;     // TS Echo Reply in milliseconds
//
//    OptTimesTamp(TcpOption_t oName, uint64_t tsval, uint64_t tsecr);
//};
//
///*! \brief Implémentation de l'option DSACK (Duplicate SACK) adaptée à MPTCP.
// *
// *
// *
// */
//class OptDSACK : public TcpOptions
//{
//public:
//    virtual ~OptDSACK();
//    vector<uint64_t> blocks;     // a vector of 4-bytes fields, representing the DSACK block's edge
//         // the size of the vector is a multiple of 2 (a block has to limits, upper and lower) representing the length of the table
//
//    OptDSACK (TcpOption_t oName);
//    void AddBlock (uint64_t leftEdge, uint64_t rightEdge);
//    void AddfstBlock (uint64_t leftEdge, uint64_t rightEdge);
//};
//
//class MpTcpHeader : public TcpHeader
//{
//public:
//  static TypeId  GetTypeId (void);
//
//  MpTcpHeader (void);
//  MpTcpHeader (const MpTcpHeader &res);
//  ~MpTcpHeader (void);
//
//  MpTcpHeader Copy ();
//
//  // Multipath capable Option
//  bool AddOptMPC(TcpOption_t optName, uint32_t TxToken);
//  // Join Connection Option
//  bool AddOptJOIN(TcpOption_t optName, uint32_t RxToken, uint8_t addrID);
//  // Add address Option
//  bool AddOptADDR(TcpOption_t optName, uint8_t addrID, Ipv4Address addr);
//  // Remove address Option
//  bool AddOptREMADR(TcpOption_t optName, uint8_t addrID);
//  // Data Sequence Mapping Option
//  bool AddOptDSN(TcpOption_t optName, uint64_t dSeqNum, uint16_t dLevelLength, uint32_t sfSeqNum);
//  // TCP TimesTamp Option
//  bool AddOptTT(TcpOption_t optName, uint64_t tsval, uint64_t tsecr);
//  // DSACK Option
//  bool AddOptDSACK(TcpOption_t optName, OptDSACK *opt);
//
//  virtual TypeId GetInstanceTypeId (void) const;
//  virtual void Print (std::ostream &os);
//  virtual uint32_t GetSerializedSize (void) const;
//  virtual void Serialize (Buffer::Iterator start) const;
//  virtual uint32_t Deserialize (Buffer::Iterator start);
//
//  void SetOptionsLength(uint8_t length);
//  void SetPaddingLength(uint8_t length);
//  uint8_t GetOptionsLength() const;
//  uint8_t GetPaddingLength() const;
//  uint8_t TcpOptionToUint(TcpOption_t opt) const;
//  TcpOption_t UintToTcpOption(uint8_t kind) const;
//
//  vector< TcpOptions* > GetOptions(void) const;
//  void SetOptions (vector<TcpOptions*> opt);
//
//protected:
//  vector< TcpOptions* > m_option;
//  uint8_t oLen;
//  uint8_t pLen;
//  bool original;
//};
//
//} // namespace ns3
//
//#endif /* MP_TCP_HEADER */
