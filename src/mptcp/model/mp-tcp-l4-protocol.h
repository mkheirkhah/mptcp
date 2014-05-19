//#ifndef MP_TCP_L4_PROTOCOL_H
//#define MP_TCP_L4_PROTOCOL_H
////
////
////
//#include <stdint.h>
//#include <vector>


//#include "ns3/packet.h"
//#include "ns3/ipv4-address.h"
//#include "ns3/ptr.h"
//#include "ns3/object-factory.h"
//#include "ns3/ip-l4-protocol.h"
//#include "ns3/tcp-l4-protocol.h"        // Morteza Kheirkhah
//#include "ns3/tcp-typedefs.h"
//#include "ns3/ipv4-end-point-demux.h"   // Morteza Kheirkhah
//#include "mp-tcp-header.h"
//#include "mp-tcp-socket-base.h"
//
//
//namespace ns3 {
//
//class MpTcpSocketBase;
//
//class MpTcpL4Protocol : public TcpL4Protocol {
//
//public:
//  static const uint8_t PROT_NUMBER;
//  static TypeId GetTypeId (void);
//  MpTcpL4Protocol ();
//  virtual ~MpTcpL4Protocol ();
//  virtual int GetProtocolNumber (void) const;
//  virtual enum IpL4Protocol::RxStatus Receive (Ptr<Packet> packet, Ipv4Header const &header, Ptr<Ipv4Interface> incomingInterface);
//  typedef std::map<uint32_t, Ipv4EndPoint*> TokenMaps;
//
//protected:
//  virtual void DoDispose (void);
//  virtual void NotifyNewAggregate ();
//
//private:
//  void SendPacket (Ptr<Packet> p, TcpHeader l4Header, Ipv4Address src, Ipv4Address dst);
//
//private:
//  friend class MpTcpSocketBase;
////  std::vector<Ptr<MpTcpSocketBase> > m_sockets;
//  //std::map<uint32_t, uint32_t> m_TokenMap;
//  std::map<uint32_t, Ipv4EndPoint* > m_TokenMap;
//};
//
//}; // namespace ns3
//
//
//#endif /* MP_TCP_L4_PROTOCOL_H */
