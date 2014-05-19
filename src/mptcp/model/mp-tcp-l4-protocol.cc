//#include "ns3/assert.h"
//#include "ns3/log.h"
//#include "ns3/nstime.h"
//#include "ns3/boolean.h"
//#include "ns3/object-vector.h"
//
//#include "ns3/packet.h"
//#include "ns3/node.h"
//#include "ns3/ipv4-route.h"
//
//#include "mp-tcp-l4-protocol.h"
//#include "ns3/tcp-header.h"               //Morteza Kheirkhah
//#include "ns3/ipv4-end-point-demux.h"     //Morteza Kheirkhah
//#include "ns3/ipv4-end-point.h"           //Morteza Kheirkhah
//#include "ns3/ipv4-l3-protocol.h"         //Morteza Kheirkhah
//#include "ns3/tcp-socket-factory-impl.h"  //Morteza Kheirkhah
//#include "ns3/tcp-socket-base.h"          //Morteza Kheirkhah
//#include "ns3/rtt-estimator.h"            //Morteza Kheirkhah
////#include "ns3/tcp-typedefs.h"
//
//#include <vector>
//#include <list>
//#include <sstream>
//#include <iomanip>
//
//NS_LOG_COMPONENT_DEFINE("MpTcpL4Protocol");
//
//namespace ns3
//{
//
//NS_OBJECT_ENSURE_REGISTERED(MpTcpL4Protocol);
//
//const uint8_t MpTcpL4Protocol::PROT_NUMBER = 6;
//
//TypeId
//MpTcpL4Protocol::GetTypeId(void)
//{
//  static TypeId tid = TypeId("ns3::MpTcpL4Protocol").SetParent<TcpL4Protocol>().AddConstructor<MpTcpL4Protocol>();
//  return tid;
//}
//
//MpTcpL4Protocol::MpTcpL4Protocol()
////  : m_endPoints (new Ipv4EndPointDemux ())
//{
//  NS_LOG_FUNCTION_NOARGS (); //
//  NS_LOG_LOGIC("Made a MpTcpL4Protocol "<<this);
//  m_endPoints = new Ipv4EndPointDemux();
//}
//
//MpTcpL4Protocol::~MpTcpL4Protocol()
//{
//  NS_LOG_FUNCTION_NOARGS ();
//}
//
//int
//MpTcpL4Protocol::GetProtocolNumber(void) const
//{
//  return PROT_NUMBER;
//}
//
//void
//MpTcpL4Protocol::NotifyNewAggregate()
//{
//  NS_LOG_FUNCTION_NOARGS();
//  if (m_node == 0)
//    {
//      Ptr<Node> node = this->GetObject<Node>();
//      if (node != 0)
//        {
//          Ptr<Ipv4L3Protocol> ipv4 = this->GetObject<Ipv4L3Protocol>();
//          if (ipv4 != 0)
//            {
//              this->SetNode(node);
//              ipv4->Insert(this);
//              Ptr<TcpSocketFactoryImpl> tcpFactory = CreateObject<TcpSocketFactoryImpl>();
//              tcpFactory->SetTcp(this);
//              node->AggregateObject(tcpFactory);
//            }
//        }
//    }
//  Object::NotifyNewAggregate();
//}
//
//// This func has inhereted from tcp-l4-protocol
//enum IpL4Protocol::RxStatus
//MpTcpL4Protocol::Receive(Ptr<Packet> packet, Ipv4Header const &header, Ptr<Ipv4Interface> incomingInterface)
//{
//  TcpHeader mptcpHeader;
//  /*if(Node::ChecksumEnabled ())
//   {
//   mptcpHeader.EnableChecksums();
//   mptcpHeader.InitializeChecksum (source, destination, PROT_NUMBER);
//   }
//   */
//  //......................................................
//  Ipv4Address source = header.GetSource(); // IP addrs of sender
//  Ipv4Address destination = header.GetDestination(); // IP addrs of receiver
//  //......................................................
//  NS_LOG_FUNCTION (m_node->GetId() << packet->GetUid() << source << destination << incomingInterface->GetDevice()->GetIfIndex());
//
//  packet->PeekHeader(mptcpHeader);
//  uint16_t srcPort = mptcpHeader.GetSourcePort();
//  uint16_t dstPort = mptcpHeader.GetDestinationPort();
//  NS_LOG_INFO(this << " MpTcpL4Protocol:Receive -> "<< mptcpHeader);  //
//  NS_LOG_INFO(this << " MpTcpL4Protocol:Receive -> srcPort: "<< srcPort << " dstPort: " << dstPort);
//
////  uint32_t FiveTuple = header.GetSource().Get() + header.GetDestination().Get() + header.GetProtocol()
////      + mptcpHeader.GetSourcePort() + mptcpHeader.GetDestinationPort();
////  NS_LOG_INFO("FiveTuple -> " << FiveTuple);
//
//  // Extract MPTCP options if there is any
//  vector<TcpOptions*> options = mptcpHeader.GetOptions();
//  uint8_t flags = mptcpHeader.GetFlags();
//  bool hasSyn = flags & TcpHeader::SYN;
//  TcpOptions *opt;
//  uint32_t Token;
////  bool OPT_MPC_Lookup = false;
////  bool OPT_JOIN_Lookup = false;
////  bool HashMap_Lookup = false;
//  for (uint32_t j = 0; j < options.size(); j++)
//    {
//      opt = options[j];
//      if ((opt->optName == OPT_MPC) && hasSyn)
//        { // In this case the endpoint with destonation port and token value of zero need to be find.
//          //OPT_MPC_Lookup = true;
//          //Token = ((OptMultipathCapable *) opt)->senderToken; // in case of sender receive this
//          //break;
//        }
//      if ((opt->optName == OPT_JOIN) && hasSyn)
//        { // In this case there should be endPoint with this token, so look for a match on all endpoints.
//          Token = ((OptJoinConnection *) opt)->receiverToken;
//          TokenMaps::iterator it;
//          it = m_TokenMap.find(Token);
//          if (it != m_TokenMap.end())
//            {
//              NS_LOG_INFO("OPT_JOIN -> Token " << Token << " has find forwardup to it");
//              ((*it).second)->ForwardUp(packet, header, srcPort, incomingInterface);
//              return IpL4Protocol::RX_OK;
//            }
//        }
//    }
//  // Taking all endPoint from Ipv4EndPointDemux's object
//  //Ipv4EndPointDemux::EndPoints allEndPoints = m_endPoints->GetAllEndPoints();
//
//  /*
//   // OPT_MPC received => look for a endpoint with token 0 and local port == destination port
//   if (OPT_MPC_Lookup)
//   {
//   Ipv4EndPointDemux::EndPoints::iterator it;
//   for (it = allEndPoints.begin(); it != allEndPoints.end(); it++)
//   {
//   NS_LOG_INFO("OPT_MPC_Lookup -> current endPoint's Token: " << (*it)->GetToken());
//   if (((*it)->GetLocalPort() == dstPort) && ((*it)->GetToken() == 0))
//   {
//   NS_LOG_INFO("OPT_MPC_Lookup -> Match has find... and endpoint'token zero");
//   OPT_MPC_Lookup = false;
//   (*it)->ForwardUp(packet, header, srcPort, incomingInterface);
//   return IpL4Protocol::RX_OK;
//   }
//   }NS_LOG_INFO("OPT_MPC_Lookup -> FAILED even though packet has MP-Capable, this might occured for sender!");
//   }
//   // In this case there should be endPoint with this token, so look for a match on all endpoints.
//   else if (OPT_JOIN_Lookup)
//   {
//   NS_ASSERT(Token != 0);
//   Ipv4EndPointDemux::EndPoints::iterator it;
//   for (it = allEndPoints.begin(); it != allEndPoints.end(); it++)
//   {
//   NS_LOG_INFO("OPT_JOIN_Lookup -> endPoint's Token: " << (*it)->GetToken() << " HeaderToken: " << Token);
//   if (((*it)->GetLocalPort() == dstPort) && ((*it)->GetToken() == Token))
//   {
//   NS_LOG_INFO("OPT_JOIN_Lookup -> Match has find...");
//   (*it)->ForwardUp(packet, header, srcPort, incomingInterface);
//   return IpL4Protocol::RX_OK;
//   }
//   }
//   NS_FATAL_ERROR("There should be a endpoint...");
//   }
//   else
//   {
//   // Look for a token by looking at TokenMap, if match find then look for an endPoint with that token
//   // 1) Find a token by finding a match of fiveTuple 2) search for the token to find an endpoint
//   TokenMaps::iterator it;
//   it = m_TokenMap.find(FiveTuple);
//   if (it != m_TokenMap.end())
//   {
//   Token = (*it).second;
//   HashMap_Lookup = true;
//   }
//   else
//   NS_LOG_INFO("Need to carry on based on TCP lookup machanism which is based on 5-Tuple!");
//   }
//
//   if (HashMap_Lookup)
//   {
//   NS_ASSERT(Token != 0);
//   Ipv4EndPointDemux::EndPoints::iterator iterator;
//   for (iterator = allEndPoints.begin(); iterator != allEndPoints.end(); iterator++)
//   {
//   if (((*iterator)->GetLocalPort() == dstPort) && ((*iterator)->GetToken() == Token))
//   {
//   NS_LOG_INFO("HashMap_Lookup -> Match has find...");
//   (*iterator)->ForwardUp(packet, header, srcPort, incomingInterface);
//   return IpL4Protocol::RX_OK;
//   }
//   }
//   }
//   */
//  //NS_LOG_LOGIC("MpTcpL4Protocol " << this << " receiving seq " << mptcpHeader.GetSequenceNumber() << " ack " << mptcpHeader.GetAckNumber() << " flags "<< std::hex << (int)mptcpHeader.GetFlags() << std::dec << " data size " << packet->GetSize());
//  /*
//   if(!tcpHeader.IsChecksumOk ())
//   {
//   NS_LOG_INFO("Bad checksum, dropping packet!");
//   return Ipv4L4Protocol::RX_CSUM_FAILED;
//   }
//   */
//  // Find a endPoint by looking through 5 tuple.
//  Ipv4EndPointDemux::EndPoints endPoints = m_endPoints->Lookup(destination, dstPort, source, srcPort, incomingInterface);
////  if (endPoints.empty())
////    {
//  // trying with destination port
///*
//  // SECOND SOLUTION
//  Ipv4EndPointDemux::EndPoints allEndPoints = m_endPoints->GetAllEndPoints();
//  Ipv4EndPointDemux::EndPoints::iterator it;
//  bool find = false;
//  NS_LOG_INFO("MpTcpL4Protocol:Receive ->  Trying to look up for end point with destination port: "<< dstPort << " AllEndpoints: " << allEndPoints.size() << " SocketLists: " << m_sockets.size());
//  for (it = allEndPoints.begin(); it != allEndPoints.end(); it++)
//    {
//      uint16_t localPort = (*it)->GetLocalPort();
//      uint16_t peerPort = (*it)->GetPeerPort();
//      if (localPort == dstPort && peerPort == srcPort)
//        {
//          find = true;
//          break;
//          //it = allEndPoints.erase(it);
//        }
//    }
//
//  if (find)
//    {
//      (*it)->ForwardUp(packet, header, srcPort, incomingInterface);  // Morteza
//      return IpL4Protocol::RX_OK; // ns3.15
//    }
//*/
////    }
//  /*
//   * endpoint'local port matched with pkt's destination port,
//   * endpoint's remote port matched with pkt's source port
//   */
//  //(*allEndPoints.begin())->SetLocalAddress(destination);
//  //(*allEndPoints.begin())->SetPeer(source, srcPort);
//  //NS_LOG_INFO ("MpTcpL4Protocol -> Ipv4EndPointDemux return an endpoint, forwarding up to endpoint/socket dest = "<< (*endPoints.begin())->GetPeerAddress() <<":"<<(*endPoints.begin())->GetPeerPort()<<" src = " << (*endPoints.begin())->GetLocalAddress() << ":" << (*endPoints.begin())->GetLocalPort());
////  if (allEndPoints.size() > 0)
////    {
////      NS_ASSERT(allEndPoints.size() == 1);
////      if ((*allEndPoints.begin())->GetLocalPort() == dstPort && (*allEndPoints.begin())->GetPeerPort() == srcPort)
////        {
////          (*allEndPoints.begin())->ForwardUp(packet, header, srcPort, incomingInterface);  // Morteza
////          NS_LOG_INFO (this << " MpTcpL4Protocol -> (allEndPoints.size() > 0) Forwarding up to endpoint Remote: "<< (*allEndPoints.begin())->GetPeerAddress() <<":"<<(*allEndPoints.begin())->GetPeerPort()<<" Local: " << (*allEndPoints.begin())->GetLocalAddress() << ":" << (*allEndPoints.begin())->GetLocalPort() << "\n");
////          return IpL4Protocol::RX_OK; // ns3.15
////        }
////    }
////  //return Ipv4L4Protocol::RX_OK; // ns3.6
////  if (endPoints.empty())
////    {
////      NS_LOG_LOGIC ("  No endpoints matched on MpTcpL4Protocol "<<this);
////      std::ostringstream oss;
////      oss << "  destination IP: ";
////      destination.Print(oss);
////      oss << " destination port: " << dstPort << " source IP: ";
////      source.Print(oss);
////      oss << " source port: " << srcPort;
////      NS_LOG_LOGIC (oss.str ());
//  /*
//   if (!(tcpHeader.GetFlags () & TcpHeader::RST))
//   {
//   // build a RST packet and send
//   Ptr<Packet> rstPacket = Create<Packet> ();
//   TcpHeader header;
//   if (tcpHeader.GetFlags () & TcpHeader::ACK)
//   {
//   // ACK bit was set
//   header.SetFlags (TcpHeader::RST);
//   header.SetSequenceNumber (header.GetAckNumber ());
//   }
//   else
//   {
//   header.SetFlags (TcpHeader::RST | TcpHeader::ACK);
//   header.SetSequenceNumber (SequenceNumber (0));
//   header.SetAckNumber (header.GetSequenceNumber () + SequenceNumber (1));
//   }
//   header.SetSourcePort (tcpHeader.GetDestinationPort ());
//   header.SetDestinationPort (tcpHeader.GetSourcePort ());
//   SendPacket (rstPacket, header, destination, source);
//   return Ipv4L4Protocol::RX_ENDPOINT_CLOSED;
//   }
//   else
//   {
//   return Ipv4L4Protocol::RX_ENDPOINT_CLOSED;
//   }
//   */
//  //}
//  if (endPoints.empty())
//    {
//      return IpL4Protocol::RX_ENDPOINT_CLOSED;
//    }
//  NS_ASSERT_MSG(endPoints.size() == 1, "Demux returned more than one endpoint: " << endPoints.size());
//  NS_LOG_INFO(this << " MpTcpL4Protocol (NON EMPTY)-> Forwarding up to endpoint  Remote: "<< (*endPoints.begin())->GetPeerAddress() <<":"<<(*endPoints.begin())->GetPeerPort()<<" Local: " << (*endPoints.begin())->GetLocalAddress() << ":" << (*endPoints.begin())->GetLocalPort() << "\n");
//  //(*endPoints.begin())->SetLocalAddress(destination); // No need for it though.
//  //(*endPoints.begin())->SetPeer(source, srcPort);
//  (*endPoints.begin())->ForwardUp(packet, header, srcPort, incomingInterface); // ns-3.15 (Morteza Kheirkhah)
//  return IpL4Protocol::RX_OK; // ns-3.15 (Morteza Kheirkhah)
//  //return Ipv4L4Protocol::RX_OK;  // ns-3.6
//}
//
//void
//MpTcpL4Protocol::DoDispose(void)
//{
//  NS_LOG_FUNCTION_NOARGS ();
////  for (std::vector<Ptr<TcpSocketBase> >::iterator i = m_sockets.begin(); i != m_sockets.end(); i++)
////    {
////      *i = 0;
////    }
////  m_sockets.clear();
//
//  if (m_endPoints != 0)
//    {
//      delete m_endPoints;
//      m_endPoints = 0;
//    }
//
//  m_node = 0;
//  IpL4Protocol::DoDispose(); // Morteza Kheirkhah
//}
//
//void
//MpTcpL4Protocol::SendPacket(Ptr<Packet> p, TcpHeader l4Header, Ipv4Address src, Ipv4Address dst)
//{
//  //NS_LOG_LOGIC("MpTcpL4Protocol " << this );
//  /*
//   << " sending seq " << l4Header.GetSequenceNumber()
//   << " ack " << l4Header.GetAckNumber()
//   << " flags " << std::hex << (int)header.GetFlags() << std::dec
//   << " data size " << p->GetSize());*/
//  NS_LOG_FUNCTION (m_node->GetId() << p->GetUid() << src << dst);NS_LOG_INFO("MpTcpL4Protocol:SendPacket -> " << l4Header);
//  //Ptr<TcpHeader> ptrHeader = CopyObject<TcpHeader>(l4Header);
//  p->AddHeader(l4Header);
//  //NS_LOG_INFO ("MpTcpL4Protocol::SendPacket -> header added successfully !");
//  Ptr<Ipv4L3Protocol> ipv4 = m_node->GetObject<Ipv4L3Protocol>();
//  if (ipv4 != 0)
//    {
//      // XXX We've already performed the route lookup in TcpSocketImpl
//      // should be cached.
//      Ipv4Header l3Header;
//      l3Header.SetDestination(dst);
//      Socket::SocketErrno errno_;
//      Ptr<Ipv4Route> route;
////      uint32_t oif = 0; //specify non-zero if bound to a source address
//      Ptr<NetDevice> oif(0);
//      // use oif to specify the interface output (see Ipv4RoutingProtocol class)
//      route = ipv4->GetRoutingProtocol()->RouteOutput(p, l3Header, oif, errno_);
//      //NS_LOG_INFO ("MpTcpL4Protocol::SendPacket -> packet size:" << p->GetSize() <<" sAddr " << src<<" dstAddr " << dst);NS_LOG_INFO ("MpTcpL4Protocol::SendPacket -> Protocol n°:" << (int)PROT_NUMBER);NS_LOG_INFO ("MpTcpL4Protocol::SendPacket -> route      :" << route);
//      ipv4->Send(p, src, dst, PROT_NUMBER, route);
//      //NS_LOG_INFO ("MpTcpL4Protocol::SendPacket -> leaving !");
//    }
//  else
//    NS_FATAL_ERROR("Trying to use MpTcp on a node without an Ipv4 interface");
//
//}
//}
//;
//// namespace ns3
//
