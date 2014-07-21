
/*
 * MultiPath-TCP (MPTCP) implementation.
 * Programmed by Morteza Kheirkhah from University of Sussex.
 * Some codes here are modeled from ns3::TCPNewReno implementation.
 * Email: m.kheirkhah@sussex.ac.uk
 */
#ifndef MP_TCP_PATH_ID_MANAGER_H
#define MP_TCP_PATH_ID_MANAGER_H

#include "ns3/callback.h"
//#include "ns3/mp-tcp-typedefs.h"
//#include "ns3/tcp-socket-base.h"
//#include "ns3/mp-tcp-path-manager.h"
//#include "ns3/gnuplot.h"
//#include "mp-tcp-subflow.h"

#include "ns3/object.h"
#include "ns3/address.h"
#include "ns3/inet-socket-address.h"
#include <map>
#include <vector>


namespace ns3
{


/**
TODO setup callbacks in order to know if we shall accept the addition
**/
class MpTcpPathIdManager : public Object
{

public:


  MpTcpPathIdManager();
  virtual ~MpTcpPathIdManager();

  /**
  Will generate an appropriate ID
  (InetSocketAddress addr
  **/
//  virtual uint8_t GetIdForLocalAddr( Ipv4Address address );
//  virtual bool RemLocalAddr(Ipv4Address addr);

  /**
  Add callback
  **/

  /**
  Can force the ID with which to register
  //    const Ipv4Address& address, uint16_t port = 0
  **/
  virtual bool AddRemoteAddr(uint8_t addrId, const Ipv4Address& address, uint16_t port);

  /**

  **/
  virtual bool RemRemoteAddr(uint8_t addrId);





protected:
  // MPTCP containers
  // INetSocketAddress
//  InetSocketAddress
  typedef std::pair<const Ipv4Address, std::vector<uint16_t> > MpTcpAddressInfo;  //!< Ipv4/v6 address and its port

//  typedef std::multimap<uint8_t,MpTcpAddressInfo>  MpTcpAddressContainer;
  typedef std::map<uint8_t,MpTcpAddressInfo>  MpTcpAddressContainer;

  //! Maps an Address Id to the pair  (Ipv4/v6, port)
//  std::map<uint8_t,MpTcpAddressInfo> m_localAddrs;

   //! List addresses advertised by the remote host
   //! index 0 for local, 1 for remote addr
  MpTcpAddressContainer m_addrs;

  /**
  Need this to check if an IP has already been advertised, in which case
  the same id should be associated to the already advertised IP

  **/
//  virtual MpTcpAddressContainer::iterator FindAddrIdOfAddr(Address addr );


//  virtual uint8_t GenerateAddrId(MpTcpAddressInfo);
//  virtual uint8_t GenerateAddrId(const InetSocketAddress&);
//  virtual uint8_t GenerateAddrId(const InetSocketAddress6&);
};



}



#endif // MP_TCP_PATH_ID_MANAGER_H
