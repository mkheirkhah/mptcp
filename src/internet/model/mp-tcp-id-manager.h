
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
* TODO setup callbacks in order to know if we shall accept the addition
* \brief The MPTCP path manager tracks ADD_ADDR/REM_ADDR in case the user wants to later open new subflows.
* It is possible to use callbacks from the MPTCP metasocket to be notified in case of a new ADD_ADDR.
* Thus it is possible to immediately create the desired subflows
*
RFC6824
   The Address IDs of the subflow used in the initial SYN exchange of
   the first subflow in the connection are implicit, and have the value
   zero.  A host MUST store the mappings between Address IDs and
   addresses both for itself and the remote host.  An implementation
   will also need to know which local and remote Address IDs are
   associated with which established subflows, for when addresses are
   removed from a local or remote host.

* There should be a testsuite to
* \class MpTcpPathIdManager
* TODO tempalte
**/
class MpTcpPathIdManager
  : public Object
{

public:
  static TypeId GetTypeId();

  MpTcpPathIdManager();

  virtual ~MpTcpPathIdManager();

  /**
  Will generate an appropriate ID
  (InetSocketAddress addr
  **/
//  virtual uint8_t GetIdForLocalAddr( Ipv4Address address );
//  virtual bool RemLocalAddr(Ipv4Address addr);

  /**
  \param addresses
  \warning Don't forget to clear the vector first !
  **/

  virtual void
  GetAllAdvertisedDestinations(std::vector<InetSocketAddress>& addresses) = 0;

  // TODO move callbacks here + local address Mgmt ?



  /**
  Can force the ID with which to register
  //    const Ipv4Address& address, uint16_t port = 0
  **/
  virtual bool
  AddRemoteAddr(uint8_t addrId, const Ipv4Address& address, uint16_t port) = 0;

  /**
  * del/rem
  *
  */
  virtual bool
  RemRemoteAddr(uint8_t addrId) = 0;

  virtual uint8_t
  GetLocalAddrId(const InetSocketAddress& address) = 0;
//  RegisterLocalAddress()

  /**
   * Called when closing the subflow
   */
  virtual bool
  RemLocalAddr(InetSocketAddress addrId) = 0;

  /**
   * Called when meta receives a REMOVE_ADDRESS. It just contians ids then.
   */
//  virtual bool
//  RemLocalAddr(uint8_t addrId) = 0;


};



}



#endif // MP_TCP_PATH_ID_MANAGER_H
