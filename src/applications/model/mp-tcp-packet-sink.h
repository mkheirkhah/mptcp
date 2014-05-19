#ifndef __mp_tcp_packet_sink_h__
#define __mp_tcp_packet_sink_h__

#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/traced-callback.h"
#include "ns3/address.h"
#include "ns3/mp-tcp-socket-base.h"
//#include "ns3/tcp-typedefs.h"

namespace ns3 {

class Address;
class Socket;
class Packet;

class MpTcpPacketSink   : public Application
{
public:
  static TypeId GetTypeId (void);
  MpTcpPacketSink ();

  virtual ~MpTcpPacketSink ();

  // Return the total bytes received in this sink app
  uint32_t GetTotalRx() const;
  Ptr<MpTcpSocketBase> getMpTcpSocket ();

protected:
  virtual void DoDispose (void);
private:
  // inherited from Application base class.
  virtual void StartApplication (void);    // Called at time specified by Start
  virtual void StopApplication (void);     // Called at time specified by Stop

  void HandleRead   (Ptr<Socket>);
  void HandleAccept (Ptr<Socket>, const Address& from);
  void HandlePeerClose (Ptr<Socket>);
  void HandlePeerError (Ptr<Socket>);

  // In the case of TCP, each socket accept returns a new socket, so the
  // listening socket is stored seperately from the accepted sockets
  Ptr<MpTcpSocketBase>     m_socket;       // Listening socket
  //Ptr<Socket> m_socket;
  std::list<Ptr<Socket> > m_socketList; //the accepted sockets

  Address         m_local;        // Local address to bind to
  uint32_t        m_totalRx;      // Total bytes received
  TypeId          m_tid;          // Protocol TypeId
  uint32_t        size;
  uint8_t *       buf;
  TracedCallback<Ptr<const Packet>, const Address &> m_rxTrace;
  uint32_t        algopr; // PacketReorder_t
};

/*
class MpTcpPacketSource : public Application
{
public:
    static TypeId GetTypeId (void);
    MpTcpPacketSource ();

    virtual ~MpTcpPacketSource();

    uint32_t m_servPort;
    Ipv4Address  m_servAddr;

private:
    virtual void StartApplication (void);
    virtual void StopApplication (void);
    TypeId  m_tid;          // Protocol TypeId
    Ptr<Socket> m_socket;

};
*/
} // namespace ns3

#endif

