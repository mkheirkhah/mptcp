/*
 * MultiPath-TCP (MPTCP) implementation.
 * Programmed by Morteza Kheirkhah from University of Sussex.
 * Some codes here are modeled from ns3::TCPNewReno implementation.
 * Email: m.kheirkhah@sussex.ac.uk
 */
#ifndef MP_TCP_SOCKET_BASE_H
#define MP_TCP_SOCKET_BASE_H

#include "ns3/callback.h"
#include "ns3/mp-tcp-typedefs.h"
#include "ns3/tcp-socket-base.h"
//#include "ns3/mp-tcp-path-manager.h"
//#include "ns3/gnuplot.h"
//#include "mp-tcp-subflow.h"

//#include "ns3/mp-tcp-cc.h"
#include "ns3/inet-socket-address.h"
#include "ns3/mp-tcp-scheduler-round-robin.h"

//using namespace std;

namespace ns3
{
class Ipv4EndPoint;
class Node;
class Packet;
class TcpL4Protocol;
class MpTcpPathIdManager;
class MpTcpSubFlow;
//class MpTcpSchedulerRoundRobin;
class MpTcpCongestionControl;
class TcpOptionMpTcpDSS;
class OutputStreamWrapper;


void
SetupSocketTracing(Ptr<TcpSocketBase> sock, const std::string prefix);

void
dumpNextTxSequence(Ptr<OutputStreamWrapper> stream, std::string context, SequenceNumber32 oldSeq, SequenceNumber32 newSeq);

void
dumpUint32(Ptr<OutputStreamWrapper> stream, std::string context, uint32_t oldVal, uint32_t newVal);

void
dumpTcpState(Ptr<OutputStreamWrapper> stream, std::string context, TcpStates_t oldVal, TcpStates_t newVal);

/**
 * \class MpTcpSocketBase

This is the MPTCP meta socket the application talks with
this socket. New subflows, as well as the first one (the master
socket) are linked to this meta socket.

Every data transfer happens on a subflow.
Following the linux kernel from UCL (http://multipath-tcp.org) convention,
the first established subflow is called the "master" subflow.

This inherits TcpSocketBase so that it can be  used as any other TCP variant:
this is the backward compability feature that is required in RFC.
Also doing so allows to run TCP tests with MPTCP via for instance the command
Config::SetDefault ("ns3::TcpL4Protocol::SocketType", "ns3::MpTcpOlia");

But to make sure some inherited functions are not improperly used, we need to redefine them so that they
launch an assert. You can notice those via the comments "//! Disabled"

As such many inherited (protected) functions are overriden & left empty.


TODO:
-rename in MetaSocket ?
-should inherit from TcpSocket rather TcpSocketBase
-should use 64 bits based buffer / sq nb
-the children should parse MPTCP option and relay them to the father
//  ProcessJoin(Ptr<TcpOptionMpTcpJoin>, Ptr<MpTcpSubFlow> sf);
//  ProcessCapable(Ptr<TcpOptionMpTcpJoin>, Ptr<MpTcpSubFlow> sf);
//  ProcessAddAddr(Ptr<TcpOptionMpTcpJoin>, Ptr<MpTcpSubFlow> sf);
//  ProcessRemAddr(Ptr<TcpOptionMpTcpJoin>, Ptr<MpTcpSubFlow> sf);
//  ProcessDSS(Ptr<TcpOptionMpTcpJoin>, Ptr<MpTcpSubFlow> sf);

// TODO inherit MpTcpSocket or TcpSocket but  would need to recreate 64bits buffer
**/
class MpTcpSocketBase : public TcpSocketBase

{
public: // public methods
  typedef std::vector< Ptr<MpTcpSubFlow> > SubflowList;

  static TypeId GetTypeId(void);

  // inherited function, no need to doc.
//  virtual TypeId GetInstanceTypeId (void) const;

  MpTcpSocketBase();
  MpTcpSocketBase(const MpTcpSocketBase&);
//  MpTcpSocketBase(Ptr<Node> node);
  virtual ~MpTcpSocketBase();

  // Window Management
  virtual uint32_t
  BytesInFlight();  // Return total bytes in flight of a subflow

  /**
  Used to export a whole range of statistics to csv files (filenames hardcoded).
  This would likely need a rework before upstream, for instance to allow
  enabling/disabling
  **/
  virtual void SetupMetaTracing(std::string prefix);


  void
  ProcessWait(Ptr<Packet> packet, const TcpHeader& tcpHeader);

  static
  void GenerateTokenForKey( mptcp_crypto_t alg, uint64_t key, uint32_t& token, uint64_t& idsn);

  //const
  virtual uint32_t CalculateTotalCWND();

  virtual uint16_t
  AdvertisedWindowSize();

  // TODO remove
  virtual uint32_t
  AvailableWindow();
  /**
  \warn This function should be called once a connection is established else
  **/
  virtual bool IsMpTcpEnabled() const;


  virtual void CloseAndNotify(void);

  /** Limit the size of in-flight data by cwnd and receiver's rxwin */
  virtual uint32_t
  Window (void);

  virtual void
  PersistTimeout();

  /* equivalent to PeerClose
  \param finalDsn
  OnDataFin
  */
  virtual void
  PeerClose( SequenceNumber32 fin_seq, Ptr<MpTcpSubFlow> sf);

  virtual void
  OnInfiniteMapping(Ptr<TcpOptionMpTcpDSS> dss, Ptr<MpTcpSubFlow> sf);

  /* equivalent to TCP Rst */
  virtual void
  SendFastClose(Ptr<MpTcpSubFlow> sf);

  /**
  \brief Generates random key, setups isdn and token
  **/
  virtual uint64_t GenerateKey();

  /**
  * TODO when is it considered
  * \return
  */
  bool IsConnected() const;

  // Public interface for MPTCP
  virtual int Bind();                         // Bind a socket by setting up endpoint in TcpL4Protocol
  virtual int Bind(const Address &address);   // Bind a socket ... to specific add:port
  virtual int Connect(const Address &address);

  // TODO to remove there is no equivalent in parent's class
//  virtual int Connect(Ipv4Address servAddr, uint16_t servPort);

  virtual int Listen(void);

  /**
  RFC 6824:
   - When an application calls close() on a socket, this indicates that it
   has no more data to send; for regular TCP, this would result in a FIN
   on the connection.  For MPTCP, an equivalent mechanism is needed, and
   this is referred to as the DATA_FIN.

   - A DATA_FIN has the semantics and behavior as a regular TCP FIN, but
   at the connection level.  Notably, it is only DATA_ACKed once all
   data has been successfully received at the connection level
  */
  // socket function member
  virtual int Close(void);

  /**
  RFC 6824
  - If all subflows have
   been closed with a FIN exchange, but no DATA_FIN has been received
   and acknowledged, the MPTCP connection is treated as closed only
   after a timeout.  This implies that an implementation will have
   TIME_WAIT states at both the subflow and connection levels (see
   Appendix C).  This permits "break-before-make" scenarios where
   connectivity is lost on all subflows before a new one can be re-
   established.
  */
//  virtual void
//  PeerClose(Ptr<Packet>, const TcpHeader&); // Received a FIN from peer, notify rx buffer

  /* called by subflow when it sees a DSS with the DATAFIN flag
  Params are ignored
  \param packet Ignored
  */
  virtual void
  PeerClose(Ptr<Packet> packet, const TcpHeader&); // Received a FIN from peer, notify rx buffer
  virtual void
  DoPeerClose(void); // FIN is in sequence, notify app and respond with a FIN

//  virtual void
//  ClosingOnEmpty(TcpHeader& header);

  virtual int
  DoClose(void); // Close a socket by sending RST, FIN, or FIN+ACK, depend on the current state
//  virtual void
//  CloseAndNotify(void); // To CLOSED state, notify upper layer, and deallocate end point

//  virtual int Close(uint8_t sFlowIdx);        // Closing subflow...
  virtual uint32_t GetTxAvailable() const;                  // Return available space in sending buffer to application
  virtual uint32_t GetRxAvailable(void) const;

  // TODO maybe this could be removed ?
  void
  DoForwardUp(Ptr<Packet> packet, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface> incomingInterface);
  /**
  \return Number of connected subflows (that is that ran the 3whs)
  */
  SubflowList::size_type GetNActiveSubflows() const;
  // uint8
  /**
  * \return an established subflow
  */
  Ptr<MpTcpSubFlow> GetSubflow(uint8_t);

  virtual void ClosingOnEmpty(TcpHeader& header);

  /**
  Sends RST on all subflows
  and MP_FASTCLOSE on one of the subflows
  */
  virtual void SendRST(void);
  // Setter for congestion Control and data distribution algorithm
//  void SetCongestionCtrlAlgo(CongestionCtrl_t ccalgo);  // This would be used by attribute system for setting congestion control
//  void SetDataDistribAlgo(DataDistribAlgo_t ddalgo);    // Round Robin is only algorithms used.

  /**
  TODO remove ? transfom into attribute ?
  \brief Allow to set the congestion control algorithm in use. You can choose between OLIA,LIA,COUPLED,UNCOUPLED.
  \bug Should not be possible to change CC after connection has started
  */
  void SetCongestionCtrlAlgo(Ptr<MpTcpCongestionControl> ccalgo);

//  void SetPathManager(Ptr<MpTcpPathManager>);
  // InetSocketAddress
  //, const INetAddress& dstAddr
  /**
  public equivalent ?
  * \brief
  * \param srcAddr Address to bind to. In theory Can be an InetSocketAddress or an Inet6SocketAddress
  * for now just InetSocketAddress
  */
  Ptr<MpTcpSubFlow> CreateSubflow(
    bool masterSocket
    );

  // Path management related functions

//  virtual int GenerateToken(uint32_t& token ) const;

  virtual void Destroy(void);
  /**
  \return 0 In case of success
  TODO bool ?
  **/
  //int GetRemoteKey(uint64_t& remoteKey) const;
  uint64_t GetRemoteKey() const;

  /**
  \brief Generated during
  */
  uint64_t GetLocalKey() const;

    /**
  For now it looks there is no way to know that an ip interface went up so we will assume until
  further notice that IPs of the client don't change.
  -1st callback called on receiving an ADD_ADDR
  -2nd callback called on receiving REM_ADDR
  (TODO this class should automatically register)
  **/
  void SetNewAddrCallback(Callback<bool, Ptr<Socket>, Address, uint8_t> remoteAddAddrCb,
                          Callback<void, uint8_t> remoteRemAddrCb);

  /**
  **/
//  virtual void GetAllAdvertisedSources(std::vector<InetSocketAddress> addresses);


  void GetAllAdvertisedDestinations(std::vector<InetSocketAddress>& );

public: // public variables
  typedef enum {
    Established = 0, /* contains ESTABLISHED/CLOSE_WAIT */
    // TODO rename to restart
    Others = 1,  /* Composed of SYN_RCVD, SYN_SENT*/
    Closing, /* CLOSE_WAIT, FIN_WAIT */
    Maximum  /* keep it last, used to decalre array */
  } mptcp_container_t;
  // TODO move back to protected/private later on


  // Evaluation & plotting parameters and containers
//  int MSS;    // Maximum Segment Size : use GetSegSize instead
//  double RTT; //

  // Apparently used for plotting. I guess this should go outside, into helpers maybe ?
  double TimeScale;

//  GnuplotCollection gnu;  //!< plotting
//
//  std::list<uint32_t> sampleList;

  // TODO remove in favor of parents' ?
//  std::vector<pair<double, double> > totalCWNDtrack;
//  std::vector<pair<double, double> > reTxTrack;
//  std::vector<pair<double, double> > timeOutTrack;
//  std::vector<pair<double, double> > PartialAck;
//  std::vector<pair<double, double> > FullAck;
//  std::vector<pair<double, double> > DupAcks;
//  std::vector<pair<double, double> > PacketDrop;
//  std::vector<pair<double, double> > TxQueue;

protected: // protected methods

  friend class Tcp;
  friend class MpTcpSubFlow;

  void CloseAllSubflows();

//  virtual int SetLocalToken(uint32_t token) const;

  // Implementing some inherited methods from ns3::TcpSocket. No need to comment them!
//  virtual void SetSndBufSize (uint32_t size);
//  virtual uint32_t GetSndBufSize (void) const;
//  virtual void SetRcvBufSize (uint32_t size);
//  virtual uint32_t GetRcvBufSize (void) const;

  /**
  TODO rename to GetMinSSThreshold;
  **/
  virtual void SetSSThresh(uint32_t threshold);
  virtual uint32_t GetSSThresh(void) const;

  void
  SetRemoteWindow(uint32_t win_size);

  virtual void SetInitialCwnd(uint32_t cwnd);
  virtual uint32_t GetInitialCwnd(void) const;
  virtual void SetSegSize(uint32_t size);
  virtual uint32_t GetSegSize(void) const;

  // MPTCP connection and subflow set up

  virtual int  SetupCallback(void);  // Setup SetRxCallback & SetRxCallback call back for a host
  // Same as parent's
//  virtual int  SetupEndpoint (void); // Configure local address for given remote address in a host - it query a routing protocol to find a source

  virtual void
  CompleteFork(Ptr<Packet> p, const TcpHeader& h, const Address& fromAddress, const Address& toAddress);

  // TODO remove should be done by helper instead
//  bool InitiateSubflows();            // Initiate new subflows

  /*
  Remove subflow from containers
  TODO should also erase its id from the path id manager
  \sf
  \param reset True if closing due to reset
  */
  void
  OnSubflowClosed(Ptr<MpTcpSubFlow> sf, bool reset);

  void
  OnSubflowDupAck(Ptr<MpTcpSubFlow> sf);

  /**
  \param dataSeq Used to reconstruct the mapping
  Currently used as callback for subflows
  */
  virtual void
  OnSubflowRecv(
                Ptr<MpTcpSubFlow> sf
//                SequenceNumber32 dataSeq, Ptr<Socket> sock
                );



  /* close all subflows
  */
  virtual void
  TimeWait();

  virtual void
  AppendDataAck(TcpHeader& hdr) const;

  /* put it outside ? */
  virtual void
  AppendDataFin(TcpHeader& header) const;

  /**
  When a subflow gets connected
  TODO rename into ConnectionSucceeded
  **/
  void OnSubflowEstablishment(Ptr<MpTcpSubFlow>);

  /**
  Should be called when subflows enters FIN_WAIT or LAST_ACK
  */
  void OnSubflowClosing(Ptr<MpTcpSubFlow>);


  /**
  Fails if
  **/
//  bool AddLocalAddress(uint8_t&, Port);
// Should generate an Id

//  void SetAddrEventCallback(Callback<bool, Ptr<Socket>, Address, uint8_t> remoteAddAddrCb,
//                          Callback<void, uint8_t> remoteRemAddrCb);
  //virtual RemoteAddAddr
  void NotifyRemoteAddAddr(Address address);
  void NotifyRemoteRemAddr(uint8_t addrId);

  /**
  \bug convert to uint64_t ?
  \note Setting a remote key has the sideeffect of enabling MPTCP on the socket
  */
  void SetPeerKey(uint64_t );

  virtual void
  ConnectionSucceeded(void); // Schedule-friendly wrapper for Socket::NotifyConnectionSucceeded()


  virtual int
  DoConnect(void);

  // Transfer operations
//  void ForwardUp(Ptr<Packet> p, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface> interface);

  /** Inherit from Socket class: Return data to upper-layer application. Parameter flags
   is not used. Data is returned as a packet of size no larger than maxSize */
  Ptr<Packet>
  Recv(uint32_t maxSize, uint32_t flags);
  int
  Send(Ptr<Packet> p, uint32_t flags);

  /**
   * Sending data via subflows with available window size. It sends data only to ESTABLISHED subflows.
   * It sends data by calling SendDataPacket() function.
   * Called by functions: ReceveidAck, NewAck
   * send as  much as possible
   * \return true if it send mappings
   */
  virtual bool SendPendingData(bool withAck = false);



  // TODO remove, move to subflow
//  void SendRST(uint8_t sFlowIdx);

  /** disabled
  */
  virtual uint32_t
  SendDataPacket(SequenceNumber32 seq, uint32_t maxSize, bool withAck);

  // Connection closing operations
//  virtual int DoClose(uint8_t sFlowIdx);

//  bool CloseMultipathConnection();      // Close MPTCP connection is possible
//  void PeerClose(uint8_t sFlow, Ptr<Packet> p, const TcpHeader& tcpHeader);
//  void DoPeerClose(uint8_t sFlowIdx);
//  void CloseAndNotify(uint8_t sFlowIdx);
//  void Destroy(void);
//  void DestroySubflowMapDSN(void);
//  void DestroyUnOrdered();

  // Why do we need those ?
//  void CancelAllTimers(uint8_t sFlowIdx);
//  void DeallocateEndPoint(uint8_t sFlowIdx);
  void CancelAllSubflowTimers(void);
//  void TimeWait(uint8_t sFlowIdx);

  void ProcessListen  (Ptr<Packet>, const TcpHeader&, const Address&, const Address&);

  // State transition functions

  ///////////////////////////////////
  // TODO move ALL these to subflow
  ///////////////////////////////////
//  void ProcessListen  (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&, const Address&, const Address&);
//void ProcessEstablished (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);


//  void ProcessSynSent (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);
//  void ProcessSynRcvd (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&, const Address&, const Address&);
//  void ProcessWait    (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);
//  void ProcessClosing (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);
//  void ProcessLastAck (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);




  // Manage data Tx/Rx
  virtual Ptr<TcpSocketBase> Fork(void);


  virtual void
  ReTxTimeout();

  /**
  */
  virtual Ptr<MpTcpSocketBase> ForkAsMeta(void) = 0;



  virtual void Retransmit();
  // TODO see if we can remove/override parents

  //! Disabled
  virtual void ReceivedAck ( Ptr<Packet>, const TcpHeader&); // Received an ACK packet

  //! Disabled
  virtual void ReceivedData ( Ptr<Packet>, const TcpHeader&); // Recv of a data, put into buffer, call L7 to get it if necessary

  virtual void ProcessDSS( const TcpHeader& tcpHeader, Ptr<TcpOptionMpTcpDSS> dss, Ptr<MpTcpSubFlow> sf);
  virtual void ProcessDSSClosing( Ptr<TcpOptionMpTcpDSS> dss, Ptr<MpTcpSubFlow> sf);
  virtual void ProcessDSSWait( Ptr<TcpOptionMpTcpDSS> dss, Ptr<MpTcpSubFlow> sf);
  virtual void ProcessDSSEstablished( const TcpHeader& tcpHeader, Ptr<TcpOptionMpTcpDSS> dss, Ptr<MpTcpSubFlow> sf);


  /** Does nothing */
  virtual void EstimateRtt (const TcpHeader&);

//  virtual bool ReadOptions (uint8_t sFlowIdx, Ptr<Packet> pkt, const TcpHeader&); // Read option from incoming packets
//  virtual bool ReadOptions (Ptr<Packet> pkt, const TcpHeader&); // Read option from incoming packets (Listening Socket only)

  //! Disabled
  void DupAck(const TcpHeader& t, uint32_t count);
  virtual void DupAck( SequenceNumber32 ack,Ptr<MpTcpSubFlow> );
//  void DupAck(uint8_t sFlowIdx, DSNMapping * ptrDSN);       // Congestion control algorithms -> loss recovery
//  void NewACK(uint8_t sFlowIdx, const TcpHeader&, TcpOptions* opt);
//  void NewAckNewReno(uint8_t sFlowIdx, const TcpHeader&, TcpOptions* opt);
//  void DoRetransmit (uint8_t sFlowIdx);
//  void DoRetransmit (uint8_t sFlowIdx, DSNMapping* ptrDSN);
//  void SetReTxTimeout(uint8_t sFlowIdx);

  /**
  * @return
  */

  /**
  */
// virtual  GenerateMappings = 0

  /**
  * @brief
  * @return
  */
  Time ComputeReTxTimeoutForSubflow( Ptr<MpTcpSubFlow> );

  bool DoChecksum() const;

  //////////////////////////////////////////////////////////////////
  ////  Here follows a list of MPTCP specific *callbacks* triggered by subflows
  ////  on certain events

  /**
   * @param
   * @param mapping
   add count param ?
  */
  virtual void OnSubflowDupack(Ptr<MpTcpSubFlow> sf, MpTcpMapping mapping);
  virtual void OnSubflowRetransmit(Ptr<MpTcpSubFlow> sf) ;

//  void LastAckTimeout(uint8_t sFlowIdx);


  /**
   *  inherited from parent: update buffers
   * @brief Called from subflows when they receive DATA-ACK. For now calls parent fct
   */
  virtual void
  NewAck(SequenceNumber32 const& dataLevelSeq);

  //! disabled
  virtual void
  SendEmptyPacket(TcpHeader& header);

  // Not implemented yet
//  virtual void
//  NewAck(SequenceNumber64 const& dataLevelSeq);

  // Re-ordering buffer
//  bool StoreUnOrderedData(DSNMapping *ptr);
//  void ReadUnOrderedData();

  /** this implementation may not be the best, maybe it would be best to subclass MpTcpSubflows
   depending on the Congestion control used. But for now it is goodenough
   Both functions the new value
   **/
//  virtual uint32_t OpenCWND(uint32_t cwnd, uint32_t ackedBytes) = 0;
//  virtual uint32_t ReduceCWND(uint32_t cwnd) = 0;




  void OnTimeWaitTimeOut();

protected: // protected variables

  int CloseSubflow(Ptr<MpTcpSubFlow> sf);

  std::string m_tracePrefix;


  virtual TypeId GetMpTcpSubflowTypeId() = 0;

  /**
  *
  */
  SubflowList m_subflows[Maximum];
  //! 0 for established,
  //!< 1 for established
  //!< 2 for backups

  Callback<bool, Ptr<Socket>, Address, uint8_t > m_onRemoteAddAddr;  //!< return true to create a subflow
//  Callback<bool, Ptr<Socket>, Address, uint8_t > m_onNewLocalIp;  //!< return true to create a subflow
  Callback<void, uint8_t > m_onAddrDeletion;// return true to create a subflow

//  Callback<void, const MpTcpAddressInfo& > m_onRemAddr;

//  virtual void OnAddAddress(MpTcpAddressInfo);
//  virtual void OnRemAddress();

  bool m_mpEnabled;   //!< True if remote host is MPTCP compliant (not used so far. could be disabled)

  // TODO rename since will track local too.
  Ptr<MpTcpPathIdManager> m_remotePathIdManager;  //!< Keep track of advertised ADDR id advertised by remote endhost


//  MappingList m_unOrdered;  //!< buffer that hold the out of sequence received packet

  // Congestion control
  /***
  TODO the scheduler is so closely

  ***/
  Ptr<MpTcpSchedulerRoundRobin> m_scheduler;  //!<
//  Ptr<MpTcpCongestionControl> m_algoCC;  //!<  Algorithm for Congestion Control


  // Window management variables node->GetObject<TcpL4Protocol>();
  uint32_t m_ssThresh;           // Slow start threshold
  uint32_t m_initialCWnd;        //!< Initial congestion window value

  // TODO alread
//  uint32_t remoteRecvWnd;        // Flow control window at remote side TODO rename ?

// Already defined in
//  uint32_t m_segmentSize;          // Segment size

  TracedValue<uint32_t>  m_cWnd;         //< Congestion window


  // TODO replace with parent's traced values
//  uint64_t nextTxSequence;       // Next expected sequence number to send in connection level
//  uint64_t nextRxSequence;       // Next expected sequence number to receive in connection level


  // TODO make private ? check what it does
  // should be able to rmeove one
  bool m_server;

private:
  // TODO rename into m_localKey  and move tokens into subflow (maybe not even needed)
  uint64_t m_localKey;  //!< Store local host token, generated during the 3-way handshake
  uint32_t m_localToken;

  uint64_t m_peerKey; //!< Store remote host token
  uint32_t m_peerToken;

  bool     m_doChecksum;  //!< Compute the checksum. Negociated during 3WHS

private:


  /* Utility function used when a subflow changes state
    Research of the subflow is done
  */
  void MoveSubflow(Ptr<MpTcpSubFlow> sf, mptcp_container_t to);
  void MoveSubflow(Ptr<MpTcpSubFlow> sf, mptcp_container_t from, mptcp_container_t to);
// CloseSubflow
//  uint8_t AddLocalAddr(const Ipv4Address& address);
//
//  bool RemLocalAddr(Ipv4Address,uint8_t&);


};

}   //namespace ns3

#endif /* MP_TCP_SOCKET_BASE_H */
