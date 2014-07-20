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
#include "ns3/gnuplot.h"
#include "mp-tcp-subflow.h"

using namespace std;
namespace ns3
{
class Ipv4EndPoint;
class Node;
class Packet;
class TcpL4Protocol;
//class MpTcpPathManager;
class MpTcpSubFlow;


/**
TODO rename in MetaSocket ?

This is the MPTCP meta socket the application talks with
this socket. New subflows, as well as the first one (the master
socket) are linked to this meta socket.
**/
class MpTcpSocketBase : public TcpSocketBase
{
public: // public methods

  static TypeId GetTypeId(void);
  MpTcpSocketBase();
  MpTcpSocketBase(Ptr<Node> node);
  virtual ~MpTcpSocketBase();


  /**
  \warn This function should be called once a connection is established else
  **/
  virtual bool IsMpTcpEnabled() const;
  virtual uint64_t GenerateKey() const;

  bool IsConnected() const;

  // Public interface for MPTCP
  virtual int Bind();                         // Bind a socket by setting up endpoint in TcpL4Protocol
  virtual int Bind(const Address &address);   // Bind a socket ... to specific add:port
  virtual int Connect(const Address &address);

  // TODO to remove there is no equivalent in parent's class
  virtual int Connect(Ipv4Address servAddr, uint16_t servPort);

  virtual int Listen(void);
  virtual int Close(void);                    // Close by app: Kill socket upon tx buffer emptied
  virtual int Close(uint8_t sFlowIdx);        // Closing subflow...
  uint32_t GetTxAvailable();                  // Return available space in sending buffer to application
  bool SendBufferedData();                    // This would called SendPendingData() - TcpTxBuffer API need to be used in future!
  int FillBuffer(uint8_t* buf, uint32_t size);// Fill sending buffer with data - TcpTxBuffer API need to be used in future!
  uint32_t Recv(uint8_t* buf, uint32_t size); // Receive data from receiveing buffer - TcpRxBuffe API need to be used in future!
  void allocateSendingBuffer(uint32_t size);  // Can be removed now as SetSndBufSize() is implemented instead!
  void allocateRecvingBuffer(uint32_t size);  // Can be removed now as SetRcvBufSize() is implemented instead!
  void SetMaxSubFlowNumber(uint8_t num);      // Max number of subflows a sender can initiate
  uint8_t GetMaxSubFlowNumber();
  void SetSourceAddress(Ipv4Address src);     // Explicitly specified the source IP address
  Ipv4Address GetSourceAddress();

  // Setter for congestion Control and data distribution algorithm
  void SetCongestionCtrlAlgo(CongestionCtrl_t ccalgo);  // This would be used by attribute system for setting congestion control
  void SetDataDistribAlgo(DataDistribAlgo_t ddalgo);    // Round Robin is only algorithms used.

//  void SetPathManager(Ptr<MpTcpPathManager>);
  //
  int CreateSubflow(const Address& srcAddr, const Address& dstAddr);
  // Path management related functions
//  void AdvertiseAddress(); //
  void AdvertiseAvailableAddresses(); // Advertise all addresses to the peer, including the already established address.

  virtual int GenerateToken(uint32_t& token ) const;

  /**
  \return 0 In case of success
  TODO bool ?
  **/
  int GetRemoteKey(uint32_t& remoteKey) const;
  uint32_t
  GetLocalKey() const;

public: // public variables

  // TODO move back to protected/private later on


  // Evaluation & plotting parameters and containers
//  int mod;    // available in parent TODO remove
  int MSS;    // Maximum Segment Size
  int LinkCapacity; // ?
  int totalBytes; // ?
  double RTT; //
  double lostRate;  // rename to lossRate ?
  double TimeScale;
  uint32_t pAck;
  GnuplotCollection gnu;
  std::list<uint32_t> sampleList;

  // TODO remove in favor of parents' ?
  vector<pair<double, double> > totalCWNDtrack;
  vector<pair<double, double> > reTxTrack;
  vector<pair<double, double> > timeOutTrack;
  vector<pair<double, double> > PartialAck;
  vector<pair<double, double> > FullAck;
  vector<pair<double, double> > DupAcks;
  vector<pair<double, double> > PacketDrop;
  vector<pair<double, double> > TxQueue;

protected: // protected methods

  friend class Tcp;
  friend class MpTcpSubFlow;


//  virtual int SetLocalToken(uint32_t token) const;

  // Implementing some inherited methods from ns3::TcpSocket. No need to comment them!
  virtual void SetSndBufSize (uint32_t size);
  virtual uint32_t GetSndBufSize (void) const;
  virtual void SetRcvBufSize (uint32_t size);
  virtual uint32_t GetRcvBufSize (void) const;
  virtual void SetSSThresh(uint32_t threshold);
  virtual uint32_t GetSSThresh(void) const;
  virtual void SetInitialCwnd(uint32_t cwnd);
  virtual uint32_t GetInitialCwnd(void) const;
  virtual void SetSegSize(uint32_t size);
  virtual uint32_t GetSegSize(void) const;

  // MPTCP connection and subflow set up
  int  SetupCallback(void);  // Setup SetRxCallback & SetRxCallback call back for a host
  int  SetupEndpoint (void); // Configure local address for given remote address in a host - it query a routing protocol to find a source
  void CompleteFork(Ptr<Packet> p, const TcpHeader& h, const Address& fromAddress, const Address& toAddress);

  // TODO remove should be done by helper instead
  bool InitiateSubflows();            // Initiate new subflows

  /**
  Fails if
  **/
//  bool AddLocalAddress(uint8_t&, Port);
// Should generate an Id

  /**
  Will notify callback on ADD_ADDR reception
  **/
  void SetAddAddrCallback(Callback<bool, Ptr<Socket>, Address, uint8_t> );
  void NotifyAddAddr(MpTcpAddressInfo);
  void NotifyRemAddr(uint8_t addrId);


  void
  ConnectionSucceeded(void); // Schedule-friendly wrapper for Socket::NotifyConnectionSucceeded()


  // Transfer operations
  void ForwardUp(Ptr<Packet> p, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface> interface);

  // These should be removed (or at least remove the flowId)
  bool SendPendingData(uint8_t sFlowId = -1);
  void SendEmptyPacket(uint8_t sFlowId, uint8_t flags);
  void SendRST(uint8_t sFlowIdx);
  uint32_t SendDataPacket (uint8_t sFlowIdx, uint32_t pktSize, bool withAck);

  // Connection closing operations
  virtual int DoClose(uint8_t sFlowIdx);
  bool CloseMultipathConnection();      // Close MPTCP connection is possible
  void PeerClose(uint8_t sFlow, Ptr<Packet> p, const TcpHeader& tcpHeader);
  void DoPeerClose(uint8_t sFlowIdx);
  void CloseAndNotify(uint8_t sFlowIdx);
  void Destroy(void);
  void DestroySubflowMapDSN(void);
  void DestroyUnOrdered();

  // Why do we need those ?
  void CancelAllTimers(uint8_t sFlowIdx);
  void DeallocateEndPoint(uint8_t sFlowIdx);
  void CancelAllSubflowTimers(void);
  void TimeWait(uint8_t sFlowIdx);

  // State transition functions
  void ProcessEstablished (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);
  void ProcessListen  (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&, const Address&, const Address&);
  void ProcessListen  (Ptr<Packet>, const TcpHeader&, const Address&, const Address&);
  void ProcessSynSent (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);
  void ProcessSynRcvd (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&, const Address&, const Address&);
  void ProcessWait    (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);
  void ProcessClosing (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);
  void ProcessLastAck (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);
  uint8_t ProcessOption(TcpOptions *opt);

  // Window Management
  virtual uint32_t BytesInFlight(uint8_t sFlowIdx);  // Return total bytes in flight of a subflow
  uint16_t AdvertisedWindowSize();
  uint32_t AvailableWindow(uint8_t sFlowIdx);

  // Manage data Tx/Rx
  virtual Ptr<TcpSocketBase> Fork(void);
  virtual void ReceivedAck (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&); // Received an ACK packet
  virtual void ReceivedData (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&); // Recv of a data, put into buffer, call L7 to get it if necessary
  virtual void EstimateRtt (uint8_t sFlowIdx, const TcpHeader&);
  virtual void EstimateRtt (const TcpHeader&);
  virtual bool ReadOptions (uint8_t sFlowIdx, Ptr<Packet> pkt, const TcpHeader&); // Read option from incoming packets
  virtual bool ReadOptions (Ptr<Packet> pkt, const TcpHeader&); // Read option from incoming packets (Listening Socket only)
  virtual void DupAck(const TcpHeader& t, uint32_t count);  // Not in operation, it's pure virtual function from TcpSocketBase
  void DupAck(uint8_t sFlowIdx, DSNMapping * ptrDSN);       // Congestion control algorithms -> loss recovery
  void NewACK(uint8_t sFlowIdx, const TcpHeader&, TcpOptions* opt);
  void NewAckNewReno(uint8_t sFlowIdx, const TcpHeader&, TcpOptions* opt);
  void DoRetransmit (uint8_t sFlowIdx);
  void DoRetransmit (uint8_t sFlowIdx, DSNMapping* ptrDSN);
  void SetReTxTimeout(uint8_t sFlowIdx);
  void ReTxTimeout(uint8_t sFlowIdx);
  void Retransmit(uint8_t sFlowIdx);
  void LastAckTimeout(uint8_t sFlowIdx);
  void DiscardUpTo(uint8_t sFlowIdx, uint32_t ack);

  // Re-ordering buffer
  bool StoreUnOrderedData(DSNMapping *ptr);
  void ReadUnOrderedData();
  bool FindPacketFromUnOrdered(uint8_t sFlowIdx);

  // Congestion control
  void OpenCWND(uint8_t sFlowIdx, uint32_t ackedBytes);
  void ReduceCWND(uint8_t sFlowIdx, DSNMapping* ptrDSN);
  void calculateAlpha();
  void calculateTotalCWND();

  // Helper functions -> main operations
  uint8_t LookupByAddrs(Ipv4Address src, Ipv4Address dst); // Called by Forwardup() to find the right subflow for incoing packet

  uint8_t getSubflowToUse();  // Called by SendPendingData() to get a subflow based on round robin algorithm

  bool IsThereRoute(Ipv4Address src, Ipv4Address dst);     // Called by InitiateSubflow & LookupByAddrs and Connect to check whether there is route between a pair of addresses.
  bool IsLocalAddress(Ipv4Address addr);
  Ptr<NetDevice> FindOutputNetDevice(Ipv4Address);         // Find Netdevice object of specific IP address.
  DSNMapping* getAckedSegment(uint8_t sFlowIdx, uint32_t ack);
  DSNMapping* getSegmentOfACK(uint8_t sFlowIdx, uint32_t ack);

  // Helper functions -> evaluation and debugging
  void PrintIpv4AddressFromIpv4Interface(Ptr<Ipv4Interface>, int32_t);
  std::string PrintCC(uint32_t cc);
  void getQueuePkt(Ipv4Address addr);


  // Helper functions -> plotting
  std::string GeneratePlotDetail();
  void GenerateRTTPlot();
  void GenerateCWNDPlot();
  void GenerateSendvsACK();
  void GenerateRTT();
  void GenerateCwndTracer();
  void GeneratePktCount();
  void generatePlots();

protected: // protected variables

  // MPTCP connection parameters
  Ptr<Node>          m_node;
//  Ipv4EndPoint*      m_endPoint;    // TODO could remove since its parent already defines it
//  Ptr<TcpL4Protocol> m_mptcp;       //? what is this ? use m_tcp from parent socket


  // TODO remove
  Ipv4Address        m_localAddress;
  Ipv4Address        m_remoteAddress;
  uint16_t           m_localPort;
  uint16_t           m_remotePort;
  uint8_t            m_currentSublow; // master socket ??? to remove

  std::vector<Ptr<MpTcpSubFlow> > m_subflows;

  //Ptr<MpTcpPathManager> m_pathManager;
  Callback<bool, Ptr<Socket>, Address, uint8_t > m_onAddAddr;  // return true to create a subflow
//  Callback<void, const MpTcpAddressInfo& > m_onRemAddr;

//  virtual void OnAddAddress(MpTcpAddressInfo);
//  virtual void OnRemAddress();


  // MultiPath related parameters
  MpStates_t mpSendState;   //!< TODO to remove (useless)
  MpStates_t mpRecvState;   //!< TODO to remove (useless)
  bool m_mpEnabled;   //!< True if remote host is MPTCP compliant
//  bool mpTokenRegister; //!< TODO remove
//  bool m_addrAdvertised;  //!< TODO remove

//  uint32_t m_unOrdMaxSize;  //!< Looks like it can be removed safely ?
  uint8_t  m_maxSubflows; //!< Max number of subflows
  uint8_t  m_lastUsedsFlowIdx;  //!< TODO remove ? part of the scheduler

  Ptr<MpTcpPathIdManager> m_remotePathIdManager;  //!< Keep track of advertised ADDR id advertised by remote endhost


  std::list<DSNMapping *> m_unOrdered;  // buffer that hold the out of sequence received packet


  // Congestion control
  // TODO store that in abstract class
  double alpha;
  uint32_t m_totalCwnd;

  CongestionCtrl_t AlgoCC;       // Algorithm for Congestion Control
  DataDistribAlgo_t distribAlgo; // Algorithm for Data Distribution

  // Window management variables node->GetObject<TcpL4Protocol>();
  uint32_t m_ssThresh;           // Slow start threshold
  uint32_t m_initialCWnd;        // Initial congestion window value
  uint32_t remoteRecvWnd;        // Flow control window at remote side
  uint32_t m_segmentSize;          // Segment size
  uint64_t nextTxSequence;       // Next expected sequence number to send in connection level
  uint64_t nextRxSequence;       // Next expected sequence number to receive in connection level

  // Buffer management
  DataBuffer *sendingBuffer;
  DataBuffer *recvingBuffer;

  // TODO make private ? check what it does
  // should be able to rmeove one
  bool client;
  bool server;

private:
  // TODO rename into m_localKey uint64_t and move tokens into subflow (maybe not even needed)
  uint32_t m_localKey;  //!< Store local host token, generated during the 3-way handshake
  uint32_t m_remoteKey; //!< Store remote host token

private:
//  bool
//  AddLocalAddr(bool remote, uint8_t addrId, const Address& address, uint16_t port);
//  bool
  RemAddr(bool remote, uint8_t addrId);


};

}   //namespace ns3

#endif /* MP_TCP_SOCKET_BASE_H */
