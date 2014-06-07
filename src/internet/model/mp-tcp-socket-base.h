/*
 * MultiPath-TCP (MPTCP) implementation.
 * Programmed by Morteza Kheirkhah from University of Sussex.
 * Some codes here are retrieved from NS3::TCPNewReno implementation and old version of MPTCP implementation in NS3.6.
 */
#ifndef MP_TCP_SOCKET_BASE_H
#define MP_TCP_SOCKET_BASE_H

#include "ns3/mp-tcp-typedefs.h"
#include "ns3/tcp-socket-base.h"
#include "ns3/Gnuplot.h"
#include "mp-tcp-subflow.h"

using namespace std;
namespace ns3
{
class Ipv4EndPoint;
class Node;
class Packet;
class TcpL4Protocol;

class MpTcpSocketBase : public TcpSocketBase
{
public:

  static TypeId GetTypeId(void);
  //MpTcpStateMachine *m_stateMachine;
  /**
   * Create an unbound MPTCP socket
   */
  MpTcpSocketBase();
  /**
   * Create an bound MPTCP socket
   */
  MpTcpSocketBase(Ptr<Node> node);
  virtual ~MpTcpSocketBase();

  //Public interface for MPTCP
  virtual int Bind();                       // Bind a socket by setting up endpoint in TcpL4Protocol
  virtual int Bind(const Address &address); // Bind a socket ... to specific add:port
  virtual int Connect(Address &address);    // Setup endpoint and call ProcessAction() to connect
  int Connect(Ipv4Address servAddr, uint16_t servPort);
  virtual int Listen(void);           // Verify the socket is in a correct state and call ProcessAction() to listen
  virtual int Close(void);            // Close by app: Kill socket upon tx buffer emptied
  virtual int Close(uint8_t sFlowIdx);// Closing subflow...
  virtual int DoClose(uint8_t sFlowIdx);  // Here the signal is sent to peer
  void PeerClose(uint8_t sFlow, Ptr<Packet> p, const TcpHeader& tcpHeader);
  void DoPeerClose(uint8_t sFlowIdx);
  void LastAckTimeout(uint8_t sFlowIdx);
  void TimeWait(uint8_t sFlowIdx);
  void CancelAllTimers(uint8_t sFlowIdx);
  void DeallocateEndPoint(uint8_t sFlowIdx);
  void CancelAllSubflowTimers(void);
  bool FindPacketFromUnOrdered(uint8_t sFlowIdx);
  void DestroySubflowMapDSN(void);
  void DestroyUnOrdered();
  void CloseAndNotify(uint8_t sFlowIdx);
  void SendRST(uint8_t sFlowIdx);
  uint32_t Recv(uint8_t* buf, uint32_t size);
  uint32_t GetTxAvailable();  // Available-to-read data size, i.e. value of m_rxAvailable
  void getQueuePkt(Ipv4Address addr);

  uint32_t AvailableWindow(uint8_t sFlowIdx); // Return unfilled portion of window
  bool SendBufferedData();
  int FillBuffer(uint8_t* buf, uint32_t size);

  // Evaluation containers
  vector<pair<double, double> > totalCWNDtrack;
  vector<pair<double, double> > reTxTrack;
  vector<pair<double, double> > timeOutTrack;
  vector<pair<double, double> > PartialAck;
  vector<pair<double, double> > FullAck;
  vector<pair<double, double> > DupAcks;
  vector<pair<double, double> > PacketDrop;
  vector<pair<double, double> > TxQueue;
  std::list<uint32_t> sampleList;
  uint8_t GetMaxSubFlowNumber();
  void SetMaxSubFlowNumber(uint8_t num);
  void SetSourceAddress(Ipv4Address src);
  Ipv4Address GetSourceAddress();

  // extended Socket API for Multipath support
  bool isMultipath();
  void AdvertiseAvailableAddresses();
  bool InitiateSubflows();
  uint8_t currentSublow;

  void allocateSendingBuffer(uint32_t size);
  void allocateRecvingBuffer(uint32_t size);
  void SetunOrdBufMaxSize(uint32_t size);
  virtual void SetSndBufSize (uint32_t size);
  virtual uint32_t GetSndBufSize (void) const;
  virtual void SetRcvBufSize (uint32_t size);
  virtual uint32_t GetRcvBufSize (void) const;
  double getPathDelay(uint8_t idxPath);
  uint64_t getPathBandwidth(uint8_t idxPath);
  double getConnectionEfficiency();
  bool rejectPacket(double threshold);
  Ptr<MpTcpSubFlow> GetSubflow(uint8_t sFlowIdx);
  uint32_t GetOutputInf(Ipv4Address addr);
  void SetCongestionCtrlAlgo(CongestionCtrl_t ccalgo);
  void SetDataDistribAlgo(DataDistribAlgo_t ddalgo);

  // Generate RTT-CDF plot.
  void GenerateRTTPlot();
  void GenerateCWNDPlot();
  void GenerateSendvsACK();
  void GenerateRTT();
  void GenerateCwndTracer();
  std::string
  GeneratePlotDetail();
  void GeneratePktCount();
  // Some pure virtual protected functions from TcpSocketBase
  //.........................................................................
  virtual void SetSSThresh(uint32_t threshold);
  virtual uint32_t GetSSThresh(void) const;
  virtual void SetInitialCwnd(uint32_t cwnd);
  virtual uint32_t GetInitialCwnd(void) const;
  virtual Ptr<TcpSocketBase> Fork(void);
  virtual void DupAck(const TcpHeader& t, uint32_t count); // Received dupack
  //..........................................................................
  // Some Extra Helper functions
  void PrintIpv4AddressFromIpv4Interface(Ptr<Ipv4Interface>, int32_t);
  Ptr<NetDevice> FindOutputNetDevice(Ipv4Address);
  //..........................................................................

  // Lost modeling
  double LossProbablity;
  uint32_t counter;
  EventId timeOut;
  void HeartBeat();
  void generatePlots();

  // Evaluation parameter (public variable)
  int mod;
  int LinkCapacity;
  int totalBytes;
  double lostRate;
  double RTT;
  double TimeScale;
  int MSS;
  std::string PrintCC(uint32_t cc);
  GnuplotCollection gnu;
  uint32_t pAck;

protected:
  virtual void
  SetSegSize(uint32_t size);
  virtual uint32_t
  GetSegSize(void) const;

  // Helper function
  uint32_t SendDataPacket (uint8_t sFlowIdx, uint32_t pktSize, bool withAck);      // Send a data packet
  //.................................................................................................
  int SetupEndpoint (void);        // Configure m_endpoint for local addr for given remote addr (NEW)
  virtual void EstimateRtt (uint8_t sFlowIdx, const TcpHeader&); // RTT accounting
  virtual void EstimateRtt (const TcpHeader&);
  virtual bool ReadOptions (uint8_t sFlowIdx, Ptr<Packet> pkt, const TcpHeader&); // Read option from incoming packets
  virtual bool ReadOptions (Ptr<Packet> pkt, const TcpHeader&);
  void CompleteFork(Ptr<Packet> p, const TcpHeader& h, const Address& fromAddress, const Address& toAddress);
  //.................................................................................................
  // State transition functions
  void ProcessEstablished (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&); // Received a packet upon ESTABLISHED state
  void ProcessListen  (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&, const Address&, const Address&); // Process the newly received ACK
  void ProcessListen  (Ptr<Packet>, const TcpHeader&, const Address&, const Address&);
  void ProcessSynSent (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);     // Received a packet upon SYN_SENT
  void ProcessSynRcvd (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&, const Address&, const Address&); // Received a packet upon SYN_RCVD
  void ProcessWait    (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);      // Received a packet upon CLOSE_WAIT, FIN_WAIT_1, FIN_WAIT_2
  void ProcessClosing (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);      // Received a packet upon CLOSING
  void ProcessLastAck (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);      // Received a packet upon LAST_ACK
  //.................................................................................................
  // Manage data tx/rx
  virtual void ReceivedAck (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&); // Received an ACK packet
  virtual void ReceivedData (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&); // Recv of a data, put into buffer, call L7 to get it if necessary
  void DoRetransmit (uint8_t sFlowIdx); // Retransmit the oldest packet
  void DoRetransmit (uint8_t sFlowIdx, DSNMapping* ptrDSN); // Retransmit the oldest packet
  void DiscardUpTo(uint8_t sFlowIdx, uint32_t ack);
  bool StoreUnOrderedData(DSNMapping *ptr);
  void ReadUnOrderedData();
  void ProcessMultipathState();
  void OpenCWND(uint8_t sFlowIdx, uint32_t ackedBytes);
  void calculate_alpha();
  void calculateTotalCWND();
  void calculateSmoothedCWND(uint8_t sFlowIdx);
  void reduceCWND(uint8_t sFlowIdx, DSNMapping* ptrDSN);
  DSNMapping* getAckedSegment(uint8_t sFlowIdx, uint32_t ack);
  DSNMapping* getAckedSegment(uint64_t lEdge, uint64_t rEdge);
  DSNMapping* getSegmentOfACK(uint8_t sFlowIdx, uint32_t ack);
  double getGlobalThroughput();
  uint8_t getSubflowToUse();
  int SetupCallback(void);

  Ptr<Node>             m_node;
  Ipv4EndPoint*         m_endPoint;
  Ptr<TcpL4Protocol>  m_mptcp;
  Ipv4Address           m_localAddress;
  uint16_t              m_localPort;
  Ipv4Address           m_remoteAddress;
  uint16_t              m_remotePort;

  // Multipath related variables
  uint8_t maxSubflows;
  MpStates_t mpState;
  MpStates_t mpSendState;
  MpStates_t mpRecvState;
  bool mpEnabled;
  bool addrAdvertised;
  bool mpTokenRegister;
  vector<Ptr<MpTcpSubFlow> > subflows;
  vector<MpTcpAddressInfo *> localAddrs;
  vector<MpTcpAddressInfo *> remoteAddrs;
  map<Ipv4Address, uint32_t> sfInitSeqNb;
  list<DSNMapping *> unOrdered;    // buffer that hold the out of sequence received packet
  uint32_t unOrdMaxSize; // maximum size of the buf that hold temporary the out of sequence data

  uint8_t lastUsedsFlowIdx;
  uint32_t totalCwnd;
  double meanTotalCwnd;
  double alpha;

  CongestionCtrl_t AlgoCC;         // Algorithm for Congestion Control
  DataDistribAlgo_t distribAlgo;    // Algorithm for Data Distribution

  // Multipath tockens
  uint32_t localToken;
  uint32_t remoteToken;

  DataBuffer *sendingBuffer;
  DataBuffer *recvingBuffer;

  // Rx buffer state
  uint32_t m_rxAvailable; // amount of data available for reading through Recv
  uint32_t m_rxBufSize;   // size in bytes of the data in the rx buf
  //.........................................................................

//private:
protected:
  friend class Tcp;
  bool client;
  bool server;
  int Binding();
  void ForwardUp(Ptr<Packet> p, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface> interface);
  void Destroy(void);
  void SendEmptyPacket(uint8_t sFlowId, uint8_t flags);
  void SendAcknowledge(uint8_t sFlowId, uint8_t flags, TcpOptions *opt);
  bool SendPendingData(uint8_t sFlowId = -1);
  bool LookupDSNMapping();
  uint8_t ProcessOption(TcpOptions *opt);
  void SetReTxTimeout(uint8_t sFlowIdx);
  void ReTxTimeout(uint8_t sFlowIdx);
  void Retransmit(uint8_t sFlowIdx);
  bool IsDuplicatedAck(uint8_t sFlowIdx, TcpHeader l4Header, TcpOptions *opt);
  void DupAck(uint8_t sFlowIdx, DSNMapping * ptrDSN);
  void NewACK(uint8_t sFlowIdx, const TcpHeader&, TcpOptions* opt);
  void NewAckNewReno(uint8_t sFlowIdx, const TcpHeader&, TcpOptions* opt);
  uint8_t LookupByAddrs(Ipv4Address src, Ipv4Address dst);
  void DetectLocalAddresses();
  uint32_t getL3MTU(Ipv4Address addr);
  uint64_t getBandwidth(Ipv4Address addr);

  //methods for window management
  virtual uint32_t BytesInFlight(uint8_t sFlowIdx);  // Return total bytes in flight of a subflow
  virtual bool IsThereRoute(Ipv4Address src, Ipv4Address dst);
  virtual bool IsLocalAddress(Ipv4Address addr);
  virtual bool CloseMultipathConnection();
  uint16_t AdvertisedWindowSize();

  // Window management variables
  uint32_t m_ssThresh;                   //Slow Start Threshold
  uint32_t m_initialCWnd;                //Initial cWnd value
  uint32_t remoteRecvWnd;                //Flow control window at remote side
  uint32_t segmentSize;

  uint64_t nextTxSequence;       // sequence number used by the multipath capable sender
  uint32_t unAckedDataCount;     // Number of outstanding bytes
  uint64_t nextRxSequence;
};

}   //namespace ns3

#endif /* MP_TCP_SOCKET_BASE_H */
