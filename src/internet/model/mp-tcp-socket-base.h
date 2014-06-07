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
  MpTcpSocketBase();
  MpTcpSocketBase(Ptr<Node> node);
  virtual ~MpTcpSocketBase();

  // Public interface for MPTCP
  virtual int Bind();                       // Bind a socket by setting up endpoint in TcpL4Protocol
  virtual int Bind(const Address &address); // Bind a socket ... to specific add:port
  virtual int Connect(Address &address);
  virtual int Connect(Ipv4Address servAddr, uint16_t servPort);
  virtual int Listen(void);
  virtual int Close(void);              // Close by app: Kill socket upon tx buffer emptied
  virtual int Close(uint8_t sFlowIdx);  // Closing subflow...
  uint32_t GetTxAvailable();

  bool SendBufferedData(); // This method should be public, it is called from application
  int FillBuffer(uint8_t* buf, uint32_t size);
  uint32_t Recv(uint8_t* buf, uint32_t size);
  void allocateSendingBuffer(uint32_t size);
  void allocateRecvingBuffer(uint32_t size);
  void SetunOrdBufMaxSize(uint32_t size);
  void SetMaxSubFlowNumber(uint8_t num);
  uint8_t GetMaxSubFlowNumber();
  void SetSourceAddress(Ipv4Address src);
  Ipv4Address GetSourceAddress();

  // Setter for congestion Control and data distribution algorithm.
  void SetCongestionCtrlAlgo(CongestionCtrl_t ccalgo);
  void SetDataDistribAlgo(DataDistribAlgo_t ddalgo);

  // Lost modeling
  double LossProbablity;

  // Evaluation & plotting parameters
  int mod;
  int LinkCapacity;
  int totalBytes;
  double lostRate;
  double RTT;
  double TimeScale;
  int MSS;
  GnuplotCollection gnu;
  uint32_t pAck;

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

protected: // Methods

  friend class Tcp;

  // Implementing some inherited methods from ns3::TcpSocket.
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
  int SetupCallback(void);
  int SetupEndpoint (void); // Configure m_endpoint for local address for given remote address
  void CompleteFork(Ptr<Packet> p, const TcpHeader& h, const Address& fromAddress, const Address& toAddress);
  void AdvertiseAvailableAddresses();
  bool InitiateSubflows();
  bool isMultipath();

  // Transfer operations
  void ForwardUp(Ptr<Packet> p, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface> interface);
  bool SendPendingData(uint8_t sFlowId = -1);
  void SendEmptyPacket(uint8_t sFlowId, uint8_t flags);
  uint32_t SendDataPacket (uint8_t sFlowIdx, uint32_t pktSize, bool withAck);
  void SendRST(uint8_t sFlowIdx);

  // Connection closing operations
  virtual int DoClose(uint8_t sFlowIdx);
  bool CloseMultipathConnection();
  void PeerClose(uint8_t sFlow, Ptr<Packet> p, const TcpHeader& tcpHeader);
  void DoPeerClose(uint8_t sFlowIdx);
  void CloseAndNotify(uint8_t sFlowIdx);
  void Destroy(void);
  void DestroySubflowMapDSN(void);
  void DestroyUnOrdered();
  void CancelAllTimers(uint8_t sFlowIdx);
  void DeallocateEndPoint(uint8_t sFlowIdx);
  void CancelAllSubflowTimers(void);
  void TimeWait(uint8_t sFlowIdx);

  // State transition functions
  void ProcessEstablished (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&); // Received a packet upon ESTABLISHED state
  void ProcessListen  (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&, const Address&, const Address&); // Process the newly received ACK
  void ProcessListen  (Ptr<Packet>, const TcpHeader&, const Address&, const Address&);
  void ProcessSynSent (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);     // Received a packet upon SYN_SENT
  void ProcessSynRcvd (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&, const Address&, const Address&); // Received a packet upon SYN_RCVD
  void ProcessWait    (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);      // Received a packet upon CLOSE_WAIT, FIN_WAIT_1, FIN_WAIT_2
  void ProcessClosing (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);      // Received a packet upon CLOSING
  void ProcessLastAck (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);      // Received a packet upon LAST_ACK
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
  virtual bool ReadOptions (Ptr<Packet> pkt, const TcpHeader&);
  virtual void DupAck(const TcpHeader& t, uint32_t count);
  void DupAck(uint8_t sFlowIdx, DSNMapping * ptrDSN);
  void NewACK(uint8_t sFlowIdx, const TcpHeader&, TcpOptions* opt);
  void NewAckNewReno(uint8_t sFlowIdx, const TcpHeader&, TcpOptions* opt);
  void DoRetransmit (uint8_t sFlowIdx);
  void DoRetransmit (uint8_t sFlowIdx, DSNMapping* ptrDSN);
  void SetReTxTimeout(uint8_t sFlowIdx);
  void ReTxTimeout(uint8_t sFlowIdx);
  void Retransmit(uint8_t sFlowIdx);
  void LastAckTimeout(uint8_t sFlowIdx);
  void DiscardUpTo(uint8_t sFlowIdx, uint32_t ack);
  bool StoreUnOrderedData(DSNMapping *ptr);
  void ReadUnOrderedData();
  bool FindPacketFromUnOrdered(uint8_t sFlowIdx);

  // Congestion control
  void OpenCWND(uint8_t sFlowIdx, uint32_t ackedBytes);
  void calculate_alpha();
  void calculateTotalCWND();
  void calculateSmoothedCWND(uint8_t sFlowIdx);
  void reduceCWND(uint8_t sFlowIdx, DSNMapping* ptrDSN);

  // Helper functions -> MPTCP main tasks
  Ptr<MpTcpSubFlow> GetSubflow(uint8_t sFlowIdx);
  Ptr<NetDevice> FindOutputNetDevice(Ipv4Address);
  uint8_t LookupByAddrs(Ipv4Address src, Ipv4Address dst);
  uint8_t getSubflowToUse();
  bool IsThereRoute(Ipv4Address src, Ipv4Address dst);
  bool IsLocalAddress(Ipv4Address addr);
  bool LookupDSNMapping();
  void DetectLocalAddresses();
  DSNMapping* getAckedSegment(uint8_t sFlowIdx, uint32_t ack);
  DSNMapping* getAckedSegment(uint64_t lEdge, uint64_t rEdge);
  DSNMapping* getSegmentOfACK(uint8_t sFlowIdx, uint32_t ack);

  // Helper functions -> evaluation and debugging
  void PrintIpv4AddressFromIpv4Interface(Ptr<Ipv4Interface>, int32_t);
  void getQueuePkt(Ipv4Address addr);
  void HeartBeat();
  std::string PrintCC(uint32_t cc);
  uint32_t getL3MTU(Ipv4Address addr);
  uint64_t getBandwidth(Ipv4Address addr);
  uint64_t getPathBandwidth(uint8_t idxPath);
  double getGlobalThroughput();
  double getPathDelay(uint8_t idxPath);
  double getConnectionEfficiency();

  // Generate plots
  std::string GeneratePlotDetail();
  void GenerateRTTPlot();
  void GenerateCWNDPlot();
  void GenerateSendvsACK();
  void GenerateRTT();
  void GenerateCwndTracer();
  void GeneratePktCount();
  void generatePlots();

protected: // Variables

  // MPTCP Connection Parameters
  Ptr<Node>             m_node;
  Ipv4EndPoint*         m_endPoint;
  Ptr<TcpL4Protocol>    m_mptcp;
  Ipv4Address           m_localAddress;
  uint16_t              m_localPort;
  Ipv4Address           m_remoteAddress;
  uint16_t              m_remotePort;
  uint8_t currentSublow;

  // MultiPath Related
  MpStates_t mpState;
  MpStates_t mpSendState;
  MpStates_t mpRecvState;
  bool mpEnabled;
  bool addrAdvertised;
  bool mpTokenRegister;
  uint32_t localToken;
  uint32_t remoteToken;
  uint32_t unOrdMaxSize;
  uint8_t  maxSubflows;
  uint8_t lastUsedsFlowIdx;

  // MPTCP Containers
  vector<Ptr<MpTcpSubFlow> > subflows;
  vector<MpTcpAddressInfo *> localAddrs;
  vector<MpTcpAddressInfo *> remoteAddrs;
  list<DSNMapping *> unOrdered;    // buffer that hold the out of sequence received packet

  // Congestion Control
  uint32_t totalCwnd;
  double alpha;
  CongestionCtrl_t AlgoCC;         // Algorithm for Congestion Control
  DataDistribAlgo_t distribAlgo;   // Algorithm for Data Distribution

  // Window management variables
  uint32_t m_ssThresh;           // Slow start threshold
  uint32_t m_initialCWnd;        // Initial congestion window value
  uint32_t remoteRecvWnd;        // Flow control window at remote side
  uint32_t segmentSize;          // Segment size
  uint64_t nextTxSequence;       // Next expected sequence number to send in connection level
  uint64_t nextRxSequence;       // Next expected sequence number to receive in connection level

  // Buffer Management
  DataBuffer *sendingBuffer;
  DataBuffer *recvingBuffer;

  bool client;
  bool server;
};

}   //namespace ns3

#endif /* MP_TCP_SOCKET_BASE_H */
