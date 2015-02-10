TODO list:


Bugs:
* I don't register the rWnd during connection establishement apparently
* Msubflow::NewAck does not do enough 
* subflow DupAck should count only if there a DSS inside and not for any other MPTCP option* remote wnd of the meta and subflows should be the same
* When computing global cwin, differentiate  fast recovery cases
* when retransmitting a packet, the mapping may be wrong !!
* the buffering is done wrongly. For instance packets can't be replicated across subflows
* if you disable Nagle algorithm, then every packet embeds an ACK packet (m_connected).
* reenable commented code in Meta::NewAck
* MpTcpSubflow::SendEmptyPacket should parse the flags and append correct option just in case (for SYN for instance)


buffering system:
* m_txBuffer.HeadSequence should not serve as head of buffer since data may stay in buffer depending on mappings
* right now it does not allow for NR-sack !!

List of tests:
* Subflow management
	* ADDADDR/REMADDR tests. Should not be able to add same ADDRID with different IPs for instance (matt)
* In case remote host is not MPTCP compliant
	* We can't add subflows
	* MPTCP CC falls back to legacy TCP (will need some work on upstream side)
* Tokens stay the same along the connection


Generic:
* rename GetMeta() into Meta() ?
* rename isn into ISS as in TCP RFC
* dans core/model/test.cc, log warn message when fullness not accepted
* http://www.nsnam.org/doxygen/group__makeboundcallback.html#ga1725d6362e6065faa0709f7c93f8d770
* provide in meta a list of pending options that can be consumed by subflow
* Note that new subflows MUST NOT be established (using the process documented in Section 3.2) until a Digital Signature Standard (DSS) option has been successfully received across th
* Unmultiplex attribute MPTCP connection according to token
* IPv6 support
* add the possibility of setting priorities, ie the ability for a subflow to act as backup. Also take into account at scheduling level
* implement callback support : need to change ns3 ? (matt)
* let RTO be chosen by meta
* crypto materials checks
* I would remove ns3::Ipv4L3Protocol::GetAddress and replace it with calls like GetInterface().GetAddress .
* on MP_join store the addresses Id
* remove the files for mptcpsocketfactory, it's not needed: we cna use a tcpsocketfacotry
* test what happens when we remove the master socket while the connection keeps going. It should provoke problems since endpoint is not allocated anymore
* Possibility for applications to provie their fine grain tuning
* During 3WHS, we send 2 acks in a row, one with a wrong seq nb
* delayed data acks ? (is it worth in mptcp ?) anyhow should be disabled by default
* in TcpL4Protocol, before dispatching based on the token, we should check if the destination ip also exists on the device with the correct token: it should prevent some collisions

Requests for ns3;
* what happens if I bind several times ?
* add ssthreshold tracing (maybe fast recovery too)
* SetInitialCWnd as an attribute ?
* Add member RemoteWindow in TcpSocketBase
* when tracing a source that does not exist, ns3 should crash or log 
* the CloseAndNotify member name is badly chosen since it does not close the socket but signal a closed state
* add an IsConnected member to TcpSocketBase ?
* TcpSocketBase should have all members virtual. MpTcpSubflow::CancelAllTimers should call its parent's but it is not virtual
* same for DoConnect
* PoinToPointHelper should be able to Install channel between 2 netDevices ?
* the metasocket should be notified by new IPs Node::RegisterDeviceAdditionListener. Should add listeners to IP interfaces up
* comment some members of TCP socketBase
use "/NodeList/[i]/DeviceList/[i]" ?
* add a LossEstimator to Tcp ?
* In functions SendEmptyPacket etc... allow to pass an option reader,option adder
* Create buffer with 64bit sequence numbers
* move RTO management away from RTT estimator (m_rto) with everything in it: setminrto/setmaxrto
* private function to set variables that are plotted. This way can't forget about updating their values
* TcpTxBuffer should be templated to work with SequenceNumber64 too
* In X::GetTypeId(), SetParent<X> makes runner hangs
* need to define each component with a new name ? best way would be to allow REGEX on test name
* In TcpSocketBase::CompleteFork, should ASSERT that addressTo and addressFrom are of the same kind
* TcpSocketBase::NewAck remove the last SendPendingData
* should be easier to use the helpers (for instance to assign an IP, or trace pcap files)
* TcpRxBuffer::IncNextRxSequence sounds like a bad idea; may break some things
* propose a safer TcpState machine 
* Add a TcpRxBuffer::HeadSeqNb() const function
* remove useless dependancy between TcpHeader and TcpRxBuffer::Add .  
* Buffer::CheckNoZero can be simplified
* should be able to bind to a specific worth via an attribute 



Thoughts on upstreaming
========
Some aspects of the implementation would need to be reworked:
- MpTcpSocketBase should not inherit from TcpSocketBase, there is little in common from the API point of view
- ns3 TcpRxBuffer/TcpTxBuffer should be redone to be able to share buffer space
- MpTcpSubflow should be derived for each MPTCP flavor (uncoupled/olia/lia). Current design was chosen because it shortened dev time.
