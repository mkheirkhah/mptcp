TODO list:

List of tests:
* Subflow management
	* ADDADDR/REMADDR tests. Should not be able to add same ADDRID with different IPs for instance (matt)
* remove dependancy on outer modules (matt)
* In case remote host is not MPTCP compliant
	* We can't add subflows
	* MPTCP CC falls back to legacy TCP (will need some work on upstream side)
* Tokens stay the same along the connection

Generic:
-IPv6 support
-should
-MpTcpSubflow::CancelAllTimers should call its parent's but it is not virtual
-same for DoConnect
-implement callback support : need to change ns3 ? (matt)
Morteza: the reason is mptcp subflows would be created in middle of run time, so no way to can hook them in configuration time. This partially being solved in MpTcpSubflow by calling to StartTracing() and then CwndTracer().I can recall there was bug in m_socket which prevent socket to fire call back at all :-)
