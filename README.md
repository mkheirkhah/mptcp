README
======

This code is yet another attempt at upstreaming MPTCP (Multipath TCP). It is based on ns3.19.


How to launch the MPTCP testsuite ?
======
To run the test suite with logging messages:
NS_LOG="MpTcpTestSuite=*|prefix_func:Socket=*:*=error|warn" ./waf --run "test-runner --suite=mptcp"or (more complete)
NS_LOG="MpTcpTestSuite=*|prefix_func:Socket=*:MpTcpSocketBase:*=error|warn" ./waf --run "test-runner --suite=mptcp"

In case you want to run it with gdb:
NS_LOG="MpTcpTestSuite=*|prefix_func:Socket=*:MpTcpSocketBase:*=error|warn" ./waf --command-template="gdb %s" --run "test-runner"

How to configure waf for prototyping
======
Few interesting flags
-Wno-reorder


Features
======

Limitations
======
* TCP options implementation is temporary and will be replaced by the Socis student implementation. So for now there is no limit to the number of options you can add. You cannot specify any port number in an ADD_ADDR
* does not work with IPv6 addresses
* CancelAllTimers() of TcpSocketBase is not virtual
