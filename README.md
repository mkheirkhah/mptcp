README
======


To run the test suite with logging messages:
NS_LOG="MpTcpTestSuite=*|prefix_func:Socket=*:*=error|warn|logic" ./waf --run "test-runner --suite=mptcp"or (more complete)
NS_LOG="MpTcpTestSuite=*|prefix_func:Socket=*:MpTcpSocketBase:*=error|warn|logic" ./waf --run "test-runner --suite=mptcp"

In case you want to run it with gdb:
NS_LOG="MpTcpTestSuite=*|prefix_func:Socket=*:MpTcpSocketBase:*=error|warn|logic" ./waf --command-template="gdb %s" --run "test-runner"
