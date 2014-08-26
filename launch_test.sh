WITH_GDB=0
SUITE="mptcp-tcp"

NS_LOG="MpTcpTestSuite=*|prefix_func:Socket=*:MpTcpSocketBase:*=error|warn" 
export NS_LOG
if [ WITH_GDB ]; then
	#COMMAND=
	echo 'gdb'
else
	echo 'Without gdb'
fi

./waf --run test-runner --command-template="gdb --args %s --suite=$SUITE"
