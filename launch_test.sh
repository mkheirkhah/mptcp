WITH_GDB=1
SUITE="mptcp-tcp"
#SUITE="mptcp-option"
NS_LOG="Socket:TcpSocketBase:MpTcpSocketBase:MpTcpSubflow:*=error|warn|prefix_all" 
NS_LOG="$NS_LOG:MpTcpSchedulerRoundRobin"
NS_LOG="$NS_LOG:TcpTestCase"
NS_LOG="$NS_LOG:TcpL4Protocol"
#NS_LOG="$NS_LOG:MpTcpTestSuite=*|prefix_func:Socket=*"

export NS_LOG
printenv|grep NS_LOG
echo "Exported:\n$NS_LOG"

if [ $WITH_GDB -gt 0 ]; then
	#COMMAND=
	echo 'gdb'
	read -r  command <<-'EOF'
		./waf --run test-runner --command-template="gdb --args %s --suite=$SUITE"
		EOF
else
	echo 'Without gdb'
	read -r  command <<-EOF
		./waf --run "test-runner --suite=$SUITE"
		EOF

fi

echo "Command:\n$command"


eval $command

