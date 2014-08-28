WITH_GDB=0
SUITE="mptcp-tcp"
#SUITE="mptcp-option"
NS_LOG="MpTcpSocketBase:MpTcpSubFlow:*=error|warn" 
NS_LOG="$NS_LOG:TcpTestCase"
#NS_LOG="$NS_LOG:MpTcpTestSuite=*|prefix_func:Socket=*"


echo "Exported:\n$NS_LOG"

if [ $WITH_GDB -gt 0 ]; then
	#COMMAND=
	echo 'gdb'
	read -r -d '' command <<-'EOF'
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

