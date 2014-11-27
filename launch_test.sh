WITH_GDB=1
SUITE="mptcp-tcp"
#SUITE="mptcp-option"
#SUITE="mptcp-mapping"
NS_LOG="TcpSocketBase"
NS_LOG="*=error|warn|prefix_node|prefix_func" 
NS_LOG="$NS_LOG:MpTcpSchedulerRoundRobin"
NS_LOG="$NS_LOG:Socket"
NS_LOG="$NS_LOG:MpTcpSubflow=*:MpTcpSocketBase=*"
NS_LOG="$NS_LOG:TcpTestSuite=*"
NS_LOG="$NS_LOG:TcpRxBuffer:TcpTxBuffer"
NS_LOG="$NS_LOG:MpTcpMapping=*"
NS_LOG="$NS_LOG:TcpHeader=*"
#NS_LOG="$NS_LOG:TcpOptionMpTcp=*"
#NS_LOG="$NS_LOG:MpTcpOptionsTestSuite=*"
#NS_LOG="$NS_LOG:TcpL4Protocol"
#NS_LOG="$NS_LOG:TraceHelper:PointToPointHelper"
#OUTPUT_FILENAME="xp.txt"
#NS_LOG="$NS_LOG:MpTcpTestSuite=*|prefix_func:Socket=*"

export NS_LOG
printenv|grep NS_LOG

# to clear screen
#clear

# --out only concerns the results of the test, not the actual stdout
if [ ! -z $OUTPUT_FILENAME ]; then
	OUT=" --out=${OUTPUT_FILENAME}"
fi

#OUT=" --out=test_results.txt"

TOFILE=""
TOFILE=" > xp.txt 2>&1"

VERBOSE="--verbose"
#VERBOSE=""

if [ $WITH_GDB -gt 0 ]; then
	#COMMAND=
	echo 'gdb'

	# http://tldp.org/LDP/abs/html/here-docs.html
	# in <<- , the '-' allows to ignore the prepended spaces
	# the '
#	echo "run --suite=$SUITE $OUT $TOFILE" > run.test
	read -r  command <<-EOF
		./waf --run test-runner --command-template="gdb -ex 'run --suite=$SUITE $VERBOSE $OUT $TOFILE' --args %s " 
		EOF

	#read -r command <<-EOF
		#gdb -ex run --args /home/teto/ns3/build/utils/ns3.19-test-runner-debug --suite=$SUITE $OUT $TOFILE
	#EOF
else
	echo 'Without gdb'
	# you can add --out to redirect output to afile instead of standard output
	#--verbose 
	read -r  command <<-EOF
		./waf --run "test-runner --suite=$SUITE $OUT $VERBOSE" $TOFILE
		EOF

fi

echo "Executed Command:\n$command"


eval $command

echo "Exported:\n$NS_LOG"
echo "Executed Command:\n$command"


