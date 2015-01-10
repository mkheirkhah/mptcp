import os
import argparse


available_suites = [
    "mptcp-tcp",
    "mptcp-option",
    "mptcp-mapping"
]

parser = argparse.ArgumentParser(help="Helper to debug mptcp")

parser.add_argument("suite", action="store_false", help="Launch gdb")
parser.add_argument("--debug", '-d', action="store_false", help="Launch gdb")
parser.add_argument("--out", "-o", nargs=1, help="redirect ns3 results output to a file")
parser.add_argument("--verbose", "-v", default="", help="to enable more output")
parser.add_argument("--graph", "-g", action="store_true", help="Convert pcap to sqlite db and then plot")

args = parser.parse_args()

if args.debug:
    cmd = "./waf --run test-runner --command-template=\"gdb -ex 'run --suite={suite} {verbose} {out} {tofile}' --args %s \" "
else:
    cmd = "./waf --run \"test-runner --suite={suite} {verbose} {out}\" {tofile}"


tofile = " > xp.txt 2>&1"

cmd = cmd.format(
    suite=args.suite,
    verbose=args.verbose,
    out=args.out,
    tofile=tofile,
)

# WITH_GDB=0
NS_LOG = "TcpSocketBase"
NS_LOG.append("*=error|warn|prefix_node|prefix_func")
NS_LOG.append(":MpTcpSchedulerRoundRobin")
NS_LOG.append(":Socket")
NS_LOG.append(":MpTcpSubflow=*:MpTcpSocketBase=*")
NS_LOG.append(":TcpTestSuite=*")
NS_LOG.append(":TcpRxBuffer:TcpTxBuffer")
NS_LOG.append(":MpTcpMapping=*")
NS_LOG.append(":TcpHeader=*")
#NS_LOG="$NS_LOG:TcpOptionMpTcp=*"
#NS_LOG="$NS_LOG:MpTcpOptionsTestSuite=*"
#NS_LOG="$NS_LOG:TcpL4Protocol"
#NS_LOG="$NS_LOG:TraceHelper:PointToPointHelper"
#OUTPUT_FILENAME="xp.txt"
#NS_LOG="$NS_LOG:MpTcpTestSuite=*|prefix_func:Socket=*"

os.environ['NS_LOG'] = NS_LOG


print("Executed Command:\n%s" % cmd)


os.system(cmd)

print("Exported:\n%s" % NS_LOG)
print("Executed Command:\n%s" % cmd)

if args.graph:
    # 
    os.system("mptcpexporter pcap2sql test-0-1.pcap")
    os.system("mptcpgraph ")
