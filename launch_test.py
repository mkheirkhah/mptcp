import os
import argparse
import subprocess

available_suites = [
    "tcp",
    "mptcp-tcp",
    "mptcp-tcp-multi",
    "mptcp-option",
    "mptcp-mapping"
]

# type=argparse.FileType('w'),
parser = argparse.ArgumentParser(description="Helper to debug mptcp")

parser.add_argument("suite", choices=available_suites, help="Launch gdb")
parser.add_argument("--debug", '-d', action="store_true", help="Launch gdb")
parser.add_argument("--out", "-o", default="", nargs='?', help="redirect ns3 results output to a file")
parser.add_argument("--verbose", "-v", default="", help="to enable more output")
parser.add_argument("--graph", "-g", action="store_true", help="Convert pcap to sqlite db and then plot")

args = parser.parse_args()

if args.debug:
    cmd = "./waf --run test-runner --command-template=\"gdb -ex 'run --suite={suite} {verbose} {tofile}' --args %s \" "
else:
    timeout = 200
    cmd = "./waf --run \"test-runner --suite={suite} --fullness={fullness} {verbose} \" {tofile}"


tofile = " > %s 2>&1" % args.out if args.out else ""
# tofile = " > xp.txt 2>&1"

cmd = cmd.format(
    suite=args.suite,
    verbose=args.verbose,
    # out=
    tofile=tofile,
    fullness="QUICK",
)

# WITH_GDB=0
NS_LOG = ""
# NS_LOG += "***"
# """
NS_LOG += "*=error|warn|prefix_node|prefix_func"
# NS_LOG += ":PointToPointNetDevice"
# NS_LOG += ":PointToPointChannel"
# NS_LOG += ":DropTailQueue"
NS_LOG += ":MpTcpMultiSuite"
NS_LOG += ":MpTcpTestSuite"
NS_LOG += ":TcpSocketBase"
NS_LOG += ":MpTcpSchedulerRoundRobin"
# NS_LOG += ":SimpleNetDevice"
# NS_LOG += ":ObjectBase=error|warn"
# NS_LOG += ":Socket"
# logic:error:warn
NS_LOG += ":MpTcpSubflow:MpTcpSocketBase"
NS_LOG += ":MpTcpSubflowUncoupled"
# NS_LOG += ":Config"
# NS_LOG += ":TypeId" # to look for AddTraceSource
NS_LOG += ":TcpTestSuite"
NS_LOG += ":TcpRxBuffer"
# NS_LOG += ":PcapFile"
NS_LOG += ":TcpTxBuffer"
# NS_LOG += ":MpTcpMapping=*"
# NS_LOG += ":TcpHeader=*"
# NS_LOG=":TcpOptionMpTcp=*"
# NS_LOG=":MpTcpOptionsTestSuite=*"
NS_LOG += ":TcpL4Protocol"
NS_LOG += ":Ipv4EndPoint:Ipv4EndPointDemux"
# NS_LOG += ":TraceHelper:PointToPointHelper"
# OUTPUT_FILENAME="xp.txt"
# NS_LOG=":MpTcpTestSuite=*|prefix_func:Socket=*"
# """

os.environ['NS_LOG'] = NS_LOG

# TODO catch
# ./waf --run "test-runner --suite=mptcp-tcp-multi --fullness=QUICK  "  > xp.txt 2>&1
# ^CTraceback (most recent call last):
#   File "/home/teto/ns3/launch_test.py", line 91, in <module>
#     ret = subprocess.call(cmd, shell=True, timeout=timeout if timeout else None)
#   File "/usr/lib/python3.4/subprocess.py", line 539, in call
#     return p.wait(timeout=timeout)
#   File "/usr/lib/python3.4/subprocess.py", line 1560, in wait
#     time.sleep(delay)
# KeyboardInterrupt

# provoked prompts in sublimetext, annoying
# os.system("rm source/*")
# os.system("rm server/*")

print("Executed Command:\n%s" % cmd)

# os.system(cmd)


# , timeout=timeout
try:
    ret = subprocess.call(cmd, shell=True, timeout=timeout if timeout else None)
except subprocess.TimeoutExpired:
    print("Timeout expired. try setting a longer timeout")

print("Exported:\n%s" % NS_LOG)
print("Executed Command:\n%s" % cmd)

if ret:
    print("ERROR: command returned error code %d" % (ret))
    exit(1)

if args.graph:
    # 
    os.system("mptcpexporter pcap2sql test-0-1.pcap")
    os.system("mptcpgraph ")

os.system("truncate --size=40000 %s" % (args.out,), shell=true)


for i in ['server', 'source']:
    print("Content of folder '%s':" % (i,))
    os.system("ls -l %s" % (i,))

# print("Content of folder 'server':")
# os.system("./draw_plots.sh")
