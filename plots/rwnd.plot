###
###  Plot real and estimated deltas 
######################################
load 'common.plot'

# set output sprintf("%s_cwnd.png", prefix)

x_axis="Time"

# Left/Right/Top/Bottom
set offset graph 0.0, graph 0.0, graph 0.35, graph 0.1

# those 2 windows 
plot  \
	sprintf("%s/meta_rwnd.csv", node)  using x_axis:"newRwnd" with linespoints pointtype 3 title "Meta Rwnd", \
	sprintf("%s/subflow1_rwnd.csv", node) using x_axis:"newRwnd" with linespoints pointtype 1 title "Subflow 1 Rwnd"
