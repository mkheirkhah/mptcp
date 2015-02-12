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
	sprintf("%s/subflow1_ssThresh.csv", node) using x_axis:"newSSThresh" with linespoints pointtype 1 title "Subflow 1 SS"
