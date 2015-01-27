###
###  Plot real and estimated deltas 
######################################
load 'common.plot'

# set output sprintf("%s_%s_tx.png", node, prefix)

x_axis="Time"

# Left/Right/Top/Bottom
# set offset graph 0.0, graph 0.0, graph 0.35, graph 0.1
set title sprintf("%s %s: Highest Tx vs NextTx", node, prefix)

plot  \
	sprintf("%s/%sTx.csv", node, prefix)  using x_axis:"newTx" with linespoints pointtype 3 title "TxNext", \
	sprintf("%s/%shighest.csv", node, prefix) using x_axis:"newHighestSequence" with linespoints pointtype 1 title "TxMax"
