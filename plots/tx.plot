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
	sprintf("%s/%sTxNext.csv", node, prefix)  using x_axis:"newNextTxSequence" with linespoints pointtype 3 title "Tx Next seq to send in order", \
	sprintf("%s/%sTxUnack.csv", node, prefix)  using x_axis:"newUnackSequence" with linespoints pointtype 2 title "Tx First unack seq", \
	sprintf("%s/%sTxHighest.csv", node, prefix) using x_axis:"newHighestSequence" with linespoints pointtype 1 title "Max seq sent ever"
