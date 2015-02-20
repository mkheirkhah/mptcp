###
###  Plot real and estimated deltas 
######################################
load 'common.plot'

# set output sprintf("%s_%s_tx.png", node, prefix)

x_axis="Time"

# Left/Right/Top/Bottom
# set offset graph 0.0, graph 0.0, graph 0.35, graph 0.1
set title sprintf("%s %s: Highest Tx vs NextTx", node, prefix)


# if monomode
# if (nb_of_subflows < 0) {
# 	print("Print in monomode")
# 	plot  \
# 	sprintf("%s/%sTxNext.csv", node, prefix)  using x_axis:"newNextTxSequence" with linespoints pointtype 3 title "Tx Next seq to send in order", \
# 	sprintf("%s/%sTxUnack.csv", node, prefix)  using x_axis:"newUnackSequence" with linespoints pointtype 2 title "Tx First unack seq sf " 

# }
# else {

plot  \
	for [id=1:nb_of_subflows] filename("TxNext.csv", id) using x_axis:"newNextTxSequence" with linespoints pointtype 3 title set_title("Tx NextSeq ",id), \
	for [id=1:nb_of_subflows] filename("TxUnack.csv", id) using x_axis:"newUnackSequence" with linespoints pointtype 2 title set_title("Tx First unack seq",id)  
# sprintf("%s/%sTxHighest.csv", node, prefix) using x_axis:"newHighestSequence" with linespoints pointtype 1 title "Max seq sent ever"
