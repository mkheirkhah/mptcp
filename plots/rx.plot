###
###  Plot real and estimated deltas 
######################################
load 'common.plot'

# set output sprintf("%s_%s_tx.png", node, prefix)

x_axis="Time"

# Left/Right/Top/Bottom
# set offset graph 0.0, graph 0.0, graph 0.35, graph 0.1
set title sprintf("%s %s: ", node, prefix)

# TODO pour avoir le out of order, should do one minus, the other
# I may use csvfix join to do that

# TODO move it to common

# if monomode

plot \
	for [id=1:nb_of_subflows] filename("RxAvailable.csv", id)  using x_axis:"newRxAvailable" with linespoints pointtype 3 title set_title("RxAvailable (no out of order)",id), \
	for [id=1:nb_of_subflows] filename("RxNext.csv", id) using x_axis:"newRxNext" with linespoints pointtype 1 title set_title("RxNext ",id), \
	for [id=1:nb_of_subflows] filename("RxTotal.csv", id) using x_axis:"newRxTotal" with linespoints pointtype 2 title set_title("RxTotal (out of order included)", id)
# }
# else {
	
# 	plot \
# 		sprintf("%s/%sRxAvailable.csv", node, prefix)  using x_axis:"newRxAvailable" with linespoints pointtype 3 title "RxAvailable (custom, no out of order)", \
# 		sprintf("%s/%sRxNext.csv", node, prefix) using x_axis:"newRxNext" with linespoints pointtype 1 title "RxNext (official)", \
# 		sprintf("%s/%sRxTotal.csv", node, prefix) using x_axis:"newRxTotal" with linespoints pointtype 2 title "RxTotal (custom, out of order included)"
# }