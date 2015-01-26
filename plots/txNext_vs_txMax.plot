###
###  Plot real and estimated deltas 
######################################
load 'common.plot'

set output "tx.png"

#sprintf("Real Forward OWD0 %d",$4)
# "::2" to start at the 2nd line (http://babilonline.blogspot.fr/2010/06/gnuplot-skipping-header-line-from-input.html)

x_axis="time"
# TODO: corriger le calcul ici
# removed the "every ::2" because of columns
# $ <=> column()
# http://stackoverflow.com/questions/19003717/gnuplot-using-a-string-variable-to-define-columns

# Left/Right/Top/Bottom
set offset graph 0.0, graph 0.0, graph 0.35, graph 0.1

# TODO la je ne peux pas faire ca c faux :/
plot  \
	prefix+"Tx.csv"  using x_axis:"newTx" with linespoints pointtype 3 title "TxNext", \
	prefix+"highest.csv" using x_axis:"newHighestSequence" with linespoints pointtype 1 title "TxMax"
	# "" using x_axis:"estimatedForwardDelta" with linespoints pointtype 6 title "Estimated forward difference in OWD", \
	# "" using x_axis:"EstimatedReverseDelta" with linespoints pointtype 2 title "Estimated reverse difference in OWD"

#with lines