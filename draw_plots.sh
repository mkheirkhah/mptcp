#!/bin/bash
# TODO pass terminal and optionnaly output
# if []
# terminal="pdfcairo" 
terminal="png"

export GNUPLOT_LIB="plots"

# node = name of the folder; either "server" or "source"
# TODO compare meta/subflows stuff 
node="server" 
prefix="meta_" 


nb_of_subflows=$(ls -alt source/subflow*_cwnd.csv | wc -l)

echo "================="
echo "${nb_of_subflows} Found"
echo "================="


array=( "server" "source" )
for node in "${array[@]}"
do
	# echo "NODE $node"
	# Tx
	gnuplot -e "node='$node';prefix='meta_';output='${node}_meta_tx'"  plots/tx.plot
	gnuplot -e "node='$node';prefix='subflow';output='${node}_subflow_tx';nb_of_subflows='${nb_of_subflows}'"  plots/tx.plot

	# Rx
	gnuplot -e "node='$node';prefix='meta_';output='${node}_meta_rx'"  plots/rx.plot
	gnuplot -e "node='$node';prefix='subflow';output='${node}_subflow_rx';nb_of_subflows='${nb_of_subflows}'"  plots/rx.plot

	# Cwin/rwin (does not care about the prefix)
	# gnuplot -e "node='$node';prefix='subflow';output='${node}_cwnd';nb_of_subflows='${nb_of_subflows}'"  plots/cwnd.plot
	# gnuplot -e "node='$node';prefix='subflow';output='${node}_rwnd';nb_of_subflows='${nb_of_subflows}'"  plots/rwnd.plot

	# 
	# gnuplot -e "node='$node';prefix='subflow_';output='${node}_rwnd'"  plots/rwnd.plot
	
	montage ${node}_meta_tx ${node}_subflow_tx ${node}_meta_rx ${node}_subflow_rx ${node}_cwnd ${node}_rwnd  -tile 2x3 -geometry +1+1 ${node}_recap.png
done

# to do the montage, you need imagemagick
# -geometry +2+2


# montage server_recap.png source_recap.png -tile 2x1 -geometry +1+1 all.png 


cmd="xdg-open all.png"

echo $cmd

shift
if [ $# -gt 0 ]; then
	eval $cmd
fi