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


array=( "server" "source" )
for node in "${array[@]}"
do
	# echo "NODE $node"
	# Tx
	gnuplot -e "node='$node';prefix='meta_';output='${node}_meta_tx'"  plots/tx.plot
	gnuplot -e "node='$node';prefix='subflow1_';output='${node}_subflow1_tx'"  plots/tx.plot

	# Rx
	gnuplot -e "node='$node';prefix='meta_';output='${node}_meta_rx'"  plots/rx.plot
	gnuplot -e "node='$node';prefix='subflow1_';output='${node}_subflow1_rx'"  plots/rx.plot

	# Cwin (does not care about the prefix)
	gnuplot -e "node='$node';prefix='subflow1_';output='${node}_cwnd'"  plots/cwnd.plot
	gnuplot -e "node='$node';prefix='subflow1_';output='${node}_rwnd'"  plots/rwnd.plot

	montage ${node}_meta_tx ${node}_subflow1_tx ${node}_meta_rx ${node}_subflow1_rx ${node}_cwnd ${node}_rwnd  -tile 2x3 -geometry +1+1 ${node}_recap.png
done

# gnuplot -e "node='server';prefix='meta_';output='server_meta_tx'"  plots/txNext_vs_txMax.plot
# gnuplot -e "node='server';prefix='subflow1_';output='server_subflow1_tx'"  plots/txNext_vs_txMax.plot


# gnuplot -e "node='source';prefix='meta_';output='source_meta_tx'"  plots/txNext_vs_txMax.plot
# gnuplot -e "node='source';prefix='subflow1_';output='source_subflow1_tx'"  plots/txNext_vs_txMax.plot
# gnuplot -e "term='$terminal'" delta.plot

# to do the montage, you need imagemagick
# -geometry +2+2

montage server_recap.png source_recap.png -tile 2x1 -geometry +1+1 all.png 

xdg-open all.png
