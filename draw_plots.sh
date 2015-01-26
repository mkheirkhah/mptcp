#!/bin/sh
# TODO pass terminal and optionnaly output
# if []
# terminal="pdfcairo" 
terminal="png"
# node = name of the folder; either "server" or "source"
# TODO compare meta/subflows stuff 
prefix="server/meta_" 
# pdfcairo
gnuplot -e "prefix='$node'"  plots/txNext_vs_txMax.plot
# gnuplot -e "term='$terminal'" delta.plot
