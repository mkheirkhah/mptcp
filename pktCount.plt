set terminal png
set output "pktCount.png"
set title "CC:Semi-Coupled  sF:1 C:100000Kbps  RTT:2Ms  D:10000Kb  dtQ(65)  MSS:536B"
set xlabel "Subflows"
set ylabel "Packets"
set xrange [0:4]
plot "-"  title " Subflow 0" with linespoints
0 18658
e
