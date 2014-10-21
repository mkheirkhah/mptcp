#!/usr/bin/env python3
###########################################################
# author: Matthieu coudron , matthieu.coudron@lip6.fr
# this script requires mptcptrace to be installed
# see https://bitbucket.org/bhesmans/mptcptrace
#
# the aim of this script is to plot window/acks
# at both the MPTCP connection and the subflow level
# (for now 1 MPTCP communication => 1 subflow)
#
# csv module doc: https://docs.python.org/3/library/csv.html

import argparse
import csv
import os
import shutil

### CONFIG
#########################
plotsDir = "plots"
subflowsList = "connection_0.csv"



# first erase previous data
shutil.rmtree(plotsDir)
os.mkdir(plotsDir)
#os.chdir(plotsDir)



# all the args sys.argv[1:]
# for now let's assume it is run by hand
#os.system("mptcptrace ")

# find all connections in that (ideally enabled via -l)
with open(subflowsList) as csvfile:
	#, quotechar='|'
	subflowReader = csv.reader(csvfile, delimiter=',')
	for subflow in subflowReader:
		print(subflow)