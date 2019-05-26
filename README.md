# Multipath-TCP in ns-3
We have developed a model for Multipath-TCP (MPTCP) in ns-3, which
conforms to RFC-6824 and closely follows the MPTCP Linux kernel design.

A brief description of our model can be found in our recent short
paper, which was presented at the WNS3-2014 workshop, with the
following link: http://arxiv.org/abs/1510.07721

Our implementation is atop ns3.19 and supports several path management
techniques (e.g. FullMesh and NdiffPorts) and congestion control
algorithms such as Linked Increases, Scalable TCP, Uncoupled TCP and
Fully Coupled.

Our recent works on multipath TCP that have been built on top of this
code are as follows: 
* [MMPTCP](https://ieeexplore.ieee.org/abstract/document/7524530)
  (IEEE INFOCOM 2016) - </b>Best in Session Presentation Award</b>
* [AMP](https://ieeexplore.ieee.org/document/8816848) (IFIP Networking 2019) -
  </b>Best Paper Candidate</b>

# Installations
We have tested this code on Mac (with llvm-gcc42 and python 2.7.3-11)
and several Linux distributions (e.g. Red Hat with gcc4.4.7 or
Ubuntu16.4 with gcc5.4.0).

1. Clone the MPTCP's repository

``` 
git clone https://github.com/mkheirkhah/mptcp.git
```

2. Configure and build 

``` 
CXXFLAGS="-Wall" ./waf configure build 
```

3. Run a simulation

``` 
./waf --run "mptcp"
```

# Simulations

A simple simulation script is available [here](./scratch/).

# Contact

```
Morteza Kheirkhah, University College London (UCL), m.kheirkhah@ucl.ac.uk
```

# How to reference this source code?

If you use this source code in part or entirely, please refer to it
with the following bibtex:

```
@article{kheirkhah2015multipath,
  author  = {Kheirkhah, Morteza and Wakeman, Ian and Parisis, George},
  title   = {{Multipath-TCP in ns-3}},
  journal = {CoRR},
  year    = {2015},
  url     = {http://arxiv.org/abs/1510.07721},
  archivePrefix = {arXiv},
}
```


