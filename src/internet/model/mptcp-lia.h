#ifndef MPTCP_CC_LIA_H
#define MPTCP_CC_LIA_H

//#include"ns3/mp-tcp-cc.h"
//#include"ns3/mp-tcp-subflow.h"
#include"ns3/mp-tcp-socket-base.h"
//#include"ns3/callback.h"

namespace ns3
{


/**
This is the linux struct.  We may try to get sthg close to this
http://www.nsnam.org/wiki/New_TCP_Socket_Architecture#Pluggable_Congestion_Control_in_Linux_TCP
static struct tcp_congestion_ops mptcp_olia = {
	.init		= mptcp_olia_init,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= mptcp_olia_cong_avoid,
	.set_state	= mptcp_olia_set_state,
	.min_cwnd	= tcp_reno_min_cwnd,
};

* \ingroup mptcp
*/
class MpTcpLia : public MpTcpSocketBase
{

public:
  static TypeId GetTypeId (void);

  MpTcpLia();
  MpTcpLia(const MpTcpLia& sock);
  virtual ~MpTcpLia();

  virtual uint32_t
  GetSSThresh(void) const;

  virtual uint32_t
  GetInitialCwnd(void) const;


  virtual Ptr<MpTcpSocketBase> ForkAsMeta(void);
//  virtual Ptr<TcpSocketBase> Fork(void);
  // transform into a callback ?
  // Callback<Ptr<MpTcpSubflow>, Ptr<MpTcpSocketBase>, Ptr<MpTcpCongestionControl> >
  //Ptr<MpTcpSubflow>

  // Called by SendPendingData() to get a subflow based on round robin algorithm
//  virtual int GeneratePartition(Ptr<MpTcpSocketBase> metaSock);

//  virtual const char*
//  GetName(void) const {
//    return "OLIA";
//  };

//  SendPendingData()
};


}


#endif /* MPTCP_CC_LIA_H */
