#ifndef MPTCP_CC_UNCOUPLED_H
#define MPTCP_CC_UNCOUPLED_H


#include <stdint.h>
#include "ns3/object.h"
//#include "ns3/mp-tcp-subflow.h"
#include"ns3/mp-tcp-socket-base.h"
//#include "ns3/mp-tcp-socket-base.h"


namespace ns3
{


/**
*/
#if 0
struct tcp_congestion_ops {
	struct list_head	list;
	unsigned long flags;

	/* initialize private data (optional) */
	void (*init)(struct sock *sk);
	/* cleanup private data  (optional) */
	void (*release)(struct sock *sk);

	/* return slow start threshold (required) */
	u32 (*ssthresh)(struct sock *sk);
	/* lower bound for congestion window (optional) */
	u32 (*min_cwnd)(const struct sock *sk);
	/* do new cwnd calculation (required) */
	void (*cong_avoid)(struct sock *sk, u32 ack, u32 acked, u32 in_flight);
	/* call before changing ca_state (optional) */
	void (*set_state)(struct sock *sk, u8 new_state);
	/* call when cwnd event occurs (optional) */
	void (*cwnd_event)(struct sock *sk, enum tcp_ca_event ev);
	/* new value of cwnd after loss (optional) */
	u32  (*undo_cwnd)(struct sock *sk);
	/* hook for packet ack accounting (optional) */
	void (*pkts_acked)(struct sock *sk, u32 num_acked, s32 rtt_us);
	/* get info for inet_diag (optional) */
	void (*get_info)(struct sock *sk, u32 ext, struct sk_buff *skb);

	char 		name[TCP_CA_NAME_MAX];
	struct module 	*owner;
};
#endif


//#include"ns3/mp-tcp-cc.h"
//#include"ns3/mp-tcp-subflow.h"

//#include"ns3/callback.h"



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
class MpTcpCCUncoupled : public MpTcpSocketBase
{

public:
  static TypeId GetTypeId (void);

  MpTcpCCUncoupled();
  MpTcpCCUncoupled(const MpTcpCCUncoupled& sock);
  virtual ~MpTcpCCUncoupled();

  /**
  TODO rename in Initial SSThreshold
  TODO remove
  Remove
  **/
  virtual uint32_t
  GetSSThresh(void) const;

  virtual uint32_t
  GetInitialCwnd(void) const;

  /**
  **/
//  virtual uint32_t OpenCWND(Ptr<MpTcpSubFlow> sf, uint32_t ackedBytes);
//  virtual uint32_t ReduceCWND(Ptr<MpTcpSubFlow> sf);

protected:
  virtual Ptr<MpTcpSocketBase> ForkAsMeta(void);
  virtual TypeId GetMpTcpSubflowTypeId();

//  virtual Ptr<TcpSocketBase> Fork(void);
  // transform into a callback ?
  // Callback<Ptr<MpTcpSubFlow>, Ptr<MpTcpSocketBase>, Ptr<MpTcpCongestionControl> >
  //Ptr<MpTcpSubFlow>

  // Called by SendPendingData() to get a subflow based on round robin algorithm
//  virtual int GeneratePartition(Ptr<MpTcpSocketBase> metaSock);

//  virtual const char*
//  GetName(void) const {
//    return "OLIA";
//  };

//  SendPendingData()
};


}

#endif
