#ifndef MPTCP_CC_H
#define MPTCP_CC_H


#include <stdint.h>
#include "ns3/object.h"
#include "ns3/mp-tcp-subflow.h"
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
class MpTcpCongestionControl : public Object
{

public:
  MpTcpCongestionControl( );
  virtual ~MpTcpCongestionControl() {}

  virtual uint32_t
  GetInitialSSThresh(void) const = 0;

  virtual uint32_t
  GetInitialCwnd(void) const = 0;

  /**
  \brief
  \return The name of the congestion control
  **/
  virtual const char*
  GetName(void) const = 0;


  virtual void
  OpenCWNDInCA(Ptr<MpTcpSubFlow> subflow, uint32_t ackedBytes) = 0;

protected:
//  m_totalCwnd ;
  // Put here for hte sake of simplicity
  // but should be moved to derived classes.
//  DataDistribAlgo_t m_distribAlgo; //!< Algorithm for Data Distribution
};


}


#endif /* MPTCP_CC_H */
