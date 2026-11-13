/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef VPPSTATS_H
#define VPPSTATS_H

#include <stdint.h>

struct ap_session;
struct rtnl_link_stats64;

struct vppstats_counts {
	uint64_t rx_packets, rx_bytes;
	uint64_t tx_packets, tx_bytes;
};

/*
 * Per-session state, owned by the vpphook_private_data_t of the ap_session. A
 * VPP sw_if_index is reused after a session is deleted and says nothing about
 * which session or which VPP instance it belongs to, so the identity of the
 * counters is kept here, next to them.
 */
struct vppstats_session {
	uint8_t valid;		/* the session was created by the hook, inst_gen is set */
	uint8_t frozen;		/* final sample, the interface is gone (or about to be) */
	uint32_t inst_gen;	/* VPP instance generation the session was created in */
	struct vppstats_counts raw_last;	/* raw values of the previous successful read */
	struct vppstats_counts total;		/* what is reported, also the frozen one, it never goes down */
};

/*
 * ap_session_hooks_t::read_stats, counters come from the VPP stats segment.
 * 0 - OK, -EAGAIN - stats temporarily unavailable (session is not lost),
 * other - the session counters are gone (VPP instance changed or lost)
 */
int vppstats_read_stats(struct ap_session *ses, struct rtnl_link_stats64 *stats);

/* the VPP interface of the session was just created, VPP counts it from zero */
void vppstats_session_created(struct ap_session *ses);

/* take the final sample and freeze it, call before the VPP interface is deleted */
void vppstats_session_freeze(struct ap_session *ses);

/* drop the stats segment connection */
void vppstats_close(void);

#endif /* VPPSTATS_H */
