/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Per-interface counters of VPP-terminated sessions. They do not exist in
 * the kernel, so they are read from the VPP stats segment instead of netlink.
 *
 * A VPP sw_if_index is reused as soon as a session is deleted, so it is not
 * an identity. The identity of the counters is the ap_session: its
 * vpphook_private_data_t owns the VPP state of the session, that is the
 * sw_if_index and the struct vppstats_session with
 *  - the VPP instance generation the session was created in
 *  - the raw counters of the previous read and the total derived from them,
 *    which never goes down, also over a counter clear
 *  - a final sample that is frozen before the interface is deleted
 * VPP zeroes the counters of an interface when it creates it, also when it
 * reuses an index, so the counters of a session start from what VPP reports and no
 * baseline is needed. The counters of one interface are read in place from
 * the shared segment, the directory is not listed and the counters of the
 * other interfaces are not copied.
 */

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <linux/if_link.h>

#include <vppinfra/vec.h>
#include <vpp-api/client/stat_client.h>

#include "triton.h"
#include "ap_session.h"
#include "log.h"

#include "vpphooks.h"
#include "vppstats.h"

#define VPPSTATS_SOCKET "/run/vpp/stats.sock"
/* VPP bumps the epoch whenever its directory changes, that is for every interface it creates:
 * a read that raced with it is repeated, a read takes microseconds */
#define VPPSTATS_READ_TRIES 10
/* the lookup of a directory entry is a listing, it fails while the directory changes */
#define VPPSTATS_RETRIES 3
#define VPPSTATS_RETRY_NSEC (2 * 1000 * 1000)
/* longest wait for VPP to finish updating the segment, the lock is held meanwhile */
#define VPPSTATS_TIMEOUT_NSEC (200ULL * 1000 * 1000)
/*
 * A restart of VPP is told by its stats socket: a new instance creates a new
 * one, so the file differs from the one the connection was made to. A busy
 * VPP is not a restarted VPP: while many sessions come up, the directory
 * changes all the time, dumps fail for a while and the heartbeat is late, so
 * those only count after a long time and only as a fallback for a frozen
 * mapping.
 * - heartbeat stalled for VPPSTATS_STALL_SEC: reconnect, the instance is gone
 * - not reachable for VPPSTATS_UNREACH_SEC: the instance is gone
 * Shorter than that the stats are only temporarily unavailable.
 */
#define VPPSTATS_STALL_SEC 60
#define VPPSTATS_UNREACH_SEC 60

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int connected;
/* bumped whenever the stats connection is dropped, sessions of an older one are lost */
static uint32_t inst_gen = 1;
static double last_hb;
static time_t last_hb_change;
static time_t unreach_since;
/* the stats socket the connection was made to, a different one is a new VPP */
static struct stat conn_sock;
static int conn_sock_valid;
/* the directory entries of /if/rx and /if/tx, looked up by name once per connection */
static int dir_valid;
static uint32_t dir_rx, dir_tx;

static time_t vppstats_now_sec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

/* the connection is dropped, nothing read through it before can be trusted */
static void vppstats_instance_lost(void)
{
	if (connected) {
		stat_segment_disconnect();
		connected = 0;
	}
	dir_valid = 0;
	unreach_since = 0;
	inst_gen++;
	log_warn("vpp: stats segment lost, sessions of the previous VPP instance are no longer accounted\n");
}

static int vppstats_connect(void)
{
	if (stat_segment_connect(VPPSTATS_SOCKET))
		return -1;

	/* stat_segment_connect() clears the client state, so set this after it */
	stat_segment_set_timeout(VPPSTATS_TIMEOUT_NSEC);
	connected = 1;
	dir_valid = 0;
	conn_sock_valid = !stat(VPPSTATS_SOCKET, &conn_sock);
	last_hb = 0;
	last_hb_change = vppstats_now_sec();
	return 0;
}

/* the stats socket is not the one the connection was made to: VPP was restarted */
static int vppstats_socket_replaced(void)
{
	struct stat st;

	if (!connected || !conn_sock_valid || stat(VPPSTATS_SOCKET, &st))
		return 0;
	return st.st_dev != conn_sock.st_dev || st.st_ino != conn_sock.st_ino ||
	       st.st_ctim.tv_sec != conn_sock.st_ctim.tv_sec ||
	       st.st_ctim.tv_nsec != conn_sock.st_ctim.tv_nsec;
}

/* directory index of the one entry that matches the pattern, -1 if it is not there or the listing failed */
static int vppstats_lookup_entry(const char *pattern, uint32_t *index)
{
	u8 **patterns = NULL;
	u32 *dir = NULL;
	int i, ret = -1;

	for (i = 0; i < VPPSTATS_RETRIES && !dir; i++) {
		struct timespec ts = { 0, VPPSTATS_RETRY_NSEC };

		if (i)
			nanosleep(&ts, NULL);

		vec_add1(patterns, (u8 *)pattern);
		dir = stat_segment_ls(patterns);
		vec_free(patterns);
	}

	if (dir && vec_len(dir) == 1) {
		*index = dir[0];
		ret = 0;
	}
	vec_free(dir);
	return ret;
}

static int vppstats_lookup_entries(void)
{
	if (vppstats_lookup_entry("^/if/rx$", &dir_rx) || vppstats_lookup_entry("^/if/tx$", &dir_tx))
		return -1;
	dir_valid = 1;
	return 0;
}

/*
 * Add the counters of one interface of a combined counter entry, over all
 * threads. 0 - OK, -EAGAIN - the index is in none of the vectors yet,
 * -ENOENT - the entry is not the one that was looked up
 */
static int vppstats_sum_entry(stat_client_main_t *sm, vlib_stats_entry_t *e, const char *name, uint32_t idx,
			      uint64_t *packets, uint64_t *bytes)
{
	vlib_counter_t **threads, *c;
	int t, seen = 0;

	if (strcmp(e->name, name) || e->type != STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED)
		return -ENOENT;

	threads = stat_segment_adjust(sm, e->data);
	if (!threads)
		return -ENOENT;

	*packets = *bytes = 0;
	for (t = 0; t < stat_segment_vec_len(threads); t++) {
		c = stat_segment_adjust(sm, threads[t]);
		if (!c || idx >= stat_segment_vec_len(c))
			continue;
		*packets += c[idx].packets;
		*bytes += c[idx].bytes;
		seen = 1;
	}

	return seen ? 0 : -EAGAIN;
}

/*
 * One read of rx and tx of an interface, valid only if the directory did not
 * change meanwhile (a changed epoch repeats the read).
 * 0 - OK, -EAGAIN - the interface is not in the counters yet, -ENOENT - the
 * entries are not where they were looked up, -EIO - no consistent read
 */
static int vppstats_read_once(uint32_t idx, struct vppstats_counts *raw)
{
	stat_client_main_t *sm = &stat_client_main;
	int i;

	for (i = 0; i < VPPSTATS_READ_TRIES; i++) {
		stat_segment_access_t sa;
		struct vppstats_counts c = { 0 };
		int ret = -ENOENT;

		if (stat_segment_access_start(&sa, sm))
			continue;

		if (sm->directory_vector && dir_rx < stat_segment_vec_len(sm->directory_vector) &&
		    dir_tx < stat_segment_vec_len(sm->directory_vector)) {
			ret = vppstats_sum_entry(sm, &sm->directory_vector[dir_rx], "/if/rx", idx, &c.rx_packets, &c.rx_bytes);
			if (!ret)
				ret = vppstats_sum_entry(sm, &sm->directory_vector[dir_tx], "/if/tx", idx, &c.tx_packets,
							 &c.tx_bytes);
		}

		if (!stat_segment_access_end(&sa, sm))
			continue;

		if (!ret)
			*raw = c;
		return ret;
	}

	return -EIO;
}

static int vppstats_segment_unreachable(void)
{
	time_t now = vppstats_now_sec();

	if (!unreach_since)
		unreach_since = now;
	if (now - unreach_since < VPPSTATS_UNREACH_SEC)
		return -EAGAIN;

	vppstats_instance_lost();
	return -ENODEV;
}

/*
 * Read the raw counters of one interface.
 * 0 - OK, -EAGAIN - temporarily unavailable, -ENODEV - instance lost
 */
static int vppstats_read_counters(uint32_t idx, struct vppstats_counts *raw)
{
	double hb;
	int ret;
	int relooked = 0;

again:
	/* a different stats socket is a restarted VPP, whatever its load */
	if (vppstats_socket_replaced())
		vppstats_instance_lost();

	if (!connected && vppstats_connect())
		return vppstats_segment_unreachable();

	if (!dir_valid && vppstats_lookup_entries())
		return vppstats_segment_unreachable();

	ret = vppstats_read_once(idx, raw);
	if (ret == -ENOENT && !relooked) {
		/* the directory was rebuilt, find the entries again */
		relooked = 1;
		dir_valid = 0;
		goto again;
	}
	if (ret == -ENOENT || ret == -EIO)
		return vppstats_segment_unreachable();
	unreach_since = 0;

	/* after a successful read, 0 means the epoch changed meanwhile, not a stall */
	hb = stat_segment_heartbeat();
	if (hb > 0) {
		if (hb != last_hb) {
			last_hb = hb;
			last_hb_change = vppstats_now_sec();
		} else if (vppstats_now_sec() - last_hb_change >= VPPSTATS_STALL_SEC) {
			vppstats_instance_lost();
			return -ENODEV;
		}
	}

	return ret;
}

static void vppstats_counts_to_stats(const struct vppstats_counts *c, struct rtnl_link_stats64 *stats)
{
	memset(stats, 0, sizeof(*stats));
	stats->rx_packets = c->rx_packets;
	stats->rx_bytes = c->rx_bytes;
	stats->tx_packets = c->tx_packets;
	stats->tx_bytes = c->tx_bytes;
}

/* read of the counters of one session */
static int vppstats_session_counters(struct vpphook_private_data_t *pd, struct vppstats_counts *raw)
{
	return vppstats_read_counters(pd->vpp_sw_if_index, raw);
}

/*
 * A VPP counter clear resets the raw values to zero. The total of the session
 * must not go down, so the part since the previous read is added and a raw
 * value below the previous one is taken as a clear: what it counts is what came
 * after the reset. Traffic between the last read and the clear is not counted.
 */
static void vppstats_session_update(struct vppstats_session *s, const struct vppstats_counts *raw)
{
#define VPPSTATS_ADD(field) \
	s->total.field += raw->field >= s->raw_last.field ? raw->field - s->raw_last.field : raw->field

	VPPSTATS_ADD(rx_packets);
	VPPSTATS_ADD(rx_bytes);
	VPPSTATS_ADD(tx_packets);
	VPPSTATS_ADD(tx_bytes);
#undef VPPSTATS_ADD

	s->raw_last = *raw;
}

void vppstats_session_created(struct ap_session *ses)
{
	struct vpphook_private_data_t *pd = vpphook_get_pd(ses);

	if (!pd)
		return;

	pthread_mutex_lock(&lock);
	/* a restarted VPP is told by its socket, so the session belongs to the instance that is there now */
	if (vppstats_socket_replaced())
		vppstats_instance_lost();
	/* a new session starts from zero, whatever the index had before */
	memset(&pd->stats, 0, sizeof(pd->stats));
	pd->stats.valid = 1;
	pd->stats.inst_gen = inst_gen;
	pthread_mutex_unlock(&lock);
}

int vppstats_read_stats(struct ap_session *ses, struct rtnl_link_stats64 *stats)
{
	struct vpphook_private_data_t *pd = vpphook_get_pd(ses);
	struct vppstats_session *s;
	struct vppstats_counts raw;
	int ret;

	if (!pd)
		return -1;
	s = &pd->stats;

	pthread_mutex_lock(&lock);

	/* the final sample stays after the interface is gone */
	if (s->frozen) {
		vppstats_counts_to_stats(&s->total, stats);
		ret = 0;
		goto out;
	}

	/*
	 * sw_if_index 0 is local0, a session interface is never 0. Besides, the session
	 * was not created by the hook, or its VPP instance or counters are gone.
	 */
	if (!pd->vpp_sw_if_index || !s->valid || s->inst_gen != inst_gen) {
		ret = -ENODEV;
		goto out;
	}

	ret = vppstats_session_counters(pd, &raw);
	if (ret)
		goto out;

	/* the read may have found a new VPP instance */
	if (s->inst_gen != inst_gen) {
		ret = -ENODEV;
		goto out;
	}

	vppstats_session_update(s, &raw);
	vppstats_counts_to_stats(&s->total, stats);
out:
	pthread_mutex_unlock(&lock);
	return ret;
}

void vppstats_session_freeze(struct ap_session *ses)
{
	struct vpphook_private_data_t *pd = vpphook_get_pd(ses);
	struct vppstats_session *s;
	struct vppstats_counts raw;

	if (!pd)
		return;
	s = &pd->stats;

	pthread_mutex_lock(&lock);

	if (s->frozen)
		goto out;

	/*
	 * A read now, so no traffic since the last one is missing. If it fails
	 * the last good value stays, which is also all there is when the
	 * instance is gone. From here on the VPP interface and its index must
	 * not be read for this session again.
	 */
	if (s->valid && s->inst_gen == inst_gen && pd->vpp_sw_if_index &&
	    !vppstats_session_counters(pd, &raw) && s->inst_gen == inst_gen)
		vppstats_session_update(s, &raw);

	s->frozen = 1;
out:
	pthread_mutex_unlock(&lock);
}

void vppstats_close(void)
{
	pthread_mutex_lock(&lock);
	dir_valid = 0;
	if (connected) {
		stat_segment_disconnect();
		connected = 0;
	}
	/* nothing read before can be matched with what a later connection shows */
	inst_gen++;
	pthread_mutex_unlock(&lock);
}
