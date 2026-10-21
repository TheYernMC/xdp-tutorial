/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "common_kern_user.h" /* defines: struct datarec; */

/* Lesson#1: See how a map is defined.
 * - Here an array with XDP_ACTION_MAX (max_)entries are created.
 * - The idea is to keep stats per (enum) xdp_action
 */
/*
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct datarec);
	__uint(max_entries, XDP_ACTION_MAX);
} xdp_stats_map SEC(".maps");
*/

/* Assignment#3: Per-CPU map, each CPU has its own copy of the values,
 * so no atomic operation is needed. Userspace sums the values of all CPUs.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct datarec);
	__uint(max_entries, XDP_ACTION_MAX);
} xdp_stats_map SEC(".maps");

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

SEC("xdp")
int  xdp_stats1_func(struct xdp_md *ctx)
{
	// void *data_end = (void *)(long)ctx->data_end;
	// void *data     = (void *)(long)ctx->data;
	struct datarec *rec;
	__u32 key = XDP_PASS; /* XDP_PASS = 2 */

	/* Lookup in kernel BPF-side return pointer to actual data record */
	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
	/* BPF kernel-side verifier will reject program if the NULL pointer
	 * check isn't performed here. Even-though this is a static array where
	 * we know key lookup XDP_PASS always will succeed.
	 */
	if (!rec)
		return XDP_ABORTED;

	/* Multiple CPUs can access data record. Thus, the accounting needs to
	 * use an atomic operation.
	 */
	lock_xadd(&rec->rx_packets, 1);
	
	/* Assignment#1: Add byte counters
	 * - Hint look at struct xdp_md *ctx (copied below)
	 */
	void *data_end 	= (void *)(long)ctx->data_end;
	void *data_init = (void *)(long)ctx->data;
	__u64 bytes		= data_end - data_init;

	lock_xadd(&rec->rx_bytes, bytes);
	
	/*
	 * Assignment#3: Avoid the atomic operation
	 * - Hint there is a map type named BPF_MAP_TYPE_PERCPU_ARRAY
	 */

	return XDP_PASS;
}

/*
 * Assignment 3
 */

SEC("xdp")
int  xdp_stats1_percpu_func(struct xdp_md *ctx)
{
	struct datarec *rec;
	__u32 key = XDP_PASS; /* XDP_PASS = 2 */

	/* Lookup in kernel BPF-side return pointer to this CPU's data record */
	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (!rec)
		return XDP_ABORTED;

	/* With BPF_MAP_TYPE_PERCPU_ARRAY each CPU updates its own copy of
	 * the record, so a plain (non-atomic) add is enough.
	 */
	rec->rx_packets++;

	void *data_end 	= (void *)(long)ctx->data_end;
	void *data_init = (void *)(long)ctx->data;
	__u64 bytes		= data_end - data_init;

	rec->rx_bytes += bytes;

	return XDP_PASS;
}

/*
 * Assignment 2
 */

int  xdp_stats_record_action(struct xdp_md *ctx, int action)
{

	struct datarec *rec;
	__u32 key = action;

	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
	/* BPF kernel-side verifier will reject program if the NULL pointer
	 * check isn't performed here. Even-though this is a static array where
	 * we know key lookup XDP_PASS always will succeed.
	 */
	if (!rec)
		return XDP_ABORTED;

	/* Multiple CPUs can access data record. Thus, the accounting needs to
	 * use an atomic operation.
	 */
	lock_xadd(&rec->rx_packets, 1);
	
	/* Assignment#1: Add byte counters
	 * - Hint look at struct xdp_md *ctx (copied below)
	 */
	void *data_end 	= (void *)(long)ctx->data_end;
	void *data_init = (void *)(long)ctx->data;
	__u64 bytes		= data_end - data_init;

	lock_xadd(&rec->rx_bytes, bytes);
	
	/*
	 * Assignment#3: Avoid the atomic operation
	 * - Hint there is a map type named BPF_MAP_TYPE_PERCPU_ARRAY
	 */

	return action;
}

SEC("xdp")
int xdp_mix_func(struct xdp_md *ctx)
{
	__u32 action = (bpf_get_prandom_u32() & 1) ? XDP_PASS : XDP_DROP;
	return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";

/* Copied from: $KERNEL/include/uapi/linux/bpf.h
 *
 * User return codes for XDP prog type.
 * A valid XDP program must return one of these defined values. All other
 * return codes are reserved for future use. Unknown return codes will
 * result in packet drops and a warning via bpf_warn_invalid_xdp_action().
 *
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};

 * user accessible metadata for XDP packet hook
 * new fields must be added to the end of this structure
 *
struct xdp_md {
	// (Note: type __u32 is NOT the real-type)
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	// Below access go through struct xdp_rxq_info
	__u32 ingress_ifindex; // rxq->dev->ifindex
	__u32 rx_queue_index;  // rxq->queue_index
};
*/
