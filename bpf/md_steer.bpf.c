// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
// Copyright (c) 2026 the low-latency-exchange authors.
//
// md_steer: XDP steering for the AF_XDP variant (07 §2.3; pattern of the kernel
// selftest progs/xdp_hw_metadata.c, R3a §1.4).
//
//  - ARP, IGMP, IP fragments, non-IPv4 and non-matching traffic: XDP_PASS (kernel).
//  - UDP whose destination port is in `md_ports` (market data, re-requests,
//    replication): redirected to the AF_XDP socket of this rx queue via `xsks`; an
//    empty slot falls back to XDP_PASS.
//  - TCP of a utcp connection (`utcp_flows`: exact 5-tuple, or `utcp_ports`: a local
//    listening port): redirected likewise, and XDP_DROPped on any queue without an
//    AF_XDP socket, so the kernel never sees the flow and never answers with RSTs.
//  - Before a redirect, a 16-byte struct md_meta goes into data_meta with the NIC RX
//    timestamp from bpf_xdp_metadata_rx_timestamp() (valid = 0 on -ENODATA, e.g.
//    mlx5 without rx_filter=ALL, or -EOPNOTSUPP when the driver lacks the kfunc).
//
// Two entry points share the maps: md_steer calls the RX-metadata kfunc and must be
// loaded device-bound (BPF_F_XDP_DEV_BOUND_ONLY + prog_ifindex); md_steer_nometa does
// not call it, for drivers without XDP RX metadata (virtio_net timestamps) or when the
// device-bound load is refused. The loader (src/net/xsk/steer.cpp) loads exactly one.
//
// License: kfunc calls need a GPL-compatible program (ADR-026).
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef ENODATA
#define ENODATA 61
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP 95
#endif

#define MD_META_MAGIC 0x4C4C4D44 /* "LLMD"; mirrors kRxMetaMagic in net/xsk/socket.h */

struct md_meta {
  __u64 rx_hw_ns;
  __u32 valid;
  __u32 magic;
};

/* utcp flow as seen on ingress (network byte order): remote -> local. */
struct utcp_flow_key {
  __u32 remote_ip;
  __u32 local_ip;
  __u16 remote_port;
  __u16 local_port;
};

enum md_stat {
  STAT_PASS = 0,         /* non-IPv4, ARP, IGMP, fragments, non-matching */
  STAT_REDIRECT_UDP = 1, /* md_ports hit (redirect attempted) */
  STAT_REDIRECT_TCP = 2, /* utcp flow hit on a queue with an AF_XDP socket */
  STAT_DROP_TCP = 3,     /* utcp flow on a queue without an AF_XDP socket */
  STAT_META_TS = 4,      /* metadata written with a valid timestamp */
  STAT_META_NODATA = 5,  /* metadata written, timestamp unavailable */
  STAT_META_FAIL = 6,    /* bpf_xdp_adjust_meta() failed: frame redirected without metadata */
  STAT_UDP_NO_XSK = 7,   /* md_ports hit but no socket on this queue: passed */
  STAT_MAX = 8,
};

struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __uint(max_entries, 64);
  __type(key, __u32);
  __type(value, __u32);
} xsks SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, __u16); /* UDP destination port, network order */
  __type(value, __u8);
} md_ports SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, struct utcp_flow_key);
  __type(value, __u8);
} utcp_flows SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16);
  __type(key, __u16); /* TCP local (destination) port, network order */
  __type(value, __u8);
} utcp_ports SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, STAT_MAX);
  __type(key, __u32);
  __type(value, __u64);
} md_stats SEC(".maps");

extern int bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx, __u64 *timestamp) __ksym;

static __always_inline void count(__u32 idx) {
  __u64 *v = bpf_map_lookup_elem(&md_stats, &idx);
  if (v)
    *v += 1;
}

enum verdict { V_PASS, V_UDP, V_TCP };

static __always_inline enum verdict classify(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > end || eth->h_proto != bpf_htons(ETH_P_IP))
    return V_PASS; /* ARP, IPv6, VLAN, ... */
  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > end || ip->ihl < 5)
    return V_PASS;
  if (ip->frag_off & bpf_htons(0x3fff))
    return V_PASS; /* fragments */
  void *l4 = (void *)ip + ip->ihl * 4;
  if (ip->protocol == IPPROTO_UDP) {
    struct udphdr *udp = l4;
    if ((void *)(udp + 1) > end)
      return V_PASS;
    __u16 dport = udp->dest;
    return bpf_map_lookup_elem(&md_ports, &dport) ? V_UDP : V_PASS;
  }
  if (ip->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = l4;
    if ((void *)(tcp + 1) > end)
      return V_PASS;
    struct utcp_flow_key k = {
        .remote_ip = ip->saddr, .local_ip = ip->daddr, .remote_port = tcp->source, .local_port = tcp->dest};
    if (bpf_map_lookup_elem(&utcp_flows, &k))
      return V_TCP;
    __u16 lport = tcp->dest;
    return bpf_map_lookup_elem(&utcp_ports, &lport) ? V_TCP : V_PASS;
  }
  return V_PASS; /* IGMP (2) and everything else */
}

static __always_inline void write_meta(struct xdp_md *ctx, int with_kfunc) {
  /* bpf_xdp_adjust_meta() invalidates every packet pointer: classify() is done. */
  if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct md_meta)) != 0) {
    count(STAT_META_FAIL);
    return;
  }
  struct md_meta *m = (void *)(long)ctx->data_meta;
  if ((void *)(m + 1) > (void *)(long)ctx->data)
    return;
  m->rx_hw_ns = 0;
  m->valid = 0;
  m->magic = MD_META_MAGIC;
  if (with_kfunc) {
    /* 0: timestamp; -ENODATA / -EOPNOTSUPP: none for this frame (valid stays 0). */
    if (bpf_xdp_metadata_rx_timestamp(ctx, &m->rx_hw_ns) == 0) {
      m->valid = 1;
      count(STAT_META_TS);
      return;
    }
    m->rx_hw_ns = 0;
  }
  count(STAT_META_NODATA);
}

static __always_inline int steer(struct xdp_md *ctx, int with_kfunc) {
  const enum verdict v = classify(ctx);
  if (v == V_PASS) {
    count(STAT_PASS);
    return XDP_PASS;
  }
  __u32 q = ctx->rx_queue_index;
  if (v == V_UDP) {
    if (!bpf_map_lookup_elem(&xsks, &q)) {
      count(STAT_UDP_NO_XSK);
      return XDP_PASS; /* no socket on this queue: the kernel gets it */
    }
    write_meta(ctx, with_kfunc);
    count(STAT_REDIRECT_UDP);
    return bpf_redirect_map(&xsks, q, XDP_PASS);
  }
  /* utcp flow: only an AF_XDP socket may see it, never the kernel stack. */
  if (!bpf_map_lookup_elem(&xsks, &q)) {
    count(STAT_DROP_TCP);
    return XDP_DROP;
  }
  write_meta(ctx, with_kfunc);
  count(STAT_REDIRECT_TCP);
  return bpf_redirect_map(&xsks, q, XDP_DROP);
}

SEC("xdp")
int md_steer(struct xdp_md *ctx) { return steer(ctx, 1); }

SEC("xdp")
int md_steer_nometa(struct xdp_md *ctx) { return steer(ctx, 0); }

char LICENSE[] SEC("license") = "Dual BSD/GPL";
