#ifndef __SOCK_H
#define __SOCK_H

#include "min_vmlinux.h"
#include "utils.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

#define AF_INET 2 /* Internet IP Protocol */
#define AF_INET6 10 /* IP version 6 */

struct nf_conn___old {
    struct net *ct_net;
};

struct net___old {
    unsigned int proc_inum;
};

struct sock_common___old {
    struct net *skc_net;
};

struct sock___old {
    struct sock_common___old __sk_common;
};
#define sk_net __sk_common.skc_net

static __always_inline __u32 get_netns_from_sock(struct sock* sk) {
    u32 net_ns_inum = 0;
    struct net *ns = NULL;
    if (bpf_core_field_exists(sk->sk_net.net) ||
        bpf_core_field_exists(((struct sock___old*)sk)->sk_net->ns)) {
        BPF_CORE_READ_INTO(&ns, sk, sk_net);
        BPF_CORE_READ_INTO(&net_ns_inum, ns, ns.inum);
    } else if (bpf_core_field_exists(((struct net___old*)ns)->proc_inum)) {
        BPF_CORE_READ_INTO(&ns, (struct sock___old*)sk, sk_net);
        BPF_CORE_READ_INTO(&net_ns_inum, (struct net___old*)ns, proc_inum);
    }
    return net_ns_inum;
}

typedef struct {
    /* Using the type unsigned __int128 generates an error in the ebpf verifier */
    __u64 saddr_h;
    __u64 saddr_l;
    __u16 sport;
    __u32 netns;
    __u32 pid;
    __u16 proto; //TCP (1) or UDP (0)
    __u16 version; //V4 (0) or V6 (1)
} conn_tuple_t;

#define GET_USER_MODE_PID(x) ((x) >> 32)

static __always_inline struct inet_sock *inet_sk(const struct sock *sk)
{
    return (struct inet_sock *)sk;
}

// source include/net/inet_sock.h
#define inet_daddr sk.__sk_common.skc_daddr
#define inet_rcv_saddr sk.__sk_common.skc_rcv_saddr
#define inet_dport sk.__sk_common.skc_dport
#define inet_num sk.__sk_common.skc_num
// source include/net/sock.h
#define sk_num __sk_common.skc_num
#define sk_dport __sk_common.skc_dport
#define sk_v6_rcv_saddr __sk_common.skc_v6_rcv_saddr
#define sk_v6_daddr __sk_common.skc_v6_daddr
#define sk_daddr __sk_common.skc_daddr
#define sk_rcv_saddr __sk_common.skc_rcv_saddr
#define sk_family __sk_common.skc_family

static __always_inline struct sock * socket_sk(struct socket *sock) {
    struct sock * sk = NULL;
    BPF_CORE_READ_INTO(&sk, sock, sk);
    return sk;
}

static __always_inline u16 read_sport(struct sock* skp) {
    // try skc_num, then inet_sport
    u16 sport = 0;
    BPF_CORE_READ_INTO(&sport, skp, sk_num);
    if (sport == 0) {
        BPF_CORE_READ_INTO(&sport, inet_sk(skp), inet_sport);
        sport = bpf_ntohs(sport);
    }
    return sport;
}

static __always_inline u32 read_saddr_v4(struct sock *skp) {
    u32 saddr = 0;
    BPF_CORE_READ_INTO(&saddr, skp, sk_rcv_saddr);
    if (saddr == 0) {
        BPF_CORE_READ_INTO(&saddr, inet_sk(skp), inet_saddr);
    }
    return saddr;
}

static __always_inline void read_in6_addr(u64 *addr_h, u64 *addr_l, const struct in6_addr *in6) {
    BPF_CORE_READ_INTO(addr_h, in6, in6_u.u6_addr32[0]);
    BPF_CORE_READ_INTO(addr_l, in6, in6_u.u6_addr32[2]);
}

static __always_inline void read_saddr_v6(struct sock *skp, u64 *addr_h, u64 *addr_l) {
    struct in6_addr in6 = {};
    BPF_CORE_READ_INTO(&in6, skp, sk_v6_rcv_saddr);
    read_in6_addr(addr_h, addr_l, &in6);
}

static __always_inline u16 _sk_family(struct sock *skp) {
    u16 family = 0;
    BPF_CORE_READ_INTO(&family, skp, sk_family);
    return family;
}

/**
 * Reads values into a `conn_tuple_t` from a `sock`. Any values that are already set in conn_tuple_t
 * are not overwritten. Returns 1 success, 0 otherwise.
 */
static __always_inline int read_conn_tuple(conn_tuple_t* t, struct sock* skp, u64 pid_tgid, metadata_mask_t type) {
    int err = 0;
    t->pid = GET_USER_MODE_PID(pid_tgid);
    t->proto = type;

    // Retrieve network namespace id first since addresses and ports may not be available for unconnected UDP
    // sends
    t->netns = get_netns_from_sock(skp);
    u16 family = _sk_family(skp);
    // Retrieve addresses
    if (family == AF_INET) {
        t->version = CONN_V4;
        if (t->saddr_l == 0) {
            t->saddr_l = read_saddr_v4(skp);
        }
    } else if (family == AF_INET6) {
        if (!(t->saddr_h || t->saddr_l)) {
            read_saddr_v6(skp, &t->saddr_h, &t->saddr_l);
        }
        t->version = CONN_V6;

    } else {
        log_debug("ERR(read_conn_tuple): unknown family %u", family);
        err = 1;
    }

    if (t->sport == 0) {
        t->sport = read_sport(skp);
    }
     
    if (t->sport == 0) {
        log_debug("sys_enter_bind: ignoring bind to 0 port, sock=%p", skp);
        err = 1;
    }

    return err ? 0 : 1;
}

#endif // __SOCK_H