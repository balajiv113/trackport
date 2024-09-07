//go:build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"

#define AF_INET6 10

char __license[] SEC("license") = "Dual MIT/GPL";

// Define 0 and 1 in big-endian (network byte order)
__u16 ZERO = __bpf_constant_htons(0x0000);  // Big-endian 0
__u16 ONE = __bpf_constant_htons(0x0001);   // Big-endian 1

struct proto {
    __u32 pad;
};

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16  u6_addr16[8];
		__be32  u6_addr32[4];
	} in6_u;
};

struct hlist_node {
    struct hlist_node *next;
    struct hlist_node **pprev;
};

/**
 * struct sock_common reflects the start of the kernel's struct sock_common.
 * It only contains the fields up until skc_family that are accessed in the
 * program, with padding to match the kernel's declaration.
 */
struct sock_common {
	union {
		struct {
			u32 skc_daddr;
			u32 skc_rcv_saddr;
		};
	};
	union {
		// Padding out union skc_hash.
		__u32 _;
	};
	union {
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	short unsigned int skc_family;
	volatile unsigned char skc_state;
    unsigned char skc_reuse:4;
    unsigned char skc_reuseport:1;
    unsigned char skc_ipv6only:1;
    unsigned char skc_net_refcnt:1;
    int skc_bound_dev_if;
    union {
        struct hlist_node skc_bind_node;
    	struct hlist_node skc_portaddr_node;
    };
    struct proto *skc_prot;
    struct net *skc_net;
    
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
};

/**
 * struct sock reflects the start of the kernel's struct sock.
 */
struct sock {
	struct sock_common __sk_common;
};

struct socket {
	__u16 state;

	short type;

	unsigned long flags;

	struct file *file;
	struct sock *sk;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);  // Use the socket pointer address as the key
    __type(value, __u16);  // Store the port number as the value
} ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

/**
 * The sample submitted to userspace over a ring buffer.
 * Emit struct event's type info into the ELF's BTF so bpf2go
 * can generate a Go type from it.
 */
struct event {
    u32 src_ip[4];
	u32 dst_ip[4];
	u16 src_port;
	u16 dst_port;
	u8 protocol;
	u8 ipv6;
	
    __u16 family;
	__u16 proto; //0 - TCP, 1 - UDP
	u32 saddr[4];
    u32 daddr[4];
    
	__u16 sport;
	__u16 dport;
    
    __u16 pid;
    
	__u16 action; //0 - Port Open, 1 - Port Close 
};
struct event *unused __attribute__((unused));

static __always_inline int handle_socket(struct sock *sk, __u16 proto, __u16 action) {
    u64 pid = bpf_get_current_pid_tgid();
    
    struct event *tcp_info;
    tcp_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!tcp_info) {
        return 0;
    }
    
    tcp_info->family = bpf_htons(sk->__sk_common.skc_family);
    if (sk->__sk_common.skc_family == AF_INET6) {
        for (int i = 0; i < 4; i++) {
            tcp_info->saddr[i] = sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[i];
            tcp_info->daddr[i] = sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[i];
        }
    } else {
        tcp_info->saddr[0] = sk->__sk_common.skc_rcv_saddr;
        tcp_info->daddr[0] = sk->__sk_common.skc_daddr;
    }
    tcp_info->sport = bpf_htons(sk->__sk_common.skc_num);
    tcp_info->dport = sk->__sk_common.skc_dport;
    
    tcp_info->proto = proto;
    tcp_info->action = action;
    tcp_info->pid = bpf_htons(pid);
    
    bpf_ringbuf_submit(tcp_info, 0);
    
    return 0;
}

SEC("fentry/inet_csk_listen_start")
int BPF_PROG(inet_csk_accept, struct sock *sk) {
	return handle_socket(sk, ZERO, ZERO);
}

SEC("fentry/inet_csk_listen_stop")
int BPF_PROG(inet_csk_listen_stop, struct sock *sk) {
	return handle_socket(sk, ZERO, ONE);
}

SEC("fexit/inet_bind")
int BPF_PROG(inet_bind_sk, struct socket *socket) {
    struct sock *sk = socket->sk;
    struct tcp_sock *tcp = bpf_skc_to_tcp_sock(socket->sk);
    if(!tcp) {
        __u64 sk_ptr = (__u64)sk;
        __u16 sport = bpf_htons(sk->__sk_common.skc_num);
        bpf_map_update_elem(&ports, &sk_ptr, &sport, BPF_ANY);
        return handle_socket(sk, ONE, ZERO);
    }
    return 0;
}

SEC("fexit/inet6_bind")
int BPF_PROG(inet6_bind_sk, struct socket *socket) {
    struct sock *sk = socket->sk;
    struct tcp_sock *tcp = bpf_skc_to_tcp_sock(sk);
    if(!tcp) {
        __u64 sk_ptr = (__u64)sk;
        __u16 sport = bpf_htons(sk->__sk_common.skc_num);
        bpf_map_update_elem(&ports, &sk_ptr, &sport, BPF_ANY);
        return handle_socket(sk, ONE, ZERO);
    }
    return 0;
}

SEC("fentry/udp_destroy_sock")
int BPF_PROG(udp_destroy_sock, struct sock *sk) {
    __u64 sk_ptr = (__u64)sk;
    __u16 *sport = bpf_map_lookup_elem(&ports, &sk_ptr);
    if (sport) {
	    return handle_socket(sk, ONE, ONE);
	}
	return 0;
}

SEC("fentry/udpv6_destroy_sock")
int BPF_PROG(udpv6_destroy_sock, struct sock *sk) {
    __u64 sk_ptr = (__u64)sk;
    __u16 *sport = bpf_map_lookup_elem(&ports, &sk_ptr);
    if (sport) {
	    return handle_socket(sk, ONE, ONE);
	}
	return 0;
}