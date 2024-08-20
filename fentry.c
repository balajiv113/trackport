//go:build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

/**
 * struct sock_common reflects the start of the kernel's struct sock_common.
 * It only contains the fields up until skc_family that are accessed in the
 * program, with padding to match the kernel's declaration.
 */
struct sock_common {
	union {
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
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
};

/**
 * struct sock reflects the start of the kernel's struct sock.
 */
struct sock {
	struct sock_common __sk_common;
	u16 sk_protocol;
};

struct socket {
    char __pad0[8];   // Padding for `state` and `type`
    unsigned long __pad1;  // Padding for `flags`
    struct file	*file;
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
    unsigned int family;
	__u16 proto; //0 - TCP, 1 - UDP
	__u16 sport;
	__be32 saddr;
	
	__u16 dport;
    __be32 daddr;
    
	__u16 action; //0 - Port Open, 1 - Port Close 
};
struct event *unused __attribute__((unused));

static __always_inline int handle_socket(struct sock *sk, __u16 proto, __u16 action) {
    struct event *tcp_info;
    tcp_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!tcp_info) {
        return 0;
    }
    
    tcp_info->family = sk->__sk_common.skc_family;
    
    tcp_info->saddr = sk->__sk_common.skc_rcv_saddr;
    tcp_info->sport = bpf_htons(sk->__sk_common.skc_num);
    
    tcp_info->daddr = sk->__sk_common.skc_daddr;
    tcp_info->dport = sk->__sk_common.skc_dport;
    
    tcp_info->proto = proto;
    tcp_info->action = action;
    
    bpf_ringbuf_submit(tcp_info, 0);
    
    return 0;
}

SEC("fentry/inet_csk_accept")
int BPF_PROG(inet_csk_accept, struct sock *sk) {
	return handle_socket(sk, 0, 0);
}

SEC("fentry/inet_csk_listen_stop")
int BPF_PROG(inet_csk_listen_stop, struct sock *sk) {
	return handle_socket(sk, 0, 1);
}

SEC("fexit/inet_bind_sk")
int BPF_PROG(inet_bind_sk, struct sock *sk) {
    struct tcp_sock *tcp = bpf_skc_to_tcp_sock(sk);
    if(!tcp) {
        __u64 sk_ptr = (__u64)sk;
        __u16 sport = bpf_htons(sk->__sk_common.skc_num);
        bpf_map_update_elem(&ports, &sk_ptr, &sport, BPF_ANY);
        return handle_socket(sk, 1, 0);
    }
    return 0;
}

SEC("fexit/inet6_bind_sk")
int BPF_PROG(inet6_bind_sk, struct sock *sk) {
    struct tcp_sock *tcp = bpf_skc_to_tcp_sock(sk);
    if(!tcp) {
        __u64 sk_ptr = (__u64)sk;
        __u16 sport = bpf_htons(sk->__sk_common.skc_num);
        bpf_map_update_elem(&ports, &sk_ptr, &sport, BPF_ANY);
        return handle_socket(sk, 1, 0);
    }
    return 0;
}

SEC("fentry/udp_destroy_sock")
int BPF_PROG(udp_destroy_sock, struct sock *sk) {
    __u64 sk_ptr = (__u64)sk;
    __u16 *sport = bpf_map_lookup_elem(&ports, &sk_ptr);
    if (sport) {
	    return handle_socket(sk, 1, 1);
	}
	return 0;
}

SEC("fentry/udpv6_destroy_sock")
int BPF_PROG(udpv6_destroy_sock, struct sock *sk) {
    __u64 sk_ptr = (__u64)sk;
    __u16 *sport = bpf_map_lookup_elem(&ports, &sk_ptr);
    if (sport) {
	    return handle_socket(sk, 1, 1);
	}
	return 0;
}