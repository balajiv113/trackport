//go:build ignore

#include "sock.h"

char __license[] SEC("license") = "Dual MIT/GPL";

static __always_inline int handle_socket(struct sock *sk, conn_tuple_t t, metadata_mask_t proto, metadata_mask_t action) {
    log_debug("handle socket");
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    if (!read_conn_tuple(&t, sk, pid_tgid, proto)) {
        log_debug("read tuple failed for");
        return 0;
    }
    
    struct event *ev;
    ev = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!ev) {
        bpf_trace_printk("failed to reserve memory", 24);
        return 0;
    }
    
    ev->ip_l = bpf_htonl(t.saddr_l);
    ev->ip_h = bpf_htonl(t.saddr_h);
    ev->port = t.sport;
    ev->netns = t.netns;
    ev->pid = t.pid;
    ev->proto = t.proto;
    ev->version = t.version;
    ev->action = action;

    bpf_ringbuf_submit(ev, 0);
    
    return 0;
}

SEC("fentry/inet_csk_accept")
int BPF_PROG(fentry__inet_csk_accept, struct sock *sk) {
    conn_tuple_t t = {};
    return handle_socket(sk, t, CONN_TYPE_TCP, PORT_OPEN);
}

SEC("kprobe/inet_csk_accept")
int BPF_KPROBE(kprobe__inet_csk_accept, struct sock *sk) {
    conn_tuple_t t = {};
    return handle_socket(sk, t, CONN_TYPE_TCP, PORT_OPEN); 
}

SEC("fentry/inet_csk_listen_stop")
int BPF_PROG(fentry__inet_csk_listen_stop, struct sock *sk) {
    conn_tuple_t t = {};
    return handle_socket(sk, t, CONN_TYPE_TCP, PORT_CLOSE); 
}

SEC("kprobe/inet_csk_listen_stop")
int BPF_KPROBE(kprobe__inet_csk_listen_stop, struct sock *sk) {
    conn_tuple_t t = {};
    return handle_socket(sk, t, CONN_TYPE_TCP, PORT_CLOSE); 
}

static __always_inline int handle_sys_bind(struct socket *sock, struct sockaddr *addr) {
    log_debug("handle sys bind");
    __u16 type = 0;
    bpf_probe_read_kernel(&type, sizeof(__u16), &sock->type);
    if ((type & SOCK_DGRAM) == 0) {
    log_debug("handle sys bind: not dgram");
        return 0;
    }
    if (addr == NULL) {
        log_debug("sys_enter_bind: could not read sockaddr, sock=%p", sock);
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bind_syscall_args_t args = {};
    args.sk = socket_sk(sock);
    args.addr = addr;
    bpf_map_update_elem(&udp_pending, &pid_tgid, &args, BPF_ANY);
    log_debug("handle sys bind: add map");
    return 0;
}

SEC("fentry/inet_bind")
int BPF_PROG(fentry__inet_bind, struct socket *sock, struct sockaddr *addr) {
    return handle_sys_bind(sock, addr);
}

SEC("fentry/inet6_bind")
int BPF_PROG(fentry__inet6_bind, struct socket *sock, struct sockaddr *addr) {
    return handle_sys_bind(sock, addr);
}

SEC("kprobe/inet_bind")
int BPF_KPROBE(kprobe__inet_bind, struct socket *sock, struct sockaddr *addr) {
    return handle_sys_bind(sock, addr);
}

static __always_inline int handle_sys_bind_exit(__s64 ret) {
    log_debug("handle sys bind exit");
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    bind_syscall_args_t *args = bpf_map_lookup_elem(&udp_pending, &pid_tgid);
    if (args == NULL) {
        log_debug("sys_exit_bind: was not a UDP bind, will not process");
        return 0;
    }
    struct sock * sk = args->sk;
    struct sockaddr *addr = args->addr;
    bpf_map_delete_elem(&udp_pending, &pid_tgid);
    if (ret != 0) {
        log_debug("handle sys bind exit: return non-zero %lld", ret);
        return 0;
    }
    conn_tuple_t t = {};
    return handle_socket(sk, t, CONN_TYPE_UDP, PORT_OPEN);
}

SEC("fexit/inet_bind")
int BPF_PROG(fexit__inet_bind, struct socket *sock, struct sockaddr *uaddr, int addr_len, int rc) {
    return handle_sys_bind_exit(rc);
}

SEC("fexit/inet6_bind")
int BPF_PROG(fexit__inet6_bind, struct socket *sock, struct sockaddr *uaddr, int addr_len, int rc) {
    return handle_sys_bind_exit(rc);
}

SEC("kretprobe/inet_bind")
int BPF_KRETPROBE(kretprobe__inet_bind, __s64 ret) {
    return handle_sys_bind_exit(ret);
}

SEC("fentry/udp_destroy_sock")
int BPF_PROG(fentry__udp_destroy_sock, struct sock *sk) {
    conn_tuple_t t = {};
    return handle_socket(sk, t, CONN_TYPE_UDP, PORT_CLOSE); 
}

SEC("fentry/udpv6_destroy_sock")
int BPF_PROG(fentry__udpv6_destroy_sock, struct sock *sk) {
    conn_tuple_t t = {};
    return handle_socket(sk, t, CONN_TYPE_UDP, PORT_CLOSE); 
}

SEC("kprobe/udp_destroy_sock")
int BPF_KPROBE(kprobe__udp_destroy_sock, struct sock *sk) {
    conn_tuple_t t = {};
    return handle_socket(sk, t, CONN_TYPE_UDP, PORT_CLOSE); 
}