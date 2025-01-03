typedef enum
{
    // Connection type
    CONN_TYPE_TCP = 0,
    CONN_TYPE_UDP = 1,

    // Connection family
    CONN_V4 = 0,
    CONN_V6 = 1,
    
    PORT_OPEN = 0,
    PORT_CLOSE = 1,
} metadata_mask_t;

typedef struct {
    struct sockaddr *addr;
    struct sock *sk;
} bind_syscall_args_t;

struct event {
    __u64 ip_l;
    __u64 ip_h;
    __u16 port;
    __u32 netns;
    __u32 pid;
    __u16 proto;
    __u16 version;
    __u16 action;
};
struct event *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);  // Use the socket pointer address as the key
    __type(value, bind_syscall_args_t);  // Store the port number as the value
} udp_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

extern void __format_check(const char *fmt, ...) __attribute__ ((format(printf, 1, 2)));

#define log_debug(fmt, ...)                                        \
    ({                                                             \
        char ____fmt[] = fmt "\n";                                 \
        if (0) __format_check(fmt, ##__VA_ARGS__);                 \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
