/* escrow kernel programs: the hold point, UDP pinning, and the cookie index.
 *
 * All three attach to the supervised workload's cgroup.
 *
 *  cgroup/connect4   TCP: record cookie -> {original dst, cgroup id, pid/tgid} in escrow_map and
 *                    rewrite the destination to the interceptor, so the socket lands at the hold
 *                    point before any packet exists.
 *                    UDP: allow only the configured resolver (dns_ip:dns_port); deny the rest
 *                    (EPERM) and count it. Everything else: deny.
 *  cgroup/sendmsg4   UDP sendto() without connect(): same resolver rule.
 *  sockops           on ACTIVE_ESTABLISHED, index {local ip, local port} -> cookie in peer_map, so
 *                    the interceptor can find the cookie of the socket it just accepted from any
 *                    network namespace (pods have their own; inet_diag would not see them).
 *
 * Built with: clang -O2 -target bpf -c escrow_connect4.bpf.c
 * Loaded by:  escrow/bpfload.py (raw bpf(2), no libbpf needed)
 */
#include <linux/bpf.h>
#include <linux/types.h>

#define AF_INET 2
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct escrow_entry {
    __u32 orig_ip;      /* network byte order */
    __u16 orig_port;    /* host byte order */
    __u16 pad;
    __u64 cgroup_id;
    __u64 pid_tgid;
    __u64 ktime_ns;
};

struct cfg {
    __u32 interceptor_ip;   /* network byte order */
    __u16 interceptor_port; /* host byte order */
    __u16 dns_port;         /* host byte order; 0 = deny all UDP */
    __u32 dns_ip;           /* network byte order */
    __u32 pad;
};

struct peer_key {
    __u32 ip;     /* network byte order */
    __u16 port;   /* host byte order */
    __u16 pad;
};

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

__attribute__((section("maps"), used))
struct bpf_map_def escrow_map = {
    .type = BPF_MAP_TYPE_LRU_HASH, .key_size = sizeof(__u64),
    .value_size = sizeof(struct escrow_entry), .max_entries = 65536,
};

__attribute__((section("maps"), used))
struct bpf_map_def peer_map = {
    .type = BPF_MAP_TYPE_LRU_HASH, .key_size = sizeof(struct peer_key),
    .value_size = sizeof(__u64), .max_entries = 65536,
};

__attribute__((section("maps"), used))
struct bpf_map_def cfg_map = {
    .type = BPF_MAP_TYPE_ARRAY, .key_size = sizeof(__u32),
    .value_size = sizeof(struct cfg), .max_entries = 1,
};

/* counters: 0 tcp held, 1 udp allowed (resolver), 2 udp denied, 3 other denied */
__attribute__((section("maps"), used))
struct bpf_map_def counter_map = {
    .type = BPF_MAP_TYPE_ARRAY, .key_size = sizeof(__u32),
    .value_size = sizeof(__u64), .max_entries = 4,
};

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static __u64 (*bpf_get_socket_cookie)(void *ctx) = (void *) 46;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *) 80;

static __always_inline __u16 bswap16(__u16 x) { return (x << 8) | (x >> 8); }

static __always_inline void count(__u32 idx)
{
    __u64 *c = bpf_map_lookup_elem(&counter_map, &idx);
    if (c)
        __sync_fetch_and_add(c, 1);
}

static __always_inline int udp_rule(struct cfg *c, __u32 ip, __u16 port)
{
    if (c->dns_port && ip == c->dns_ip && port == c->dns_port) {
        count(1);
        return 1;
    }
    count(2);
    return 0;
}

__attribute__((section("cgroup/connect4"), used))
int escrow_connect4(struct bpf_sock_addr *ctx)
{
    if (ctx->user_family != AF_INET)
        return 1;
    __u32 zero = 0;
    struct cfg *c = bpf_map_lookup_elem(&cfg_map, &zero);
    if (!c || !c->interceptor_port)
        return 1;
    __u16 dport = bswap16((__u16)ctx->user_port);
    if (ctx->protocol == IPPROTO_UDP)
        return udp_rule(c, ctx->user_ip4, dport);
    if (ctx->protocol != IPPROTO_TCP) {
        count(3);
        return 0;
    }
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct escrow_entry e = {
        .orig_ip = ctx->user_ip4, .orig_port = dport,
        .cgroup_id = bpf_get_current_cgroup_id(),
        .pid_tgid = bpf_get_current_pid_tgid(),
        .ktime_ns = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&escrow_map, &cookie, &e, BPF_ANY);
    count(0);
    ctx->user_ip4 = c->interceptor_ip;
    ctx->user_port = (__u32) bswap16(c->interceptor_port);
    return 1;
}

__attribute__((section("cgroup/sendmsg4"), used))
int escrow_sendmsg4(struct bpf_sock_addr *ctx)
{
    if (ctx->user_family != AF_INET || ctx->protocol != IPPROTO_UDP)
        return 1;
    __u32 zero = 0;
    struct cfg *c = bpf_map_lookup_elem(&cfg_map, &zero);
    if (!c || !c->interceptor_port)
        return 1;
    return udp_rule(c, ctx->user_ip4, bswap16((__u16)ctx->user_port));
}

__attribute__((section("sockops"), used))
int escrow_sockops(struct bpf_sock_ops *skops)
{
    if (skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || skops->family != AF_INET)
        return 0;
    struct peer_key k = { .ip = skops->local_ip4, .port = (__u16) skops->local_port, .pad = 0 };
    __u64 cookie = bpf_get_socket_cookie(skops);
    bpf_map_update_elem(&peer_map, &k, &cookie, BPF_ANY);
    return 0;
}

char _license[] __attribute__((section("license"), used)) = "GPL";
