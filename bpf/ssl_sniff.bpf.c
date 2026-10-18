#include <linux/bpf.h>
#include <linux/types.h>

/* x86-64 struct pt_regs byte offsets */
#define OFF_RDX 96
#define OFF_RSI 104
#define OFF_RDI 112

#define MAXDATA 256

struct event {
    __u32 pid;
    __u32 tid;
    __u32 len;      /* full plaintext length SSL_write was called with */
    __u32 cap;      /* bytes captured into data[] */
    __u8  data[MAXDATA];
};

struct bpf_map_def {
    __u32 type, key_size, value_size, max_entries, map_flags;
};

/* key = pid_tgid -> latest SSL_write plaintext */
__attribute__((section("maps"), used))
struct bpf_map_def writes = {
    .type = 1 /*HASH*/, .key_size = sizeof(__u64),
    .value_size = sizeof(struct event), .max_entries = 4096,
};
/* scratch to build the event (too big for the stack) */
__attribute__((section("maps"), used))
struct bpf_map_def scratch = {
    .type = 2 /*ARRAY*/, .key_size = sizeof(__u32),
    .value_size = sizeof(struct event), .max_entries = 1,
};

static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;
static long (*bpf_map_update_elem)(void *, const void *, const void *, __u64) = (void *)2;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_probe_read_user)(void *, __u32, const void *) = (void *)112;
static long (*bpf_probe_read_kernel)(void *, __u32, const void *) = (void *)113;

__attribute__((section("uprobe/SSL_write"), used))
int uprobe_ssl_write(void *ctx)
{
    __u64 buf = 0, num = 0;
    /* read the register file (kernel memory) */
    bpf_probe_read_kernel(&buf, sizeof(buf), (char *)ctx + OFF_RSI); /* arg1: const void *buf */
    bpf_probe_read_kernel(&num, sizeof(num), (char *)ctx + OFF_RDX); /* arg2: int num */

    __u32 zero = 0;
    struct event *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e)
        return 0;
    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tid = (__u32)id;
    e->len = (__u32)num;
    __u32 cap = (__u32)num;
    if (cap > MAXDATA)
        cap = MAXDATA;
    e->cap = cap;
    /* bounded copy of the plaintext buffer from user space */
    if (cap > 0 && cap <= MAXDATA)
        bpf_probe_read_user(e->data, cap, (void *)buf);
    bpf_map_update_elem(&writes, &id, e, 0 /*BPF_ANY*/);
    return 0;
}

char _license[] __attribute__((section("license"), used)) = "GPL";
