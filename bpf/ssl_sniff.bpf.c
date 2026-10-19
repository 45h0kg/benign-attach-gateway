#include <linux/bpf.h>
#include <linux/types.h>

/* x86-64 struct pt_regs byte offsets */
#define OFF_RBX 40
#define OFF_RAX 80
#define OFF_RCX 88
#define OFF_RDX 96
#define OFF_RSI 104
#define OFF_RDI 112

/* Bytes of plaintext captured per write. A TLS record carries at most 16 KiB of
 * plaintext; 2 KiB is enough for a request line, headers and the start of a body,
 * and is what the content model scores. Raise it (and the maps) to see more. */
#define MAXDATA 2048

struct event {
    __u32 pid;
    __u32 tid;
    __u64 handle;   /* the TLS object the write was made on: SSL* (OpenSSL) or *tls.Conn (Go) */
    __u32 len;      /* full plaintext length the write was called with */
    __u32 cap;      /* bytes captured into data[] */
    __u8  data[MAXDATA];
};

struct bpf_map_def {
    __u32 type, key_size, value_size, max_entries, map_flags;
};

/* Latest write per task (pid_tgid -> event). Kept for the first-record gate and for
 * callers that only want "what did this process last write". */
__attribute__((section("maps"), used))
struct bpf_map_def writes = {
    .type = 1 /*HASH*/, .key_size = sizeof(__u64),
    .value_size = sizeof(struct event), .max_entries = 1024,
};
/* Every write, in order (FIFO). The stream gate drains this and holds each outgoing
 * TLS record until the plaintext that produced it has been scored. */
__attribute__((section("maps"), used))
struct bpf_map_def writes_q = {
    .type = 22 /*QUEUE*/, .key_size = 0,
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
static long (*bpf_map_push_elem)(void *, const void *, __u64) = (void *)87;
static long (*bpf_probe_read_user)(void *, __u32, const void *) = (void *)112;
static long (*bpf_probe_read_kernel)(void *, __u32, const void *) = (void *)113;

/* Common capture: copy up to MAXDATA bytes of the plaintext buffer the TLS library was
 * handed, before it encrypts, keyed by the writing task and the TLS object. The registers
 * that carry the handle, buffer and length differ per calling convention; the capture
 * does not. The event goes both to the latest-per-task map and to the FIFO. */
static __attribute__((always_inline)) int capture(void *ctx, int off_handle, int off_buf, int off_len)
{
    __u64 handle = 0, buf = 0, num = 0;
    bpf_probe_read_kernel(&handle, sizeof(handle), (char *)ctx + off_handle);
    bpf_probe_read_kernel(&buf, sizeof(buf), (char *)ctx + off_buf);
    bpf_probe_read_kernel(&num, sizeof(num), (char *)ctx + off_len);

    __u32 zero = 0;
    struct event *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e)
        return 0;
    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tid = (__u32)id;
    e->handle = handle;
    e->len = (__u32)num;
    __u32 cap = (__u32)num;
    if (cap > MAXDATA)
        cap = MAXDATA;
    e->cap = cap;
    if (cap > 0 && cap <= MAXDATA)
        bpf_probe_read_user(e->data, cap, (void *)buf);
    bpf_map_update_elem(&writes, &id, e, 0 /*BPF_ANY*/);
    bpf_map_push_elem(&writes_q, e, 0);
    return 0;
}

/* OpenSSL / BoringSSL / LibreSSL: int SSL_write(SSL *s, const void *buf, int num)
 * System V ABI: s=rdi, buf=rsi, num=rdx. Same layout for SSL_write_ex(s, buf, num, *written).
 * Works whether libssl is a shared object or statically linked into the agent binary:
 * the uprobe is placed at the symbol's file offset in whichever ELF holds the code. */
__attribute__((section("uprobe/SSL_write"), used))
int uprobe_ssl_write(void *ctx)
{
    return capture(ctx, OFF_RDI, OFF_RSI, OFF_RDX);
}

/* Go crypto/tls: func (c *Conn) Write(b []byte) (int, error)
 * Go internal register ABI (amd64, Go >= 1.17): receiver c=rax, b.ptr=rbx, b.len=rcx.
 * Go binaries are statically linked; the symbol "crypto/tls.(*Conn).Write" is in the
 * binary's own .symtab. Attach at function entry, before the stack-growth prologue. */
__attribute__((section("uprobe/go_tls_write"), used))
int uprobe_go_tls_write(void *ctx)
{
    return capture(ctx, OFF_RAX, OFF_RBX, OFF_RCX);
}

char _license[] __attribute__((section("license"), used)) = "GPL";
