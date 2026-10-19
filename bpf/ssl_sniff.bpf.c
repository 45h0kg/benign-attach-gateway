#include <linux/bpf.h>
#include <linux/types.h>

/* x86-64 struct pt_regs byte offsets */
#define OFF_RBX 40
#define OFF_RAX 80
#define OFF_RCX 88
#define OFF_RDX 96
#define OFF_RSI 104
#define OFF_RDI 112

/* Bytes of plaintext captured per write: one full TLS record's worth (16 KiB), so a
 * write of up to one record is seen whole; a longer write is seen up to its first record. */
#define MAXDATA 16384

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
    .value_size = sizeof(struct event), .max_entries = 256,
};
/* Every write, in order (FIFO). The stream gate drains this and holds each outgoing
 * TLS record until the plaintext that produced it has been scored. */
__attribute__((section("maps"), used))
struct bpf_map_def writes_q = {
    .type = 22 /*QUEUE*/, .key_size = 0,
    .value_size = sizeof(struct event), .max_entries = 1024,
};
/* TLS handle -> socket fd. Filled exactly by SSL_set_fd (OpenSSL) and, for runtimes that
 * do not announce the fd, by correlating a TLS write with the socket write that follows it
 * on the same task (pending_handle below). Userspace resolves fd -> socket -> local port
 * and so binds each captured write to the connection the relay is holding. */
__attribute__((section("maps"), used))
struct bpf_map_def fd_by_handle = {
    .type = 1 /*HASH*/, .key_size = sizeof(__u64),
    .value_size = sizeof(__u32), .max_entries = 4096,
};
/* task -> TLS handle of the write in progress; consumed by the next socket write. */
__attribute__((section("maps"), used))
struct bpf_map_def pending_handle = {
    .type = 1 /*HASH*/, .key_size = sizeof(__u64),
    .value_size = sizeof(__u64), .max_entries = 1024,
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
static long (*bpf_map_delete_elem)(void *, const void *) = (void *)3;
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
    bpf_map_update_elem(&pending_handle, &id, &handle, 0);   /* the socket write that follows names the fd */
    return 0;
}

/* The socket write that a TLS write turns into, on the same task: record handle -> fd. */
static __attribute__((always_inline)) int bind_fd(void *ctx, int off_fd)
{
    __u64 fd64 = 0;
    bpf_probe_read_kernel(&fd64, sizeof(fd64), (char *)ctx + off_fd);
    __u64 id = bpf_get_current_pid_tgid();
    __u64 *h = bpf_map_lookup_elem(&pending_handle, &id);
    if (!h)
        return 0;
    __u32 fd = (__u32)fd64;
    bpf_map_update_elem(&fd_by_handle, h, &fd, 0);
    bpf_map_delete_elem(&pending_handle, &id);
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

/* OpenSSL: int SSL_set_fd(SSL *s, int fd) -- s=rdi, fd=rsi. Exact handle -> fd binding for
 * every client that attaches a socket this way (CPython's ssl module, most C clients). */
__attribute__((section("uprobe/SSL_set_fd"), used))
int uprobe_ssl_set_fd(void *ctx)
{
    __u64 handle = 0, fd64 = 0;
    bpf_probe_read_kernel(&handle, sizeof(handle), (char *)ctx + OFF_RDI);
    bpf_probe_read_kernel(&fd64, sizeof(fd64), (char *)ctx + OFF_RSI);
    __u32 fd = (__u32)fd64;
    bpf_map_update_elem(&fd_by_handle, &handle, &fd, 0);
    return 0;
}

/* System V socket write (libc write/send/sendto: fd=rdi): bind the pending handle to this fd.
 * Covers OpenSSL clients that attach a BIO instead of calling SSL_set_fd. */
__attribute__((section("uprobe/fd_write_sysv"), used))
int uprobe_fd_write_sysv(void *ctx)
{
    return bind_fd(ctx, OFF_RDI);
}

/* Go: func syscall.write(fd int, p unsafe.Pointer, n int32) -- Go register ABI, fd=rax. */
__attribute__((section("uprobe/fd_write_go"), used))
int uprobe_fd_write_go(void *ctx)
{
    return bind_fd(ctx, OFF_RAX);
}

char _license[] __attribute__((section("license"), used)) = "GPL";
