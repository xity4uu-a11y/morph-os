// SPDX-License-Identifier: MIT
// Copyright (c) 2026 xity4uu-a11y
//
// morph-os Read-Only Linux eBPF Observability Tracepoint Specification
// ====================================================================
//
// SAFETY BOUNDARY (NON-NEGOTIABLE):
//   - Strictly READ-ONLY observational telemetry.
//   - NEVER calls bpf_probe_write_user(), bpf_override_return(), or any kernel/process
//     memory-mutating helper.
//   - Requires explicit PID opt-in via the `morph_target_pids` BPF hash map so
//     unconsented processes are completely ignored in kernel space before any read occurs.
//   - Emits fixed-size 112-byte little-endian frames matching
//     `crates/morph-core/src/ebpf_observer.rs` over BPF_MAP_TYPE_RINGBUF.
//
// Build on Linux (>= 5.8, BTF enabled):
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c ebpf/trace_spec.c -o ebpf/trace_spec.o

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#define MORPH_FRAME_MAGIC            0x4850524DU /* ASCII "MRPH" little-endian */
#define MORPH_FRAME_VERSION          1U
#define MORPH_EVENT_SYS_ENTER_WRITE  1U
#define MORPH_FLAG_READ_ONLY         0x0001U
#define MORPH_PREVIEW_CAP            48U
#define MORPH_COMM_LEN               16U

/*
 * Exact 112-byte naturally aligned wire layout matching Rust `ebpf_observer.rs`.
 * Zero implicit padding on x86_64 and aarch64:
 *   offset  0..4   : magic        (u32 LE = 0x4850524D "MRPH")
 *   offset  4..6   : version      (u16 LE = 1)
 *   offset  6..8   : event_kind   (u16 LE = 1:SysEnterWrite, 2:TcpSendMeta, 3:StdoutFlush)
 *   offset  8..16  : timestamp_ns (u64 LE)
 *   offset 16..20  : pid          (u32 LE)
 *   offset 20..24  : tgid         (u32 LE)
 *   offset 24..28  : uid          (u32 LE)
 *   offset 28..32  : fd           (s32 LE)
 *   offset 32..40  : byte_count   (u64 LE)
 *   offset 40..56  : comm         (u8[16])
 *   offset 56..58  : preview_len  (u16 LE, clamped <= 48)
 *   offset 58..60  : flags        (u16 LE, bit 0 = MORPH_FLAG_READ_ONLY)
 *   offset 60..64  : reserved     (u32 LE = 0)
 *   offset 64..112 : preview      (u8[48])
 */
struct morph_obs_event {
    __u32 magic;
    __u16 version;
    __u16 event_kind;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __s32 fd;
    __u64 byte_count;
    __u8  comm[MORPH_COMM_LEN];
    __u16 preview_len;
    __u16 flags;
    __u32 reserved;
    __u8  preview[MORPH_PREVIEW_CAP];
};

/* Kernel tracepoint context for `tracepoint/syscalls/sys_enter_write`. */
struct sys_enter_write_ctx {
    __u64 unused;
    __s32 syscall_nr;
    __u32 pad;
    __u64 fd;
    const char *buf;
    __u64 count;
};

/* Explicit opt-in PID allowlist populated by user-space morph-os controller. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} morph_target_pids SEC(".maps");

/* Lock-free ring buffer delivering read-only telemetry frames to user space. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1 MiB ring buffer */
} morph_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct sys_enter_write_ctx *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;
    __u32 tgid = (__u32)(pid_tgid >> 32);

    /* Strictly ignore any process not explicitly registered in morph_target_pids. */
    __u8 *allowed = bpf_map_lookup_elem(&morph_target_pids, &tgid);
    if (!allowed || *allowed == 0) {
        return 0;
    }

    /* Observe only standard streams (stdout=1, stderr=2) or explicit socket fds (>2). */
    __s32 fd = (__s32)ctx->fd;
    if (fd < 1) {
        return 0;
    }

    struct morph_obs_event *ev = bpf_ringbuf_reserve(&morph_events, sizeof(*ev), 0);
    if (!ev) {
        return 0;
    }

    ev->magic = MORPH_FRAME_MAGIC;
    ev->version = MORPH_FRAME_VERSION;
    ev->event_kind = MORPH_EVENT_SYS_ENTER_WRITE;
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid = pid;
    ev->tgid = tgid;
    ev->uid = (__u32)bpf_get_current_uid_gid();
    ev->fd = fd;
    ev->byte_count = ctx->count;
    ev->flags = MORPH_FLAG_READ_ONLY;
    ev->reserved = 0;

    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    __u32 copy_len = ctx->count < MORPH_PREVIEW_CAP ? (__u32)ctx->count : MORPH_PREVIEW_CAP;
    ev->preview_len = (__u16)copy_len;

    if (copy_len > 0 && ctx->buf != 0) {
        /* Read-only copy from user buffer into telemetry ring buffer; never mutates user memory. */
        if (bpf_probe_read_user(&ev->preview, copy_len, ctx->buf) != 0) {
            ev->preview_len = 0;
        }
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
