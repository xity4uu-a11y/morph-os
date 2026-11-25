# Read-Only Linux eBPF Observability Bridge

`ebpf/trace_spec.c` defines the strictly **read-only** Linux eBPF CO-RE observability program paired with the Rust binary ring-buffer decoder in `crates/morph-core/src/ebpf_observer.rs`.

## Safety Boundaries

- **Zero kernel or user-space mutation:** The program never invokes `bpf_probe_write_user()`, `bpf_override_return()`, or any syscall-tampering helper.
- **Explicit consent allowlist:** Every `sys_enter_write` event is filtered immediately against the `morph_target_pids` hash map. Unregistered processes are ignored with zero buffer reads.
- **Bounded preview:** At most 48 bytes of observational prefix telemetry are copied into each 112-byte ring-buffer frame (`BPF_MAP_TYPE_RINGBUF`), and every frame carries `MORPH_FLAG_READ_ONLY` (`0x0001`), which the Rust user-space decoder explicitly enforces.

## Binary Wire Layout (`struct morph_obs_event`, 112 bytes)

| Byte Offset | Field | Type (LE) | Description |
| --- | --- | --- | --- |
| `0..4` | `magic` | `u32` | `0x4850524D` (`"MRPH"`) |
| `4..6` | `version` | `u16` | Schema version (`1`) |
| `6..8` | `event_kind` | `u16` | `1=SysEnterWrite`, `2=TcpSendMeta`, `3=StdoutFlush` |
| `8..16` | `timestamp_ns` | `u64` | Monotonic kernel timestamp (`bpf_ktime_get_ns`) |
| `16..20` | `pid` | `u32` | Thread PID |
| `20..24` | `tgid` | `u32` | Process TGID |
| `24..28` | `uid` | `u32` | Effective UID |
| `28..32` | `fd` | `i32` | Target file descriptor (`1=stdout`, `2=stderr`, `>2=socket`) |
| `32..40` | `byte_count` | `u64` | Write syscall byte count |
| `40..56` | `comm` | `[u8; 16]` | NUL-terminated process `comm` |
| `56..58` | `preview_len` | `u16` | Valid preview bytes (`0..=48`) |
| `58..60` | `flags` | `u16` | Bit `0` (`0x0001`) = `READ_ONLY_VERIFIED` |
| `60..64` | `reserved` | `u32` | Zero-initialized alignment field |
| `64..112` | `preview` | `[u8; 48]` | Bounded read-only prefix bytes |

## Building on Linux (`>= 5.8`, BTF enabled)

```bash
# Requires clang, llvm, libbpf-dev, and Linux headers
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c ebpf/trace_spec.c -o ebpf/trace_spec.o
```

On macOS and Windows, `morph-os` uses the pure-Rust child-process `stdio` interceptor and loopback HTTP reverse proxy, while `morph-os ebpf-spec --decode-sample` verifies binary wire compatibility against the 112-byte ring-buffer decoder.
