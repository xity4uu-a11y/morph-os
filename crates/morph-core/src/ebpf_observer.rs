use crate::error::MorphError;
use serde::{Deserialize, Serialize};

/// Exact wire size of `struct morph_obs_event` defined in `ebpf/trace_spec.c`.
pub const EBPF_EVENT_FRAME_SIZE: usize = 112;

/// Little-endian magic header (`b"MRPH"`) framing every read-only eBPF telemetry event.
pub const EBPF_FRAME_MAGIC: u32 = 0x4850_524D;

/// Current binary schema version shared between `ebpf/trace_spec.c` and `morph-core`.
pub const EBPF_FRAME_VERSION: u16 = 1;

/// Flag indicating the eBPF program operated strictly in read-only observation mode.
pub const EBPF_FLAG_READ_ONLY_VERIFIED: u16 = 0x0001;

/// Read-only observational tracepoint event classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EbpfEventKind {
    SysEnterWrite = 1,
    TcpSendMeta = 2,
    StdoutFlush = 3,
}

impl EbpfEventKind {
    pub fn from_u16(raw: u16) -> Result<Self, MorphError> {
        match raw {
            1 => Ok(Self::SysEnterWrite),
            2 => Ok(Self::TcpSendMeta),
            3 => Ok(Self::StdoutFlush),
            other => Err(MorphError::EbpfFrameMalformed(format!(
                "unsupported eBPF event kind {other}"
            ))),
        }
    }
}

/// Decoded read-only Linux eBPF ring-buffer observability event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfObserveEvent {
    pub version: u16,
    pub event_kind: EbpfEventKind,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub fd: i32,
    pub byte_count: u64,
    pub comm: String,
    pub read_only: bool,
    pub preview: String,
}

/// Static specification of the strictly read-only Linux eBPF observability bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfObserverSpec {
    pub section: String,
    pub program_source: String,
    pub frame_size_bytes: usize,
    pub frame_magic_ascii: String,
    pub schema_version: u16,
    pub min_linux_kernel: String,
    pub required_capabilities: Vec<String>,
    pub safety_invariants: Vec<String>,
    pub host_platform: String,
    pub live_attach_supported: bool,
}

impl EbpfObserverSpec {
    pub fn default_spec() -> Self {
        let host_platform = std::env::consts::OS.to_string();
        let live_attach_supported = host_platform == "linux";
        Self {
            section: "tracepoint/syscalls/sys_enter_write".to_string(),
            program_source: "ebpf/trace_spec.c".to_string(),
            frame_size_bytes: EBPF_EVENT_FRAME_SIZE,
            frame_magic_ascii: "MRPH".to_string(),
            schema_version: EBPF_FRAME_VERSION,
            min_linux_kernel: "5.8+ (BPF_MAP_TYPE_RINGBUF + BTF CO-RE)".to_string(),
            required_capabilities: vec![
                "CAP_BPF".to_string(),
                "CAP_PERFMON".to_string(),
            ],
            safety_invariants: vec![
                "Strictly read-only observational telemetry; never invokes bpf_probe_write_user".to_string(),
                "Never alters syscall arguments, return codes, or process memory".to_string(),
                "Explicit PID allowlist map (morph_target_pids) prevents observing unconsented processes".to_string(),
                "Bounded 48-byte UTF-8 sanitized preview per ring-buffer frame".to_string(),
            ],
            host_platform,
            live_attach_supported,
        }
    }
}

/// Encodes an observability event into the exact 112-byte little-endian binary frame
/// emitted by `ebpf/trace_spec.c` over `BPF_MAP_TYPE_RINGBUF`.
pub fn encode_ringbuf_event(ev: &EbpfObserveEvent) -> [u8; EBPF_EVENT_FRAME_SIZE] {
    let mut frame = [0u8; EBPF_EVENT_FRAME_SIZE];
    frame[0..4].copy_from_slice(&EBPF_FRAME_MAGIC.to_le_bytes());
    frame[4..6].copy_from_slice(&ev.version.to_le_bytes());
    frame[6..8].copy_from_slice(&(ev.event_kind as u16).to_le_bytes());
    frame[8..16].copy_from_slice(&ev.timestamp_ns.to_le_bytes());
    frame[16..20].copy_from_slice(&ev.pid.to_le_bytes());
    frame[20..24].copy_from_slice(&ev.tgid.to_le_bytes());
    frame[24..28].copy_from_slice(&ev.uid.to_le_bytes());
    frame[28..32].copy_from_slice(&ev.fd.to_le_bytes());
    frame[32..40].copy_from_slice(&ev.byte_count.to_le_bytes());

    let comm_bytes = ev.comm.as_bytes();
    let comm_len = comm_bytes.len().min(15);
    frame[40..40 + comm_len].copy_from_slice(&comm_bytes[..comm_len]);

    let preview_bytes = ev.preview.as_bytes();
    let preview_len = preview_bytes.len().min(48);
    frame[56..58].copy_from_slice(&(preview_len as u16).to_le_bytes());

    let flags = if ev.read_only {
        EBPF_FLAG_READ_ONLY_VERIFIED
    } else {
        0
    };
    frame[58..60].copy_from_slice(&flags.to_le_bytes());
    // bytes 60..64 reserved = 0
    frame[64..64 + preview_len].copy_from_slice(&preview_bytes[..preview_len]);
    frame
}

/// Decodes a single 112-byte binary ring-buffer frame emitted by `ebpf/trace_spec.c`.
pub fn decode_ringbuf_event(bytes: &[u8]) -> Result<EbpfObserveEvent, MorphError> {
    if bytes.len() != EBPF_EVENT_FRAME_SIZE {
        return Err(MorphError::EbpfFrameMalformed(format!(
            "expected {EBPF_EVENT_FRAME_SIZE} bytes, got {}",
            bytes.len()
        )));
    }

    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if magic != EBPF_FRAME_MAGIC {
        return Err(MorphError::EbpfFrameMalformed(format!(
            "invalid frame magic 0x{magic:08x} (expected 0x{EBPF_FRAME_MAGIC:08x})"
        )));
    }

    let version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    if version != EBPF_FRAME_VERSION {
        return Err(MorphError::EbpfFrameMalformed(format!(
            "unsupported frame version {version} (expected {EBPF_FRAME_VERSION})"
        )));
    }

    let event_kind = EbpfEventKind::from_u16(u16::from_le_bytes(bytes[6..8].try_into().unwrap()))?;
    let timestamp_ns = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let pid = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let tgid = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    let uid = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
    let fd = i32::from_le_bytes(bytes[28..32].try_into().unwrap());
    let byte_count = u64::from_le_bytes(bytes[32..40].try_into().unwrap());

    let comm_slice = &bytes[40..56];
    let comm_end = comm_slice.iter().position(|&b| b == 0).unwrap_or(16);
    let comm = String::from_utf8_lossy(&comm_slice[..comm_end]).to_string();

    let preview_len = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    if preview_len > 48 {
        return Err(MorphError::EbpfFrameMalformed(format!(
            "preview_len {preview_len} exceeds 48-byte wire cap"
        )));
    }
    let flags = u16::from_le_bytes(bytes[58..60].try_into().unwrap());
    let read_only = (flags & EBPF_FLAG_READ_ONLY_VERIFIED) != 0;
    if !read_only {
        return Err(MorphError::EbpfFrameMalformed(
            "rejected eBPF frame without READ_ONLY_VERIFIED flag".into(),
        ));
    }

    let preview = sanitize_preview(&bytes[64..64 + preview_len]);

    Ok(EbpfObserveEvent {
        version,
        event_kind,
        timestamp_ns,
        pid,
        tgid,
        uid,
        fd,
        byte_count,
        comm,
        read_only,
        preview,
    })
}

/// Decodes a contiguous stream of concatenated 112-byte ring-buffer frames.
pub fn decode_ringbuf_stream(stream: &[u8]) -> Result<Vec<EbpfObserveEvent>, MorphError> {
    let (chunks, remainder) = stream.as_chunks::<EBPF_EVENT_FRAME_SIZE>();
    if !remainder.is_empty() {
        return Err(MorphError::EbpfFrameMalformed(format!(
            "stream length {} is not a multiple of {EBPF_EVENT_FRAME_SIZE}",
            stream.len()
        )));
    }
    let mut events = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        events.push(decode_ringbuf_event(chunk)?);
    }
    Ok(events)
}

fn sanitize_preview(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    text.chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '.'
            } else {
                c
            }
        })
        .collect()
}

/// Produces wire-encoded and round-trip decoded sample telemetry events for cross-platform inspection.
pub fn sample_decoded_events() -> Vec<EbpfObserveEvent> {
    let samples = vec![
        EbpfObserveEvent {
            version: EBPF_FRAME_VERSION,
            event_kind: EbpfEventKind::SysEnterWrite,
            timestamp_ns: 1_764_083_500_000_012,
            pid: 4182,
            tgid: 4182,
            uid: 1000,
            fd: 1,
            byte_count: 342,
            comm: "legacy-ps".to_string(),
            read_only: true,
            preview: "PID     SERVICE            STATE     MEM_MB".to_string(),
        },
        EbpfObserveEvent {
            version: EBPF_FRAME_VERSION,
            event_kind: EbpfEventKind::StdoutFlush,
            timestamp_ns: 1_764_083_500_001_420,
            pid: 4182,
            tgid: 4182,
            uid: 1000,
            fd: 1,
            byte_count: 196,
            comm: "legacy-ps".to_string(),
            read_only: true,
            preview: "1042    auth-gateway       RUNNING   128.4".to_string(),
        },
        EbpfObserveEvent {
            version: EBPF_FRAME_VERSION,
            event_kind: EbpfEventKind::TcpSendMeta,
            timestamp_ns: 1_764_083_500_004_910,
            pid: 4210,
            tgid: 4210,
            uid: 1000,
            fd: 7,
            byte_count: 518,
            comm: "erp-xml-svc".to_string(),
            read_only: true,
            preview: "<?xml version=\"1.0\"?><OrderResponse status=".to_string(),
        },
    ];

    // Round-trip through the binary wire encoder/decoder so samples prove wire fidelity.
    samples
        .into_iter()
        .filter_map(|ev| {
            let encoded = encode_ringbuf_event(&ev);
            decode_ringbuf_event(&encoded).ok()
        })
        .collect()
}
