use crate::error::{FailPolicy, MorphError};
use crate::pipeline::{EnginePreference, MutationPipeline, MutationRequest, MutationResult};
use crate::plugins::OutputFormat;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// Configuration for explicitly spawning and mutating a child process's stdio stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StdioOptions {
    pub rule_id: String,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
    pub engine: EnginePreference,
    pub output_format: Option<OutputFormat>,
    pub fail_policy: Option<FailPolicy>,
    pub pretty: bool,
    pub include_stderr_in_input: bool,
}

impl Default for StdioOptions {
    fn default() -> Self {
        Self {
            rule_id: "cli-table-to-json".to_string(),
            timeout_ms: 15_000,
            max_output_bytes: 8 * 1024 * 1024,
            engine: EnginePreference::Deterministic,
            output_format: Some(OutputFormat::Json),
            fail_policy: Some(FailPolicy::FailOpen),
            pretty: true,
            include_stderr_in_input: false,
        }
    }
}

/// Captured child process execution and mutation telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StdioExecutionResult {
    pub command: String,
    pub args: Vec<String>,
    pub exit_code: i32,
    pub timed_out: bool,
    pub truncated: bool,
    pub duration_ms: f64,
    pub raw_stdout: String,
    pub raw_stderr: String,
    pub mutation: MutationResult,
}

/// Safely spawns a user-specified CLI command with explicit piped stdio, strict byte cap,
/// hard execution timeout, and panic-isolated runtime stream mutation.
pub async fn run_mutated_command(
    pipeline: &MutationPipeline,
    program: &str,
    args: &[String],
    opts: StdioOptions,
) -> Result<StdioExecutionResult, MorphError> {
    if program.trim().is_empty() {
        return Err(MorphError::ProcessSpawnFailed(
            "program path cannot be empty".into(),
        ));
    }

    let start = Instant::now();
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd.spawn().map_err(|e| {
        MorphError::ProcessSpawnFailed(format!("failed to spawn '{program}': {e}"))
    })?;

    let mut stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| MorphError::ProcessSpawnFailed("failed to capture child stdout".into()))?;
    let mut stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| MorphError::ProcessSpawnFailed("failed to capture child stderr".into()))?;

    let max_bytes = opts.max_output_bytes.max(1024);
    let stdout_task = tokio::spawn(async move { read_bounded(&mut stdout_pipe, max_bytes).await });
    let stderr_task = tokio::spawn(async move { read_bounded(&mut stderr_pipe, max_bytes).await });

    let timeout_dur = Duration::from_millis(opts.timeout_ms.max(50));
    let mut timed_out = false;
    let exit_code = match tokio::time::timeout(timeout_dur, child.wait()).await {
        Ok(Ok(status)) => status.code().unwrap_or(-1),
        Ok(Err(e)) => {
            return Err(MorphError::IoError(format!(
                "failed waiting on child process '{program}': {e}"
            )));
        }
        Err(_) => {
            timed_out = true;
            let _ = child.kill().await;
            let _ = child.wait().await;
            -1
        }
    };

    let (stdout_bytes, stdout_truncated) = stdout_task
        .await
        .map_err(|e| MorphError::IoError(format!("stdout reader join error: {e}")))??;
    let (stderr_bytes, stderr_truncated) = stderr_task
        .await
        .map_err(|e| MorphError::IoError(format!("stderr reader join error: {e}")))??;

    if timed_out && opts.fail_policy == Some(FailPolicy::FailClosed) {
        return Err(MorphError::Timeout {
            operation: format!("child process '{program}'"),
            timeout_ms: opts.timeout_ms,
        });
    }

    let raw_stdout = String::from_utf8_lossy(&stdout_bytes).to_string();
    let raw_stderr = String::from_utf8_lossy(&stderr_bytes).to_string();

    let combined_input = if opts.include_stderr_in_input && !raw_stderr.trim().is_empty() {
        format!("{raw_stdout}\n{raw_stderr}")
    } else if raw_stdout.trim().is_empty() && !raw_stderr.trim().is_empty() {
        raw_stderr.clone()
    } else {
        raw_stdout.clone()
    };

    let mutation = pipeline
        .mutate(MutationRequest {
            rule_id: opts.rule_id,
            input: combined_input,
            engine: opts.engine,
            output_format: opts.output_format,
            fail_policy: opts.fail_policy,
            pretty: opts.pretty,
            source: format!("stdio:{program}"),
        })
        .await?;

    let duration_ms = (start.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;

    Ok(StdioExecutionResult {
        command: program.to_string(),
        args: args.to_vec(),
        exit_code,
        timed_out,
        truncated: stdout_truncated || stderr_truncated,
        duration_ms,
        raw_stdout,
        raw_stderr,
        mutation,
    })
}

async fn read_bounded<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<(Vec<u8>, bool), MorphError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut truncated = false;

    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if buf.len() < max_bytes {
            let remaining = max_bytes - buf.len();
            let take = remaining.min(n);
            buf.extend_from_slice(&chunk[..take]);
            if take < n {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }

    Ok((buf, truncated))
}
