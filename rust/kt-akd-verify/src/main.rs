//! kt-akd-verify — sidecar for the kt-witness Go process.
//!
//! Protocol: one JSON request per line on stdin, one JSON response per line on
//! stdout. The process is long-lived so the Go parent can reuse it; stdout is
//! flushed after every response. Diagnostics go to stderr only.
//!
//! Request:
//!   {"log_directory":"https://...","epoch":624700,"prev_root":"<64hex>","curr_root":"<64hex>"}
//! Response:
//!   {"ok":true,"epoch":N,"download_ms":N,"decode_ms":N,"verify_ms":N,"bytes":N}
//!   {"ok":false,"epoch":N,"error":"...","kind":"fetch"|"decode"|"verify"}
//!
//! `kind` is load-bearing: "verify" means the log cryptographically misbehaved
//! and triggers a permanent public accusation. A network/HTTP failure ("fetch")
//! or a malformed proof ("decode") means we simply could not check, and must be
//! retried. Never conflate them.

use akd::local_auditing::{AuditBlob, AuditBlobName};
use akd::AppendOnlyProof;
use serde::Deserialize;
use std::convert::TryFrom;
use std::io::{BufRead, Write};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::time::Instant;

type Config = akd::WhatsAppV1Configuration;

#[derive(Deserialize)]
struct Request {
    log_directory: String,
    epoch: u64,
    prev_root: String,
    curr_root: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Fetch,
    Decode,
    Verify,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Fetch => "fetch",
            Kind::Decode => "decode",
            Kind::Verify => "verify",
        }
    }
}

struct Failure {
    kind: Kind,
    error: String,
}

fn fail(kind: Kind, error: impl Into<String>) -> Failure {
    Failure {
        kind,
        error: error.into(),
    }
}

struct Success {
    download_ms: u128,
    decode_ms: u128,
    verify_ms: u128,
    bytes: u64,
}

/// Deletes the downloaded proof on drop so a 284MB temp file never leaks,
/// including on the error paths.
struct TempProof(PathBuf);

impl Drop for TempProof {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

impl TempProof {
    fn path(&self) -> &Path {
        &self.0
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn download(url: &str) -> Result<(TempProof, u64), Failure> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "kt-akd-verify-{}-{}.bin",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    // Guard is created before any write so an interrupted download is cleaned up.
    let guard = TempProof(path);

    let resp = ureq::get(url)
        .call()
        .map_err(|e| fail(Kind::Fetch, format!("GET {url}: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(fail(Kind::Fetch, format!("GET {url}: HTTP {status}")));
    }

    let mut reader = resp.into_body().into_reader();
    let mut file = std::fs::File::create(guard.path())
        .map_err(|e| fail(Kind::Fetch, format!("create temp file: {e}")))?;
    let bytes = std::io::copy(&mut reader, &mut file)
        .map_err(|e| fail(Kind::Fetch, format!("download body: {e}")))?;
    file.flush()
        .map_err(|e| fail(Kind::Fetch, format!("flush temp file: {e}")))?;
    drop(file);

    if bytes == 0 {
        return Err(fail(Kind::Fetch, "empty proof body"));
    }
    Ok((guard, bytes))
}

fn handle(rt: &tokio::runtime::Runtime, req: &Request) -> Result<Success, Failure> {
    if !is_hex64(&req.prev_root) || !is_hex64(&req.curr_root) {
        return Err(fail(Kind::Fetch, "prev_root/curr_root must be 64 hex chars"));
    }
    let key = format!("{}/{}/{}", req.epoch, req.prev_root, req.curr_root);
    let url = format!("{}/{}", req.log_directory.trim_end_matches('/'), key);

    let t = Instant::now();
    let (proof_file, bytes) = download(&url)?;
    let download_ms = t.elapsed().as_millis();

    let data = std::fs::read(proof_file.path())
        .map_err(|e| fail(Kind::Fetch, format!("read temp proof: {e}")))?;
    // Temp file is no longer needed; free the disk before the memory-heavy part.
    drop(proof_file);

    let name = AuditBlobName::try_from(key.as_str())
        .map_err(|e| fail(Kind::Decode, format!("bad blob name {key}: {e:?}")))?;
    let blob = AuditBlob { name, data };

    let t = Instant::now();
    let (key_epoch, phash, chash, proof) = blob
        .decode()
        .map_err(|e| fail(Kind::Decode, format!("decode proof: {e:?}")))?;
    let decode_ms = t.elapsed().as_millis();

    // === The off-by-one, and the least obvious line in this file ===
    // Meta names each audit object by its TARGET epoch (the epoch the proof
    // advances *to*), but akd's `audit_verify` indexes `epochs` by the SOURCE
    // epoch (the epoch the proof starts *from*). So we must pass
    // `key_epoch - 1`, not `key_epoch`.
    //
    // This is not cosmetic and it is not fail-safe: with `vec![key_epoch]` the
    // START hash still verifies and only the END hash fails, so the mistake
    // looks like a genuine append-only violation rather than a bug — i.e. it
    // would produce false public accusations. Do not "simplify" this.
    let source_epoch = key_epoch
        .checked_sub(1)
        .ok_or_else(|| fail(Kind::Decode, "epoch 0 has no predecessor"))?;
    let aop = AppendOnlyProof {
        proofs: vec![proof],
        epochs: vec![source_epoch],
    };

    let t = Instant::now();
    let res = rt.block_on(akd::auditor::audit_verify::<Config>(vec![phash, chash], aop));
    let verify_ms = t.elapsed().as_millis();
    res.map_err(|e| fail(Kind::Verify, format!("append-only verification failed: {e:?}")))?;

    Ok(Success {
        download_ms,
        decode_ms,
        verify_ms,
        bytes,
    })
}

fn write_line(out: &mut std::io::StdoutLock, v: &serde_json::Value) {
    let _ = serde_json::to_writer(&mut *out, v);
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

fn main() {
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to build tokio runtime: {e}");
            std::process::exit(1);
        }
    };

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("stdin read error: {e}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }

        let req: Option<Request> = match serde_json::from_str::<Request>(&line) {
            Ok(r) => Some(r),
            Err(e) => {
                write_line(
                    &mut out,
                    &serde_json::json!({
                        "ok": false,
                        "epoch": 0,
                        "error": format!("malformed request: {e}"),
                        "kind": Kind::Fetch.as_str(),
                    }),
                );
                None
            }
        };
        let Some(req) = req else { continue };
        let epoch = req.epoch;

        // A panic anywhere in decode/verify must become a JSON error, never a
        // dead loop and never a "verify" verdict.
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| handle(&rt, &req)));

        let value = match result {
            Ok(Ok(s)) => serde_json::json!({
                "ok": true,
                "epoch": epoch,
                "download_ms": s.download_ms,
                "decode_ms": s.decode_ms,
                "verify_ms": s.verify_ms,
                "bytes": s.bytes,
            }),
            Ok(Err(f)) => serde_json::json!({
                "ok": false,
                "epoch": epoch,
                "error": f.error,
                "kind": f.kind.as_str(),
            }),
            Err(p) => {
                let msg = if let Some(s) = p.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = p.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic".to_string()
                };
                // A panic means we could not complete the check — it is NOT
                // evidence of log misbehaviour, so it is never kind "verify".
                serde_json::json!({
                    "ok": false,
                    "epoch": epoch,
                    "error": format!("panic during verification: {msg}"),
                    "kind": Kind::Decode.as_str(),
                })
            }
        };
        write_line(&mut out, &value);
    }
}
