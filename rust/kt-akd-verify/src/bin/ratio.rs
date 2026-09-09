//! The ratio test from docs/gpu_notes.md, applied to AKD audit verification.
//!
//! Before writing a GPU verifier it is worth knowing whether verification is
//! hash-bound at all. The method is the one that saved an afternoon on Proton:
//! count the operations, measure the machine's rate for that operation, compute
//! what the phase *should* cost, and divide.
//!
//! A ratio near 1 means the work is hashing and a GPU is the right answer. A
//! large ratio means the time is going somewhere else — allocation, tree
//! construction, task overhead — and moving hashes to a GPU would accelerate
//! the part that was never the problem.
//!
//! Usage: echo '{"log_directory":...,"epoch":N,"prev_root":...,"curr_root":...}' | ratio

use akd::local_auditing::{AuditBlob, AuditBlobName};
use akd::{AppendOnlyProof, Configuration};
use serde::Deserialize;
use std::convert::TryFrom;
use std::io::Read;
use std::time::Instant;

type Config = akd::WhatsAppV1Configuration;

#[derive(Deserialize)]
struct Request {
    log_directory: String,
    epoch: u64,
    prev_root: String,
    curr_root: String,
    #[serde(default)]
    proof_path: Option<String>,
}

fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).expect("stdin");
    let req: Request = serde_json::from_str(&s).expect("request json");

    let key = format!("{}/{}/{}", req.epoch, req.prev_root, req.curr_root);
    let url = format!("{}/{}", req.log_directory.trim_end_matches('/'), key);

    let t = Instant::now();
    let data = match req.proof_path.as_deref() {
        Some(p) => std::fs::read(p).expect("read cached proof"),
        None => {
            let resp = ureq::get(&url).call().expect("GET proof");
            let mut buf = Vec::new();
            resp.into_body().into_reader().read_to_end(&mut buf).expect("body");
            buf
        }
    };
    let download = t.elapsed();
    let bytes = data.len();

    let name = AuditBlobName::try_from(key.as_str()).expect("blob name");
    let blob = AuditBlob { name, data };
    let t = Instant::now();
    let (key_epoch, phash, chash, single) = blob.decode().expect("decode");
    let decode = t.elapsed();

    // Count the work. A sparse Merkle tree over n leaves has about n internal
    // nodes, so node hashes ~= 2n; each is one or two compressions.
    let inserted = single.inserted.len();
    let unchanged = single.unchanged_nodes.len();
    // Same wrapping as the sidecar: the proof describes the transition INTO
    // key_epoch, so it starts from the epoch before.
    let proof = AppendOnlyProof {
        proofs: vec![single],
        epochs: vec![key_epoch.checked_sub(1).expect("epoch 0 has no predecessor")],
    };
    let leaves = inserted + unchanged;
    let node_hashes = 2 * leaves; // generous: leaves + internal

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let t = Instant::now();
    let res = rt.block_on(akd::auditor::audit_verify::<Config>(vec![phash, chash], proof));
    let verify = t.elapsed();
    let ok = res.is_ok();

    // The machine's rate for the same operation, measured here and now rather
    // than quoted from anywhere.
    let sample = 2_000_000usize;
    let t = Instant::now();
    let mut acc = [0u8; 32];
    for i in 0..sample {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&acc);
        buf[32..40].copy_from_slice(&(i as u64).to_le_bytes());
        acc = Config::hash(&buf);
    }
    let hash_time = t.elapsed();
    std::hint::black_box(acc);
    let rate = sample as f64 / hash_time.as_secs_f64();

    let expected = node_hashes as f64 / rate;
    println!("proof            {:.1} MB", bytes as f64 / 1e6);
    println!("  inserted       {inserted}");
    println!("  unchanged      {unchanged}");
    println!("  node hashes    ~{node_hashes} (2 x leaves)");
    println!("download         {:.2} s", download.as_secs_f64());
    println!("decode           {:.2} s", decode.as_secs_f64());
    println!("verify           {:.2} s   (ok={ok})", verify.as_secs_f64());
    println!("hash rate        {:.2} M/s single-threaded", rate / 1e6);
    println!("expected hashing {:.2} s", expected);
    println!("RATIO            {:.1}x", verify.as_secs_f64() / expected);
    println!();
    if verify.as_secs_f64() / expected > 4.0 {
        println!("Not hash-bound. A GPU would accelerate {:.0}% of the work at most.",
                 100.0 * expected / verify.as_secs_f64());
    } else {
        println!("Hash-bound. A GPU is the right tool.");
    }
}
