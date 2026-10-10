/*!
 * sasana — Tamper-Evident Audit Verifier for OpenClaw sessions
 *
 * Usage:
 *   sasana verify <session.jsonl> [--json] [--trust-key B64] [--require-seal] [--strict]
 *
 * Exit codes:
 *   0  INTACT      — chain is valid, no drops
 *   1  COMPROMISED — hash chain has integrity violations
 *   2  PARTIAL     — valid chain but LOG_DROP events present
 *   3  ERROR       — file not found, malformed JSONL, bad usage (incl. unknown flags)
 *   4  --strict only: INTACT but not AUTHORITATIVE_EVIDENCE
 *
 * Trust model (matches the Python verifier v2.0.0):
 *   AUTHORITATIVE_EVIDENCE requires --trust-key: a CHAIN_SEAL that only verifies against its
 *   own embedded server_pubkey is SELF_SEALED_EVIDENCE. --trust-key and --require-seal both
 *   make a missing CHAIN_SEAL a COMPROMISED verdict.
 *
 * NOT implemented here (the Python verifier does these): RFC 3161 timestamp checks, per-event
 * Ed25519 signatures, the per-check breakdown in --json output.
 *
 * Hash algorithm: SHA-256 over RFC 8785 canonical JSON of each event
 * (excluding the event_hash field itself), chained via prev_hash.
 * This must match sasana/envelope.py exactly.
 */

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ring::signature::{self as ring_sig, UnparsedPublicKey};
use hex::encode as hex_encode;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::process;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const VERIFIER_VERSION: &str = "2.0.0";

// ---------------------------------------------------------------------------
// RFC 8785 canonical JSON
//
// Rules:
//   1. Object keys sorted by UTF-16 code unit sequence (lexicographic)
//   2. No whitespace outside strings
//   3. Control chars U+0000–U+001F escaped as \uXXXX
//   4. Numbers: shortest round-trip; -0.0 → "0"
//   5. Arrays: order preserved
// ---------------------------------------------------------------------------

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                return i.to_string();
            }
            if let Some(u) = n.as_u64() {
                return u.to_string();
            }
            if let Some(f) = n.as_f64() {
                if f == 0.0 {
                    return "0".to_string(); // RFC 8785: -0.0 → "0"
                }
                let s = format!("{}", n); // serde_json gives shortest round-trip
                return s;
            }
            n.to_string()
        }
        Value::String(s) => {
            let mut out = String::with_capacity(s.len() + 2);
            out.push('"');
            for ch in s.chars() {
                match ch {
                    '"'  => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '\x08' => out.push_str("\\b"),
                    '\x0C' => out.push_str("\\f"),
                    c if (c as u32) < 0x20 => {
                        let _ = write!(out, "\\u{:04x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
            out
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        Value::Object(map) => {
            // RFC 8785: sort by UTF-16 code unit sequence
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| {
                let a16: Vec<u16> = a.encode_utf16().collect();
                let b16: Vec<u16> = b.encode_utf16().collect();
                a16.cmp(&b16)
            });
            let pairs: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        canonical_json(&Value::String((*k).clone())),
                        canonical_json(&map[*k])
                    )
                })
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

// ---------------------------------------------------------------------------
// Hash computation — must match sasana/envelope.py
//
// event_hash = SHA-256( canonical_json(event_without_event_hash_and_signature) )
// ---------------------------------------------------------------------------

fn compute_event_hash(event_map: &Map<String, Value>) -> String {
    let stripped: Map<String, Value> = event_map
        .iter()
        .filter(|(k, _)| k.as_str() != "event_hash" && k.as_str() != "signature")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let canonical = canonical_json(&Value::Object(stripped));
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex_encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Check 5 — CHAIN_SEAL Ed25519 signature verification
//
// Matches Python sasana.verifier._check_seal_signature exactly:
//   - pubkey: base64-encoded raw 32-byte Ed25519 public key
//   - signature: base64-encoded 64-byte Ed25519 signature
//   - message: event_hash as UTF-8 bytes (the 64-char hex string)
// ---------------------------------------------------------------------------

struct SealOutcome {
    errors: Vec<String>,
    present: bool,
    trusted: bool,
}

fn seal_fail(msgs: Vec<String>, present: bool) -> SealOutcome {
    SealOutcome { errors: msgs, present, trusted: false }
}

fn verify_seal_signature(
    events: &[Map<String, Value>],
    trusted_pubkey: Option<&str>,
    require_seal: bool,
) -> SealOutcome {
    let seals: Vec<usize> = events
        .iter()
        .enumerate()
        .filter(|(_, e)| e.get("event_type").and_then(Value::as_str) == Some("CHAIN_SEAL"))
        .map(|(i, _)| i)
        .collect();

    if seals.is_empty() {
        let mut errors = Vec::new();
        if trusted_pubkey.is_some() {
            errors.push("pinned key provided but session has no CHAIN_SEAL".to_string());
        }
        if require_seal {
            errors.push("seal required but session has no CHAIN_SEAL".to_string());
        }
        return seal_fail(errors, false);
    }
    if seals.len() > 1 {
        return seal_fail(
            vec![format!("session has {} CHAIN_SEAL events; exactly one is allowed", seals.len())],
            true,
        );
    }
    let seal_idx = seals[0];
    if seal_idx != events.len() - 1 {
        return seal_fail(vec!["CHAIN_SEAL must be the final event".to_string()], true);
    }
    let seal = &events[seal_idx];

    let payload = seal.get("payload").and_then(Value::as_object);
    let pubkey_b64 = match payload.and_then(|p| p.get("server_pubkey")).and_then(Value::as_str) {
        Some(k) => k,
        None => return seal_fail(vec!["CHAIN_SEAL missing server_pubkey in payload".to_string()], true),
    };
    let sig_b64 = match seal.get("signature").and_then(Value::as_str) {
        Some(s) => s,
        None => return seal_fail(vec!["CHAIN_SEAL missing signature".to_string()], true),
    };
    let event_hash = match seal.get("event_hash").and_then(Value::as_str) {
        Some(h) => h,
        None => return seal_fail(vec!["CHAIN_SEAL missing event_hash".to_string()], true),
    };

    // Key pinning: if a trusted key is specified, reject any other key.
    if let Some(trusted) = trusted_pubkey {
        if pubkey_b64 != trusted {
            return seal_fail(
                vec![format!(
                    "CHAIN_SEAL signed by untrusted key — expected {}…, got {}…",
                    &trusted[..trusted.len().min(16)],
                    &pubkey_b64[..pubkey_b64.len().min(16)]
                )],
                true,
            );
        }
    }

    let pubkey_bytes = match BASE64.decode(pubkey_b64) {
        Ok(b) => b,
        Err(_) => return seal_fail(vec!["CHAIN_SEAL server_pubkey is not valid base64".to_string()], true),
    };
    let sig_bytes = match BASE64.decode(sig_b64) {
        Ok(b) => b,
        Err(_) => return seal_fail(vec!["CHAIN_SEAL signature is not valid base64".to_string()], true),
    };
    if pubkey_bytes.len() != 32 {
        return seal_fail(vec!["CHAIN_SEAL server_pubkey must be 32 bytes".to_string()], true);
    }
    if sig_bytes.len() != 64 {
        return seal_fail(vec!["CHAIN_SEAL signature must be 64 bytes".to_string()], true);
    }

    let pub_key = UnparsedPublicKey::new(&ring_sig::ED25519, &pubkey_bytes);
    if pub_key.verify(event_hash.as_bytes(), &sig_bytes).is_err() {
        return seal_fail(
            vec!["CHAIN_SEAL signature invalid — seal has been tampered with".to_string()],
            true,
        );
    }

    // The seal must attest to the chain head it follows.
    if events.len() >= 2 {
        let head = events[events.len() - 2].get("event_hash").and_then(Value::as_str);
        let claimed = payload.and_then(|p| p.get("session_hash")).and_then(Value::as_str);
        if claimed.is_none() || claimed != head {
            return seal_fail(
                vec![
                    "CHAIN_SEAL session_hash does not match the preceding event's event_hash"
                        .to_string(),
                ],
                true,
            );
        }
    }

    SealOutcome { errors: vec![], present: true, trusted: trusted_pubkey.is_some() }
}

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct VerifyResult {
    status: String,
    evidence_class: String,
    session_id: Option<String>,
    event_count: usize,
    log_drop_count: usize,
    root_hash: Option<String>,
    errors: Vec<String>,
    warnings: Vec<String>,
    pinned: bool,
    require_seal: bool,
    seal_present: bool,
    seal_trusted: bool,
    verifier_version: String,
}

// ---------------------------------------------------------------------------
// Core verifier
// ---------------------------------------------------------------------------

fn verify_file(path: &str, trusted_pubkey: Option<&str>, require_seal: bool) -> VerifyResult {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            return error_result(format!("Cannot read '{}': {}", path, e), trusted_pubkey, require_seal)
        }
    };

    let mut raw_events: Vec<Map<String, Value>> = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(trimmed) {
            Ok(Value::Object(map)) => raw_events.push(map),
            Ok(_) => {
                return error_result(format!("Line {}: not a JSON object", i + 1), trusted_pubkey, require_seal)
            }
            Err(e) => {
                return error_result(
                    format!("Line {}: JSON parse error: {}", i + 1, e),
                    trusted_pubkey,
                    require_seal,
                )
            }
        }
    }
    verify_events(&raw_events, trusted_pubkey, require_seal)
}

fn verify_events(
    raw_events: &[Map<String, Value>],
    trusted_pubkey: Option<&str>,
    require_seal: bool,
) -> VerifyResult {
    if raw_events.is_empty() {
        return error_result("File is empty or contains no JSON objects".to_string(), trusted_pubkey, require_seal);
    }

    let event_count = raw_events.len();
    let mut errors: Vec<String> = Vec::new();
    let mut log_drop_count = 0usize;
    let mut session_id: Option<String> = None;
    let mut last_hash = GENESIS_HASH.to_string();
    let mut root_hash: Option<String> = None;

    // Check 1: structural validity
    let required = ["seq", "event_type", "session_id", "timestamp", "payload", "prev_hash", "event_hash"];
    for event_map in raw_events {
        let seq = event_map.get("seq").and_then(Value::as_i64).unwrap_or(0);
        for field in &required {
            if !event_map.contains_key(*field) {
                errors.push(format!("seq={}: missing required field '{}'", seq, field));
            }
        }
        if let Some(et) = event_map.get("event_type").and_then(Value::as_str) {
            if et == "LOG_DROP" {
                log_drop_count += 1;
            }
        }
        if session_id.is_none() {
            if let Some(sid) = event_map.get("session_id").and_then(Value::as_str) {
                session_id = Some(sid.to_string());
            }
        }
    }

    // Check 2: sequence continuity
    for (i, event_map) in raw_events.iter().enumerate() {
        if let Some(seq) = event_map.get("seq").and_then(Value::as_i64) {
            let expected = (i as i64) + 1;
            if seq != expected {
                errors.push(format!("Sequence gap: expected seq={}, found seq={}", expected, seq));
            }
        }
    }

    // Check 3: hash chain integrity
    for event_map in raw_events {
        let seq = event_map.get("seq").and_then(Value::as_i64).unwrap_or(0);

        if let Some(stored_prev) = event_map.get("prev_hash").and_then(Value::as_str) {
            if stored_prev != last_hash.as_str() {
                errors.push(format!(
                    "seq={}: prev_hash mismatch: stored={}…, expected={}…",
                    seq,
                    &stored_prev[..8.min(stored_prev.len())],
                    &last_hash[..8.min(last_hash.len())]
                ));
            }
        }

        let recomputed = compute_event_hash(event_map);
        if let Some(stored) = event_map.get("event_hash").and_then(Value::as_str) {
            if stored != recomputed.as_str() {
                errors.push(format!(
                    "seq={}: event_hash mismatch: stored={}…, computed={}…",
                    seq,
                    &stored[..8.min(stored.len())],
                    &recomputed[..8.min(recomputed.len())]
                ));
            }
            last_hash = stored.to_string();
        } else {
            last_hash = recomputed;
        }
        root_hash = Some(last_hash.clone());
    }

    // Check 4: session bookends
    let first_type = raw_events.first()
        .and_then(|e| e.get("event_type"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let last_type = raw_events.last()
        .and_then(|e| e.get("event_type"))
        .and_then(Value::as_str)
        .unwrap_or("");

    let has_session_end = raw_events.iter().any(|e| {
        e.get("event_type").and_then(Value::as_str) == Some("SESSION_END")
    });
    let has_chain_seal = raw_events.iter().any(|e| {
        e.get("event_type").and_then(Value::as_str) == Some("CHAIN_SEAL")
    });

    if first_type != "SESSION_START" {
        errors.push(format!("First event is '{}', expected SESSION_START", first_type));
    }

    // A server-sealed session ends: … SESSION_END → CHAIN_SEAL
    // Accept CHAIN_SEAL as last when SESSION_END is also present.
    let closing_ok = last_type == "SESSION_END"
        || (last_type == "CHAIN_SEAL" && has_session_end)
        || has_chain_seal && !has_session_end;
    if !closing_ok {
        errors.push(format!(
            "Session must end with SESSION_END or CHAIN_SEAL, found '{}'",
            last_type
        ));
    }

    // Check 5: CHAIN_SEAL Ed25519 signature, key pinning, single/final seal, session_hash
    let seal = verify_seal_signature(raw_events, trusted_pubkey, require_seal);
    errors.extend(seal.errors);
    let seal_trusted = seal.trusted && errors.is_empty();

    let mut warnings: Vec<String> = Vec::new();
    if seal.present && trusted_pubkey.is_none() {
        warnings.push(
            "seal not verified against a trusted key; anyone can produce this \
             (pass --trust-key with the Archeion public key to verify who sealed it)"
                .to_string(),
        );
    }
    if !seal.present && !require_seal && trusted_pubkey.is_none() {
        warnings.push(
            "session has no CHAIN_SEAL: only internal consistency was checked, so a complete \
             rewrite of this log cannot be detected"
                .to_string(),
        );
    }

    let (status, evidence_class) = if !errors.is_empty() {
        ("COMPROMISED".to_string(), "NO_EVIDENCE".to_string())
    } else if log_drop_count > 0 {
        ("PARTIAL".to_string(), "PARTIAL_EVIDENCE".to_string())
    } else if has_chain_seal && seal_trusted {
        ("INTACT".to_string(), "AUTHORITATIVE_EVIDENCE".to_string())
    } else if has_chain_seal {
        ("INTACT".to_string(), "SELF_SEALED_EVIDENCE".to_string())
    } else {
        ("INTACT".to_string(), "NON_AUTHORITATIVE_EVIDENCE".to_string())
    };

    VerifyResult {
        status,
        evidence_class,
        session_id,
        event_count,
        log_drop_count,
        root_hash,
        errors,
        warnings,
        pinned: trusted_pubkey.is_some(),
        require_seal,
        seal_present: seal.present,
        seal_trusted,
        verifier_version: VERIFIER_VERSION.to_string(),
    }
}

fn error_result(msg: String, trusted_pubkey: Option<&str>, require_seal: bool) -> VerifyResult {
    VerifyResult {
        status: "ERROR".to_string(),
        evidence_class: "NO_EVIDENCE".to_string(),
        session_id: None,
        event_count: 0,
        log_drop_count: 0,
        root_hash: None,
        errors: vec![msg],
        warnings: vec![],
        pinned: trusted_pubkey.is_some(),
        require_seal,
        seal_present: false,
        seal_trusted: false,
        verifier_version: VERIFIER_VERSION.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Human-readable output
// ---------------------------------------------------------------------------

fn print_human(result: &VerifyResult, path: &str) {
    println!("Sasana Verifier v{}", VERIFIER_VERSION);
    println!("File:    {}", path);
    if let Some(sid) = &result.session_id {
        println!("Session: {}", sid);
    }
    println!("Events:  {}", result.event_count);
    println!("Evidence class: {}", result.evidence_class);
    println!(
        "Trusted key: {}",
        if result.pinned { "pinned (--trust-key)" } else { "none (seal key NOT trusted)" }
    );
    println!();

    let pass = "PASS";
    let fail = "FAIL";
    let hash_ok    = !result.errors.iter().any(|e| e.contains("hash mismatch") || e.contains("prev_hash"));
    let seq_ok     = !result.errors.iter().any(|e| e.contains("Sequence gap"));
    let struct_ok  = !result.errors.iter().any(|e| e.contains("missing required"));
    let bookend_ok = !result.errors.iter().any(|e| e.contains("SESSION_START") || e.contains("SESSION_END"));
    let seal_ok    = !result.errors.iter().any(|e| e.contains("CHAIN_SEAL") || e.contains("seal"));

    println!("[1/5] Structural validity  ... {}", if struct_ok  { pass } else { fail });
    println!("[2/5] Sequence integrity   ... {}", if seq_ok     { pass } else { fail });
    println!("[3/5] Hash chain integrity ... {}", if hash_ok    { pass } else { fail });
    println!("[4/5] Session completeness ... {}", if bookend_ok { pass } else { fail });
    let seal_label = if !seal_ok {
        fail
    } else if !result.seal_present {
        "NO SEAL (no CHAIN_SEAL present)"
    } else if result.seal_trusted {
        "PASS (signed by the pinned key)"
    } else {
        "SELF-SIGNED (valid against its own embedded key only)"
    };
    println!("[5/5] Seal signature       ... {}", seal_label);
    if result.log_drop_count > 0 {
        println!("      ({} LOG_DROP events)", result.log_drop_count);
    }
    println!();
    for w in &result.warnings {
        println!("⚠  {}", w);
    }
    if !result.warnings.is_empty() {
        println!();
    }

    match result.status.as_str() {
        "INTACT" => println!("RESULT: INTACT ✅"),
        "PARTIAL" => println!("RESULT: PARTIAL ⚠️  ({} LOG_DROP events)", result.log_drop_count),
        "COMPROMISED" => {
            println!("RESULT: COMPROMISED ❌");
            for err in &result.errors {
                println!("  → {}", err);
            }
        }
        _ => {
            println!("RESULT: ERROR ❌");
            for err in &result.errors {
                println!("  → {}", err);
            }
        }
    }

    if let Some(root) = &result.root_hash {
        let preview_len = 16.min(root.len());
        println!("Root hash: {}…", &root[..preview_len]);
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn usage() {
    eprintln!("Sasana Verifier v{}", VERIFIER_VERSION);
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  sasana verify <session.jsonl>                         Verify session");
    eprintln!("  sasana verify <session.jsonl> --json                  JSON output");
    eprintln!("  sasana verify <session.jsonl> --trust-key BASE64      Pin Archeion pubkey (needed for AUTHORITATIVE)");
    eprintln!("  sasana verify <session.jsonl> --require-seal          Missing CHAIN_SEAL is COMPROMISED");
    eprintln!("  sasana verify <session.jsonl> --trust-key K --strict  Exit 4 unless AUTHORITATIVE_EVIDENCE");
    eprintln!();
    eprintln!("EXIT CODES:");
    eprintln!("  0  INTACT      — chain is valid (see Evidence class: unpinned seals are SELF_SEALED)");
    eprintln!("  1  COMPROMISED — chain or seal has integrity violations");
    eprintln!("  2  PARTIAL     — valid but LOG_DROP events present");
    eprintln!("  3  ERROR       — file unreadable or malformed, or bad usage / unknown flag");
    eprintln!("  4  --strict only: INTACT but not AUTHORITATIVE_EVIDENCE");
}

fn usage_error(msg: &str) -> ! {
    eprintln!("sasana verify: error: {}", msg);
    process::exit(3);
}

fn exit_code_for(result: &VerifyResult, strict: bool) -> i32 {
    if strict && result.status == "INTACT" && result.evidence_class != "AUTHORITATIVE_EVIDENCE" {
        return 4;
    }
    match result.status.as_str() {
        "INTACT" => 0,
        "COMPROMISED" => 1,
        "PARTIAL" => 2,
        _ => 3,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        usage();
        process::exit(3);
    }

    match args[1].as_str() {
        "verify" => {
            let rest = &args[2..];
            let mut path: Option<&str> = None;
            let mut json_output = false;
            let mut require_seal = false;
            let mut strict = false;
            let mut trusted_pubkey: Option<String> = None;
            let mut i = 0;
            // Unknown flags are an error: silently ignoring e.g. `--trust_key` would drop a
            // security control while still printing a verdict.
            while i < rest.len() {
                match rest[i].as_str() {
                    "--json" => json_output = true,
                    "--require-seal" => require_seal = true,
                    "--strict" => strict = true,
                    "--trust-key" => {
                        i += 1;
                        match rest.get(i) {
                            Some(v) if !v.starts_with("--") => trusted_pubkey = Some(v.clone()),
                            _ => usage_error("--trust-key requires a base64 public key"),
                        }
                    }
                    flag if flag.starts_with("--") => {
                        usage_error(&format!("unrecognized argument: {}", flag))
                    }
                    other => {
                        if path.is_some() {
                            usage_error(&format!("unexpected extra argument: {}", other));
                        }
                        path = Some(other);
                    }
                }
                i += 1;
            }
            let path = match path {
                Some(p) => p,
                None => usage_error("missing <session.jsonl>"),
            };
            if strict && trusted_pubkey.is_none() {
                usage_error("--strict requires --trust-key (AUTHORITATIVE_EVIDENCE needs a pinned key)");
            }
            let result = verify_file(path, trusted_pubkey.as_deref(), require_seal);
            let exit_code = exit_code_for(&result, strict);
            if json_output {
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            } else {
                print_human(&result, path);
                if exit_code == 4 {
                    println!("--strict: INTACT but {} (exit 4)", result.evidence_class);
                }
            }
            process::exit(exit_code);
        }
        "--version" | "-V" | "version" => {
            println!("sasana {}", VERIFIER_VERSION);
        }
        "--help" | "-h" | "help" | _ => {
            usage();
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_sorts_keys() {
        let obj = json!({"z": 1, "a": 2, "m": 3});
        assert_eq!(canonical_json(&obj), r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn canonical_json_negative_zero() {
        let zero = Value::Number(serde_json::Number::from_f64(-0.0_f64).unwrap());
        assert_eq!(canonical_json(&zero), "0");
    }

    #[test]
    fn canonical_json_escapes_newline() {
        let s = Value::String("\n".to_string());
        assert_eq!(canonical_json(&s), r#""\n""#);
    }

    #[test]
    fn canonical_json_nested_object() {
        let obj = json!({"b": {"y": 1, "x": 2}, "a": 3});
        let result = canonical_json(&obj);
        assert!(result.starts_with(r#"{"a":3,"b":{"x":2,"y":1}}"#));
    }

    #[test]
    fn canonical_json_empty_object() {
        assert_eq!(canonical_json(&json!({})), "{}");
    }

    #[test]
    fn genesis_hash_is_64_hex_zeros() {
        assert_eq!(GENESIS_HASH.len(), 64);
        assert!(GENESIS_HASH.chars().all(|c| c == '0'));
    }

    #[test]
    fn compute_event_hash_excludes_event_hash_and_signature() {
        let mut map = Map::new();
        map.insert("seq".to_string(), json!(1));
        map.insert("event_type".to_string(), json!("SESSION_START"));
        map.insert("event_hash".to_string(), json!("should_be_excluded"));
        map.insert("signature".to_string(), json!("also_excluded"));
        map.insert("prev_hash".to_string(), json!(GENESIS_HASH));

        let h1 = compute_event_hash(&map);
        map.remove("event_hash");
        map.remove("signature");
        let h2 = compute_event_hash(&map);
        assert_eq!(h1, h2);
    }

    #[test]
    fn error_result_has_error_status() {
        let r = error_result("test error".to_string(), None, false);
        assert_eq!(r.status, "ERROR");
        assert_eq!(r.event_count, 0);
    }

    // ----- trust-model tests: same cases as tests/test_tamper_matrix.py -----------------

    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    type Ev = Map<String, Value>;

    fn mk_event(seq: i64, et: &str, payload: Value, prev: &str) -> Ev {
        let mut m = Map::new();
        m.insert("seq".into(), json!(seq));
        m.insert("event_type".into(), json!(et));
        m.insert("session_id".into(), json!("rs-matrix"));
        m.insert("timestamp".into(), json!("2026-01-01T00:00:00.000000Z"));
        m.insert("payload".into(), payload);
        m.insert("prev_hash".into(), json!(prev));
        let h = compute_event_hash(&m);
        m.insert("event_hash".into(), json!(h));
        m
    }

    fn base_session() -> Vec<Ev> {
        let spec = [
            ("SESSION_START", json!({"agent_id": "a1"})),
            ("TOOL_CALL", json!({"tool_name": "bash"})),
            ("TOOL_RESULT", json!({"result_hash": "d"})),
            ("SESSION_END", json!({"status": "success", "classification": "DIVERGENT"})),
        ];
        let mut out: Vec<Ev> = Vec::new();
        for (i, (et, pl)) in spec.iter().enumerate() {
            let prev = out.last().map(|e| e["event_hash"].as_str().unwrap().to_string())
                .unwrap_or_else(|| GENESIS_HASH.to_string());
            out.push(mk_event(i as i64 + 1, et, pl.clone(), &prev));
        }
        out
    }

    fn keypair() -> (Ed25519KeyPair, String) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pubkey = BASE64.encode(kp.public_key().as_ref());
        (kp, pubkey)
    }

    fn rechain(evs: &mut [Ev]) {
        for i in 0..evs.len() {
            let prev = if i == 0 { GENESIS_HASH.to_string() }
                else { evs[i - 1]["event_hash"].as_str().unwrap().to_string() };
            evs[i].insert("prev_hash".into(), json!(prev));
            let h = compute_event_hash(&evs[i]);
            evs[i].insert("event_hash".into(), json!(h));
        }
    }

    fn seal_over(evs: &[Ev], kp: &Ed25519KeyPair, pubkey: &str) -> Ev {
        let head = evs.last().unwrap()["event_hash"].as_str().unwrap().to_string();
        let seq = evs.last().unwrap()["seq"].as_i64().unwrap() + 1;
        let mut m = mk_event(
            seq,
            "CHAIN_SEAL",
            json!({"session_hash": head, "sealed_by": "test", "server_pubkey": pubkey}),
            &head,
        );
        let sig = BASE64.encode(kp.sign(m["event_hash"].as_str().unwrap().as_bytes()).as_ref());
        m.insert("signature".into(), json!(sig));
        m
    }

    fn sealed(kp: &Ed25519KeyPair, pubkey: &str) -> Vec<Ev> {
        let mut evs = base_session();
        let s = seal_over(&evs, kp, pubkey);
        evs.push(s);
        evs
    }

    fn run(evs: &[Ev], pin: Option<&str>, require: bool) -> VerifyResult {
        verify_events(evs, pin, require)
    }

    #[test]
    fn a_genuine_seal_unpinned_is_self_sealed_pinned_is_authoritative() {
        let (kp, pk) = keypair();
        let evs = sealed(&kp, &pk);
        let r = run(&evs, None, false);
        assert_eq!((r.status.as_str(), r.evidence_class.as_str()), ("INTACT", "SELF_SEALED_EVIDENCE"));
        assert!(!r.seal_trusted && r.warnings.iter().any(|w| w.contains("anyone can produce this")));
        let r = run(&evs, Some(&pk), false);
        assert_eq!((r.status.as_str(), r.evidence_class.as_str()), ("INTACT", "AUTHORITATIVE_EVIDENCE"));
        assert!(r.seal_trusted);
    }

    #[test]
    fn b_edit_only_is_compromised() {
        let (kp, pk) = keypair();
        let mut evs = sealed(&kp, &pk);
        evs[3].get_mut("payload").unwrap()["classification"] = json!("IN-BOUNDS");
        assert_eq!(run(&evs, Some(&pk), false).status, "COMPROMISED");
        assert_eq!(run(&evs, None, false).status, "COMPROMISED");
    }

    #[test]
    fn c_rechain_keeping_old_seal_is_compromised() {
        let (kp, pk) = keypair();
        let mut evs = sealed(&kp, &pk);
        evs[3].get_mut("payload").unwrap()["classification"] = json!("IN-BOUNDS");
        rechain(&mut evs[..4]); // seal event untouched (c1)
        assert_eq!(run(&evs, Some(&pk), false).status, "COMPROMISED");
        let head = evs[3]["event_hash"].clone();
        evs[4].insert("prev_hash".into(), head.clone()); // c2: relink + rehash, stale signature
        evs[4].get_mut("payload").unwrap()["session_hash"] = head;
        let h = compute_event_hash(&evs[4]);
        evs[4].insert("event_hash".into(), json!(h));
        let r = run(&evs, Some(&pk), false);
        assert_eq!(r.status, "COMPROMISED");
        assert!(r.errors.iter().any(|e| e.contains("signature invalid")));
    }

    #[test]
    fn d_e_attacker_reseal_pinned_rejected_unpinned_not_authoritative() {
        let (real_kp, real_pk) = keypair();
        let (atk_kp, atk_pk) = keypair();
        let mut evs = base_session();
        evs[3].get_mut("payload").unwrap()["classification"] = json!("IN-BOUNDS");
        rechain(&mut evs);
        let s = seal_over(&evs, &atk_kp, &atk_pk);
        evs.push(s);
        let r = run(&evs, Some(&real_pk), false); // d
        assert_eq!(r.status, "COMPROMISED");
        assert!(r.errors.iter().any(|e| e.contains("untrusted key")));
        let r = run(&evs, None, false); // e
        assert_eq!((r.status.as_str(), r.evidence_class.as_str()), ("INTACT", "SELF_SEALED_EVIDENCE"));
        assert_ne!(r.evidence_class, "AUTHORITATIVE_EVIDENCE");
        let _ = real_kp;
    }

    #[test]
    fn f_stripped_seal_is_compromised_when_pinned_or_required() {
        let (_kp, pk) = keypair();
        let mut evs = base_session();
        evs[3].get_mut("payload").unwrap()["classification"] = json!("IN-BOUNDS");
        rechain(&mut evs);
        let r = run(&evs, Some(&pk), false); // f
        assert_eq!(r.status, "COMPROMISED");
        assert!(r.errors.iter().any(|e| e.contains("pinned key provided but session has no CHAIN_SEAL")));
        let r = run(&evs, None, true); // f'
        assert_eq!(r.status, "COMPROMISED");
        assert!(r.errors.iter().any(|e| e.contains("seal required")));
        // neither flag: still INTACT/NON_AUTHORITATIVE, but with a warning
        let r = run(&evs, None, false);
        assert_eq!((r.status.as_str(), r.evidence_class.as_str()), ("INTACT", "NON_AUTHORITATIVE_EVIDENCE"));
        assert!(!r.warnings.is_empty());
    }

    #[test]
    fn g_seal_claiming_real_key_signed_by_attacker_is_compromised() {
        let (_real_kp, real_pk) = keypair();
        let (atk_kp, _atk_pk) = keypair();
        let mut evs = base_session();
        let s = seal_over(&evs, &atk_kp, &real_pk); // advertises real key, signed by attacker
        evs.push(s);
        assert_eq!(run(&evs, None, false).status, "COMPROMISED");
        assert_eq!(run(&evs, Some(&real_pk), false).status, "COMPROMISED");
    }

    #[test]
    fn two_seals_and_non_final_seal_are_rejected() {
        let (kp, pk) = keypair();
        let mut evs = sealed(&kp, &pk);
        let second = seal_over(&evs, &kp, &pk);
        evs.push(second);
        let r = run(&evs, Some(&pk), false);
        assert_eq!(r.status, "COMPROMISED");
        assert!(r.errors.iter().any(|e| e.contains("2 CHAIN_SEAL events")));

        // seal in the middle of an otherwise valid chain
        let base = base_session();
        let mut mid: Vec<Ev> = vec![base[0].clone(), base[1].clone()];
        let s = seal_over(&mid, &kp, &pk);
        mid.push(s);
        for (seq, src) in [(4i64, &base[2]), (5, &base[3])] {
            let prev = mid.last().unwrap()["event_hash"].as_str().unwrap().to_string();
            mid.push(mk_event(seq, src["event_type"].as_str().unwrap(), src["payload"].clone(), &prev));
        }
        let r = run(&mid, None, false);
        assert_eq!(r.status, "COMPROMISED");
        assert!(r.errors.iter().any(|e| e.contains("must be the final event")));
    }

    #[test]
    fn seal_session_hash_must_match_chain_head() {
        let (kp, pk) = keypair();
        let mut evs = sealed(&kp, &pk);
        evs[4].get_mut("payload").unwrap()["session_hash"] = json!("a".repeat(64));
        let h = compute_event_hash(&evs[4]);
        evs[4].insert("event_hash".into(), json!(h.clone()));
        let sig = BASE64.encode(kp.sign(h.as_bytes()).as_ref());
        evs[4].insert("signature".into(), json!(sig));
        let r = run(&evs, Some(&pk), false);
        assert_eq!(r.status, "COMPROMISED");
        assert!(r.errors.iter().any(|e| e.contains("session_hash")));
    }

    #[test]
    fn strict_exit_codes() {
        let (kp, pk) = keypair();
        let r = run(&sealed(&kp, &pk), Some(&pk), false);
        assert_eq!(exit_code_for(&r, true), 0);
        let r = run(&base_session(), None, false);
        assert_eq!(exit_code_for(&r, false), 0);
        assert_eq!(exit_code_for(&r, true), 4);
    }
}
