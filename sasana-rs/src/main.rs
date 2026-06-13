/*!
 * sasana — Tamper-Evident Audit Verifier for OpenClaw sessions
 *
 * Usage:
 *   sasana verify <session.jsonl>         Verify hash chain integrity
 *   sasana verify <session.jsonl> --json  JSON output
 *
 * Exit codes:
 *   0  INTACT      — chain is valid, no drops
 *   1  COMPROMISED — hash chain has integrity violations
 *   2  PARTIAL     — valid chain but LOG_DROP events present
 *   3  ERROR       — file not found, malformed JSONL, or missing fields
 *
 * Hash algorithm: SHA-256 over RFC 8785 canonical JSON of each event
 * (excluding the event_hash field itself), chained via prev_hash.
 * This must match sasana/envelope.py exactly.
 */

use hex::encode as hex_encode;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::process;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const VERIFIER_VERSION: &str = "1.0.0";

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
    verifier_version: String,
}

// ---------------------------------------------------------------------------
// Core verifier
// ---------------------------------------------------------------------------

fn verify_file(path: &str) -> VerifyResult {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return error_result(format!("Cannot read '{}': {}", path, e)),
    };

    let mut raw_events: Vec<Map<String, Value>> = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(trimmed) {
            Ok(Value::Object(map)) => raw_events.push(map),
            Ok(_) => return error_result(format!("Line {}: not a JSON object", i + 1)),
            Err(e) => return error_result(format!("Line {}: JSON parse error: {}", i + 1, e)),
        }
    }

    if raw_events.is_empty() {
        return error_result("File is empty or contains no JSON objects".to_string());
    }

    let event_count = raw_events.len();
    let mut errors: Vec<String> = Vec::new();
    let mut log_drop_count = 0usize;
    let mut session_id: Option<String> = None;
    let mut last_hash = GENESIS_HASH.to_string();
    let mut root_hash: Option<String> = None;

    // Check 1: structural validity
    let required = ["seq", "event_type", "session_id", "timestamp", "payload", "prev_hash", "event_hash"];
    for event_map in &raw_events {
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
    for event_map in &raw_events {
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

    // Check 4: session bookends and evidence class
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
        || has_chain_seal && !has_session_end; // CHAIN_SEAL alone is an acceptable closing marker
    if !closing_ok {
        errors.push(format!(
            "Session must end with SESSION_END or CHAIN_SEAL, found '{}'",
            last_type
        ));
    }

    let (status, evidence_class) = if !errors.is_empty() {
        ("COMPROMISED".to_string(), "NO_EVIDENCE".to_string())
    } else if log_drop_count > 0 {
        ("PARTIAL".to_string(), "PARTIAL_EVIDENCE".to_string())
    } else if has_chain_seal {
        ("INTACT".to_string(), "AUTHORITATIVE_EVIDENCE".to_string())
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
        verifier_version: VERIFIER_VERSION.to_string(),
    }
}

fn error_result(msg: String) -> VerifyResult {
    VerifyResult {
        status: "ERROR".to_string(),
        evidence_class: "NONE".to_string(),
        session_id: None,
        event_count: 0,
        log_drop_count: 0,
        root_hash: None,
        errors: vec![msg],
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
    println!();

    let pass = "PASS";
    let fail = "FAIL";
    let hash_ok    = !result.errors.iter().any(|e| e.contains("hash mismatch") || e.contains("prev_hash"));
    let seq_ok     = !result.errors.iter().any(|e| e.contains("Sequence gap"));
    let struct_ok  = !result.errors.iter().any(|e| e.contains("missing required"));
    let bookend_ok = !result.errors.iter().any(|e| e.contains("SESSION_START") || e.contains("SESSION_END"));

    println!("Check 1 — Structural validity ......... {}", if struct_ok  { pass } else { fail });
    println!("Check 2 — Sequence continuity ......... {}", if seq_ok     { pass } else { fail });
    println!("Check 3 — Hash chain integrity ........ {}", if hash_ok    { pass } else { fail });
    println!("Check 4 — Session bookends ............ {}", if bookend_ok { pass } else { fail });
    println!("Check 5 — Log drop analysis ........... {} ({} drops)", pass, result.log_drop_count);
    println!();

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
    eprintln!("  sasana verify <session.jsonl>          Verify session hash chain");
    eprintln!("  sasana verify <session.jsonl> --json   JSON output");
    eprintln!();
    eprintln!("EXIT CODES:");
    eprintln!("  0  INTACT      — chain is valid");
    eprintln!("  1  COMPROMISED — chain has integrity violations");
    eprintln!("  2  PARTIAL     — valid but LOG_DROP events present");
    eprintln!("  3  ERROR       — file unreadable or malformed");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        usage();
        process::exit(3);
    }

    match args[1].as_str() {
        "verify" => {
            if args.len() < 3 {
                eprintln!("Usage: sasana verify <session.jsonl> [--json]");
                process::exit(3);
            }
            let path = &args[2];
            let json_output = args.iter().any(|a| a == "--json");
            let result = verify_file(path);
            let exit_code = match result.status.as_str() {
                "INTACT"      => 0,
                "COMPROMISED" => 1,
                "PARTIAL"     => 2,
                _             => 3,
            };
            if json_output {
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            } else {
                print_human(&result, path);
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
        let r = error_result("test error".to_string());
        assert_eq!(r.status, "ERROR");
        assert_eq!(r.event_count, 0);
    }
}
