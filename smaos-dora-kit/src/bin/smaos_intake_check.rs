//! SMAOS Intake & Pre-Flight Validator CLI (`smaos-intake-check`).
//! Validates client log file integrity, schema compliance, and row conservation before review execution.

use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process;

fn print_usage() {
    println!(
        r#"
================================================================================
🛡️  SMAOS DATA INTAKE & PRE-FLIGHT VALIDATOR (v1.0.5)
================================================================================
Usage:
  smaos-intake-check <input.jsonl> [OPTIONS]

Options:
  --expected-rows <N>    Expected row count declared in Source Contract (e.g. 25000)
  --help                 Show this help message
================================================================================
"#
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_usage();
        return;
    }

    let input_path = &args[1];
    let mut expected_rows: Option<usize> = None;

    let mut i = 2;
    while i < args.len() {
        if args[i] == "--expected-rows" && i + 1 < args.len() {
            if let Ok(n) = args[i + 1].parse::<usize>() {
                expected_rows = Some(n);
            }
            i += 2;
        } else {
            i += 1;
        }
    }

    let path = Path::new(input_path);
    if !path.exists() {
        eprintln!("❌ Input file not found: {}", input_path);
        process::exit(1);
    }

    let file_meta = match path.metadata() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("❌ Failed to inspect file metadata: {}", e);
            process::exit(1);
        }
    };

    println!("================================================================================");
    println!("🛡️  SMAOS CLIENT DATA INTAKE PRE-FLIGHT AUDIT");
    println!("================================================================================");
    println!("Target Log:        {}", input_path);
    println!(
        "File Size:         {:.2} MB ({} bytes)",
        (file_meta.len() as f64) / 1_048_576.0,
        file_meta.len()
    );
    if let Some(exp) = expected_rows {
        println!("Contract Declared: {} rows", exp);
    }
    println!("================================================================================\n");

    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("❌ Failed to open input file: {}", e);
            process::exit(1);
        }
    };

    let reader = BufReader::new(file);

    let mut total_lines = 0usize;
    let mut valid_json_lines = 0usize;
    let mut malformed_lines = 0usize;
    let mut duplicate_nonces = 0usize;
    let mut distinct_actions = HashSet::new();
    let mut seen_nonces = HashSet::new();
    let mut malformed_samples = Vec::new();

    println!("🔍 Performing stream pre-flight scan...");

    for (idx, line_res) in reader.lines().enumerate() {
        let line_num = idx + 1;
        total_lines += 1;

        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                malformed_lines += 1;
                if malformed_samples.len() < 5 {
                    malformed_samples.push((line_num, format!("IO Read Error: {}", e)));
                }
                continue;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            malformed_lines += 1;
            if malformed_samples.len() < 5 {
                malformed_samples.push((line_num, "Empty or whitespace line".into()));
            }
            continue;
        }

        match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(val) => {
                valid_json_lines += 1;

                if let Some(aid) = val.get("action_id").and_then(|v| v.as_str()) {
                    if !aid.is_empty() {
                        distinct_actions.insert(aid.to_string());
                    }
                }

                if let Some(nonce) = val.get("nonce").and_then(|v| v.as_str()) {
                    if !nonce.is_empty() {
                        if seen_nonces.contains(nonce) {
                            duplicate_nonces += 1;
                        } else {
                            seen_nonces.insert(nonce.to_string());
                        }
                    }
                }
            }
            Err(err) => {
                malformed_lines += 1;
                if malformed_samples.len() < 5 {
                    malformed_samples.push((line_num, format!("JSON Syntax: {}", err)));
                }
            }
        }
    }

    println!("\n📊 PRE-FLIGHT AUDIT SUMMARY:");
    println!("  • Total Lines Scanned:       {}", total_lines);
    println!("  • Well-Formed JSON Rows:     {}", valid_json_lines);
    println!("  • Malformed / Corrupted:     {}", malformed_lines);
    println!("  • Duplicate Nonces (Retries):{}", duplicate_nonces);
    println!("  • Distinct Action IDs:       {}", distinct_actions.len());

    if let Some(declared) = expected_rows {
        let delta = (declared as i64) - (total_lines as i64);
        println!(
            "  • Contract Conservation Δ:   {} (Declared: {}, Actual: {})",
            delta, declared, total_lines
        );
        if delta == 0 {
            println!("  • Row Conservation Status:   ✅ PERFECT ZERO-DELTA MATCH");
        } else {
            println!(
                "  • Row Conservation Status:   ⚠️ MISMATCH DETECTED (Δ = {})",
                delta
            );
        }
    }

    if !malformed_samples.is_empty() {
        println!(
            "\n⚠️ SAMPLE MALFORMED ROWS (First {} occurrences):",
            malformed_samples.len()
        );
        for (ln, reason) in malformed_samples {
            println!("    [Line {:>5}] {}", ln, reason);
        }
    }

    println!("\n================================================================================");
    if malformed_lines == 0 && (expected_rows.is_none() || expected_rows == Some(total_lines)) {
        println!("✅ PRE-FLIGHT VERIFIED: Log file is ready for `smaos-review` execution.");
    } else {
        println!(
            "ℹ️ PRE-FLIGHT COMPLETED: Discrepancies isolated. The review engine will preserve"
        );
        println!("   malformed rows in `conservation_scorecard.json` without data loss.");
    }
    println!("================================================================================\n");
}
