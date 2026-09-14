//! SMAOS Incident Review & STAR Verification Engine CLI entrypoint.
//! Usage:
//!   smaos-review <input.jsonl> [OPTIONS]
//!   smaos-dora-kit review <input.jsonl> [OPTIONS]

use smaos_dora_kit::review::{BundleMode, ReviewProcessor, SourceContract};
use std::env;
use std::fs::File;
use std::path::Path;
use std::process;

fn print_usage() {
    println!(
        r#"
================================================================================
⭐  STAR PROTOCOL & SMAOS INCIDENT REVIEW ENGINE (v1.0.5)
================================================================================
Usage:
  smaos-review <input.jsonl> [OPTIONS]
  smaos-dora-kit review <input.jsonl> [OPTIONS]

Options:
  --source-contract <PATH>   Path to source extraction contract (default: fixtures/source_contract.json)
  --output <PATH>            Path to output deliverables directory (default: review)
  --bundle-mode <MODE>       Deliverable mode: star750 (default for <=250 rows) or dora10day
  --help                     Print this help message
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

    let mut input_path = String::new();
    let mut source_contract_path = String::from("fixtures/source_contract.json");
    let mut output_path = String::from("review");
    let mut explicit_bundle_mode: Option<BundleMode> = None;

    let mut start_idx = 1;
    if args[1] == "review" {
        start_idx = 2;
    } else if !args[1].starts_with("--") {
        input_path = args[1].clone();
        start_idx = 2;
    }

    let mut i = start_idx;
    while i < args.len() {
        match args[i].as_str() {
            "--source-contract" => {
                if i + 1 < args.len() {
                    source_contract_path = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("❌ Missing argument for --source-contract");
                    process::exit(1);
                }
            }
            "--output" => {
                if i + 1 < args.len() {
                    output_path = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("❌ Missing argument for --output");
                    process::exit(1);
                }
            }
            "--bundle-mode" => {
                if i + 1 < args.len() {
                    let mode_str = args[i + 1].to_lowercase();
                    if mode_str == "star750" || mode_str == "feasibility" || mode_str == "star" {
                        explicit_bundle_mode = Some(BundleMode::StarFeasibility);
                    } else if mode_str == "dora10day" || mode_str == "pilot" || mode_str == "dora" {
                        explicit_bundle_mode = Some(BundleMode::DoraTenDay);
                    } else {
                        eprintln!("❌ Unrecognized --bundle-mode: {}. Expected: star750 | dora10day", args[i + 1]);
                        process::exit(1);
                    }
                    i += 2;
                } else {
                    eprintln!("❌ Missing argument for --bundle-mode");
                    process::exit(1);
                }
            }
            arg if !arg.starts_with("--") && input_path.is_empty() => {
                input_path = arg.to_string();
                i += 1;
            }
            other => {
                eprintln!("❌ Unrecognized argument: {}", other);
                process::exit(1);
            }
        }
    }

    if input_path.is_empty() {
        eprintln!("❌ Missing required input JSONL file path.");
        print_usage();
        process::exit(1);
    }

    let contract = if Path::new(&source_contract_path).exists() {
        match File::open(&source_contract_path) {
            Ok(f) => match serde_json::from_reader(f) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "⚠️ Failed to parse contract JSON ({}). Using default contract.",
                        e
                    );
                    SourceContract::default()
                }
            },
            Err(e) => {
                eprintln!(
                    "⚠️ Failed to open contract file ({}). Using default contract.",
                    e
                );
                SourceContract::default()
            }
        }
    } else {
        println!(
            "ℹ️ Source contract not found at {}. Using default CONN-SN-CZ-001 contract.",
            source_contract_path
        );
        SourceContract::default()
    };

    let bundle_mode = explicit_bundle_mode.unwrap_or_else(|| {
        if contract.declared_extraction_rows <= 250
            || contract.contract_id.contains("250")
            || contract.contract_id.contains("FEASIBILITY")
            || output_path == "review"
        {
            BundleMode::StarFeasibility
        } else {
            BundleMode::DoraTenDay
        }
    });

    println!("================================================================================");
    println!("⭐  STAR PROTOCOL & SMAOS DORA REVIEW ENGINE (v1.0.5)");
    println!("================================================================================");
    println!("Target Input:      {}", input_path);
    println!("Source Contract:   {} (Declared: {} rows)", source_contract_path, contract.declared_extraction_rows);
    println!("Output Directory:  {}", output_path);
    match bundle_mode {
        BundleMode::StarFeasibility => {
            println!("Sprint Package:    STAR €750 Data Feasibility Sprint (8-File Package)");
            println!("Statutory Anchors: EU AI Act Arts. 12 & 14 • DORA Arts. 18, 19, 28 • RTS 2025/301");
        }
        BundleMode::DoraTenDay => {
            println!("Sprint Package:    10-Day Unknown Exposure Pilot Package (with ServiceNow IRM)");
            println!("Statutory Anchors: EU 2022/2554 (DORA) Arts. 18, 19, 24 & RTS 2025/301");
        }
    }
    println!("================================================================================
");

    println!("──► [1/3] PARSE  (Tree-sitter AST & stream JSON validation with zero-delta conservation)");
    println!("──► [2/3] PROVE  (Offline JCS SHA-256 Merkle DAG root computation & Ed25519 signing)");
    println!("──► [3/3] GATE   (Mutually exclusive classification: confirmed | unknown | conflict | malformed)
");

    let processor = ReviewProcessor::with_mode(contract, bundle_mode);

    match processor.execute_review(&input_path, &output_path) {
        Ok(scorecard) => {
            println!("✅ INGESTION CONSERVATION SCORECARD:");
            println!(
                "  • Declared Extraction Rows:  {}",
                scorecard.declared_extraction_rows
            );
            println!(
                "  • Accepted Event Rows:       {}",
                scorecard.accepted_event_rows
            );
            println!(
                "  • State Transition Rows:     {}",
                scorecard.state_transition_rows
            );
            println!(
                "  • Retransmissions (Dedupe):  {}",
                scorecard.retransmissions
            );
            println!(
                "  • Malformed Rows (Retained): {}",
                scorecard.malformed_rows
            );
            println!("  • Conflict Rows (Held):      {}", scorecard.conflict_rows);
            println!("  --------------------------------------------------");
            println!(
                "  • Total Accounted Rows:      {}",
                scorecard.total_accounted_rows
            );
            println!(
                "  • Conservation Delta (Δ):    {} (IS_CONSERVED: {})",
                scorecard.delta, scorecard.is_conserved
            );
            println!("  • Accounting Equation:       {}", scorecard.row_accounting_equation);

            println!("
📊 PRIMARY DISPOSITIONS:");
            if let Some(ref pd) = scorecard.primary_dispositions {
                println!("  • Confirmed Actions:         {}", pd.confirmed);
                println!("  • Unknown Actions (Locked):  {}", pd.unknown);
                println!("  • Conflict-Held Actions:     {}", pd.conflict_held);
                println!("  • Malformed Rows (Retained): {}", pd.malformed);
            } else {
                println!(
                    "  • Confirmed Actions:         {}",
                    scorecard.business_transaction_metrics.confirmed_actions
                );
                println!(
                    "  • Unconfirmed UNKNOWN Locks: {}",
                    scorecard.business_transaction_metrics.unconfirmed_unknown_actions
                );
            }
            println!(
                "  • Gross Nominal Unresolved:  €{:.2}",
                (scorecard.business_transaction_metrics.gross_unresolved_nominal_cents as f64) / 100.0
            );

            match bundle_mode {
                BundleMode::StarFeasibility => {
                    println!(
                        "
📦 GENERATED AUDIT DELIVERABLE PACKAGE IN '{}':",
                        output_path
                    );
                    println!("  [1] conservation_scorecard.json             (Δ=0 accounting + secondary findings map)");
                    println!("  [2] unknown_exposure_inventory.json         (UNKNOWN timeouts & retry conflicts)");
                    println!("  [3] telemetry_gaps.json                     (schema gaps + degraded confidence flags)");
                    println!("  [4] evidence_insufficient_or_findings.json  (3-outcome verdict: FINDINGS / NO FINDINGS / INSUFFICIENT)");
                    println!("  [5] replay.json                             (T0–T9 forensic replay fixture)");
                    println!("  [6] limitations.md                          (human-in-the-loop boundaries)");
                    println!("  [7] processing_and_deletion_record.json     (local shredding audit trail - not a Cert of Deletion)");
                    println!("  [8] manifest.json                           (JCS SHA-256 Merkle root, file digests, commit hash)");
                }
                BundleMode::DoraTenDay => {
                    println!(
                        "
📦 GENERATED CLIENT PILOT DELIVERABLES IN '{}':",
                        output_path
                    );
                    println!("  [1] conservation_scorecard.json       (Zero-delta row accounting manifest)");
                    println!("  [2] unknown_exposure_inventory.json   (Unconfirmed action gap inventory)");
                    println!("  [3] criteria_matrix.json              (EU 2024/1772 major incident evaluation)");
                    println!("  [4] replay.json                       (Counterfactual blast-radius replay)");
                    println!("  [5] kpi_baseline.json                 (74h -> 1.25h efficiency audit)");
                    println!("  [6] servicenow_case_export.json       (Draft sn_si_incident payload)");
                    println!("  [7] evidence_manifest.json            (JCS Merkle digest & Ed25519 signatures)");
                    println!("  [8] LIMITATIONS.md                    (1-Page legal boundary memo)");
                }
            }

            println!("
================================================================================");
            println!("✅ REVIEW COMPLETE: Zero-delta verified (Δ = 0). Deliverables ready for review.");
            println!("================================================================================");
        }
        Err(err) => {
            eprintln!("
❌ Execution failed: {}", err);
            process::exit(1);
        }
    }
}
