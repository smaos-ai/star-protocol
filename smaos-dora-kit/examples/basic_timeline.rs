//! Minimal Timeline Reconstruction Example.

use smaos_dora_kit::scenario::DoraScenarioGenerator;
use smaos_dora_kit::timeline::{DoraTimelineReconstructor, EvidenceConfidence};

fn main() {
    println!("Loading canonical ghost incident scenario...");
    let bundle = DoraScenarioGenerator::generate_canonical_ghost_incident()
        .expect("Failed to generate scenario");

    println!("Reconstructing T0–T9 timeline for action: ACT-SWIFT-9901\n");
    let timeline =
        DoraTimelineReconstructor::reconstruct_timeline("ACT-SWIFT-9901", &bundle.events);

    let mut has_telemetry_gap = false;
    for phase in &timeline.phases {
        let wall = phase
            .timestamp_wall_iso
            .as_deref()
            .unwrap_or("MISSING_TIMESTAMP");
        println!(
            "[{}] {:<32} (Evidence: {:<8?}) — Wall: {}",
            phase.phase_code, phase.phase_name, phase.confidence, wall
        );
        if phase.confidence == EvidenceConfidence::Missing {
            has_telemetry_gap = true;
        }
    }

    if has_telemetry_gap {
        println!("\n⚠️  TELEMETRY GAP IDENTIFIED: Missing external ledger confirmation detected.");
    }
    if let Some(secs) = timeline.total_uncertainty_window_seconds {
        println!(
            "⏱️  TOTAL UNCERTAINTY WINDOW: {:.2} seconds before dual-control recovery.",
            secs
        );
    }
}
