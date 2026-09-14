use smaos_dora_kit::scenario::DoraScenarioGenerator;
use std::fs;

fn main() {
    let bundle = DoraScenarioGenerator::generate_canonical_ghost_incident()
        .expect("Failed to generate ghost incident scenario");
    let json_str =
        serde_json::to_string_pretty(&bundle).expect("Failed to serialize bundle to JSON");
    fs::write("dora_tabletop_bundle.json", &json_str)
        .expect("Failed to write dora_tabletop_bundle.json");
    println!(
        "Exported dora_tabletop_bundle.json ({} bytes, {} events, final hash: {})",
        json_str.len(),
        bundle.total_events,
        bundle.final_hash
    );
}
