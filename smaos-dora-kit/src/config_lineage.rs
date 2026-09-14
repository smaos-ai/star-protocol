//! Change Lineage Graph Tracking Before/After Digests and Authorization Authority.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigMutation {
    pub mutation_id: String,
    pub target_component: String,
    pub before_digest: String,
    pub after_digest: String,
    pub change_authority: String,
    pub authorization_permit: String,
    pub applied_at_iso: String,
}

pub struct ConfigLineageGraph {
    pub mutations: Vec<ConfigMutation>,
    pub current_digests: HashMap<String, String>, // target_component -> latest digest
}

impl Default for ConfigLineageGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigLineageGraph {
    pub const GENESIS_CONFIG_HASH: &'static str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    pub fn new() -> Self {
        Self {
            mutations: Vec::new(),
            current_digests: HashMap::new(),
        }
    }

    /// Computes SHA-256 digest of raw configuration / policy payload.
    pub fn compute_digest(payload: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Registers a change mutation and verifies lineage continuity against expected before_digest.
    pub fn record_mutation(
        &mut self,
        mutation_id: &str,
        target_component: &str,
        new_config_payload: &str,
        change_authority: &str,
        authorization_permit: &str,
        timestamp_iso: &str,
    ) -> Result<ConfigMutation, String> {
        let expected_before = self
            .current_digests
            .get(target_component)
            .cloned()
            .unwrap_or_else(|| Self::GENESIS_CONFIG_HASH.to_string());

        let after_digest = Self::compute_digest(new_config_payload);

        // Disallow self-modification or zero-change spam
        if expected_before == after_digest {
            return Err("Zero-delta mutation rejected: after_digest equals before_digest".into());
        }

        let mutation = ConfigMutation {
            mutation_id: mutation_id.to_string(),
            target_component: target_component.to_string(),
            before_digest: expected_before,
            after_digest: after_digest.clone(),
            change_authority: change_authority.to_string(),
            authorization_permit: authorization_permit.to_string(),
            applied_at_iso: timestamp_iso.to_string(),
        };

        self.current_digests
            .insert(target_component.to_string(), after_digest);
        self.mutations.push(mutation.clone());

        Ok(mutation)
    }

    /// Verifies unbroken cryptographic continuity across all mutations for a target component.
    pub fn verify_component_lineage(&self, target_component: &str) -> Result<bool, String> {
        let component_mutations: Vec<&ConfigMutation> = self
            .mutations
            .iter()
            .filter(|m| m.target_component == target_component)
            .collect();

        if component_mutations.is_empty() {
            return Ok(true);
        }

        let mut prev = Self::GENESIS_CONFIG_HASH.to_string();
        for m in component_mutations {
            if m.before_digest != prev {
                return Err(format!(
                    "Lineage breach for {}: mutation {} expected before_digest {}, got {}",
                    target_component, m.mutation_id, prev, m.before_digest
                ));
            }
            prev = m.after_digest.clone();
        }

        Ok(true)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_config_lineage_tracking_and_continuity() {
        let mut graph = ConfigLineageGraph::new();
        let tool = "TOOL_GRANT_CORE_WIRE_TRANSFER";

        // Step 1: Initial grant
        let m1 = graph
            .record_mutation(
                "MUT-001",
                tool,
                "ALLOW_SWIFT_WIRE_LIMIT_1000000",
                "CRO_ALICE",
                "PERMIT-001",
                "2026-09-14T08:00:00Z",
            )
            .unwrap();
        assert_eq!(m1.before_digest, ConfigLineageGraph::GENESIS_CONFIG_HASH);

        // Step 2: Policy limit expansion
        let m2 = graph
            .record_mutation(
                "MUT-002",
                tool,
                "ALLOW_SWIFT_WIRE_LIMIT_2000000",
                "CISO_BOB",
                "PERMIT-002",
                "2026-09-14T08:15:00Z",
            )
            .unwrap();
        assert_eq!(m2.before_digest, m1.after_digest);

        // Verify full lineage
        assert!(graph.verify_component_lineage(tool).unwrap());
    }
}
