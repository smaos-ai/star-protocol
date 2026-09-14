#!/usr/bin/env python3
"""
STAR Decadal Core (v1.0) — star legacy verify
Merge gate verifier: inspects current AST Merkle root against .star/golden_baseline.json.
Supports --policy strict|permissive, --pr <num>, --offline, and --target-languages flags.
"""

import sys
import json
import ast
import hashlib
import argparse
from pathlib import Path
from typing import Dict, List, Any, Tuple


class StarLegacyVerify:
    def __init__(self, workspace_path: str = ".", target_languages: str = "py,rs,ts,js"):
        self.workspace = Path(workspace_path).resolve()
        self.star_dir = self.workspace / ".star"
        self.baseline_file = self.star_dir / "golden_baseline.json"
        self.exts = tuple(f".{e.strip().lstrip('.')}" for e in target_languages.split(","))

    def scan_ast_nodes(self) -> List[Dict[str, Any]]:
        """Parse current codebase AST nodes."""
        nodes = []
        target_dirs = [self.workspace / "smaos", self.workspace / "star_protocol", self.workspace / "scripts", self.workspace / "crates", self.workspace / "smaos-dora-kit"]
        
        for tdir in target_dirs:
            if not tdir.exists():
                continue
            for file_path in tdir.rglob("*"):
                if file_path.is_file() and file_path.suffix in self.exts:
                    if any(part in file_path.relative_to(self.workspace).parts for part in ["__pycache__", "target", "node_modules"]):
                        continue
                    try:
                        rel_path = file_path.relative_to(self.workspace).as_posix()
                        content = file_path.read_bytes()
                        file_hash = hashlib.sha256(content).hexdigest()

                        funcs_count = 0
                        classes_count = 0
                        classes_list = []

                        if file_path.suffix == ".py":
                            try:
                                text_content = content.decode("utf-8", errors="ignore")
                                tree = ast.parse(text_content, filename=rel_path)
                                funcs_count = len([n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)])
                                classes_list = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
                                classes_count = len(classes_list)
                            except Exception:
                                pass

                        leaf_data = f"{rel_path}:{file_hash}:{funcs_count}:{classes_count}"
                        leaf_hash = hashlib.sha256(leaf_data.encode("utf-8")).hexdigest()

                        nodes.append({
                            "file": rel_path,
                            "hash": file_hash,
                            "leaf_hash": leaf_hash,
                            "classes": classes_list,
                            "functions_count": funcs_count
                        })
                    except Exception:
                        pass

        nodes.sort(key=lambda x: x["file"])
        return nodes

    def compute_merkle_root(self, nodes: List[Dict[str, Any]]) -> str:
        """Compute Merkle Tree root over all AST node leaf hashes."""
        hashes = [n["leaf_hash"] for n in nodes]
        if not hashes:
            return hashlib.sha256(b"empty_baseline").hexdigest()

        while len(hashes) > 1:
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])
            next_level = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i + 1]
                next_level.append(hashlib.sha256(combined.encode("utf-8")).hexdigest())
            hashes = next_level

        return hashes[0]

    def verify_merge(self, policy: str = "strict", pr_num: str = "") -> Tuple[bool, Dict[str, Any]]:
        """Verify current workspace against .star/golden_baseline.json."""
        if not self.baseline_file.exists():
            return False, {"error": f"Golden baseline receipt '{self.baseline_file}' missing. Run 'star legacy freeze' first."}

        try:
            baseline_data = json.loads(self.baseline_file.read_text(encoding="utf-8"))
        except Exception as e:
            return False, {"error": f"Failed to parse golden baseline JSON: {e}"}

        if "_type" in baseline_data:
            # Article 12 in-toto format
            baseline_merkle = baseline_data["subject"][0]["digest"]["sha256"]
            signature = baseline_data["predicate"]["eu_ai_act_article_12"]["operator_attestation"]
            baseline_nodes = baseline_data["predicate"]["ast_node_count"]
        else:
            baseline_merkle = baseline_data.get("merkle_root")
            signature = baseline_data.get("signature")
            baseline_nodes = baseline_data.get("ast_node_count", 0)

        current_nodes = self.scan_ast_nodes()
        current_merkle = self.compute_merkle_root(current_nodes)

        is_valid = (current_merkle == baseline_merkle)
        if not is_valid and policy == "permissive":
            # Permissive policy warns but passes
            is_valid = True

        diff_info = {
            "pr_number": pr_num if pr_num else "LOCAL_HEAD",
            "policy": policy,
            "baseline_merkle": baseline_merkle[:32] + "..." if baseline_merkle else "UNKNOWN",
            "current_merkle": current_merkle[:32] + "...",
            "baseline_nodes": baseline_nodes,
            "current_nodes": len(current_nodes),
            "signature": signature,
            "status": "PASSED" if (current_merkle == baseline_merkle) else ("WARNING_PERMISSIVE" if policy == "permissive" else "MUTATION_DETECTED")
        }

        return is_valid, diff_info


def main():
    parser = argparse.ArgumentParser(description="STAR Decadal Core — star legacy verify (Merge Gate)")
    parser.add_argument("--repo", type=str, default=".", help="Path to repository root")
    parser.add_argument("--pr", type=str, default="", help="Pull request number or ID")
    parser.add_argument("--policy", type=str, choices=["strict", "permissive"], default="strict", help="Enforcement policy (strict or permissive)")
    parser.add_argument("--target-languages", type=str, default="py,rs,ts,js", help="Comma-separated target language extensions")
    parser.add_argument("--offline", action="store_true", default=True, help="Run offline without external network sockets")
    args = parser.parse_args()

    verifier = StarLegacyVerify(workspace_path=args.repo, target_languages=args.target_languages)
    success, info = verifier.verify_merge(policy=args.policy, pr_num=args.pr)

    print("\n" + "="*70)
    print("🛡️  STAR DECADAL CORE — star legacy verify (Merge Gate)")
    print("="*70)
    print(f"Target PR:               {info.get('pr_number')}")
    print(f"Policy:                  {info.get('policy').upper()}")
    print(f"Offline Mode:            {args.offline}")
    print(f"Golden Baseline Merkle:  {info.get('baseline_merkle')}")
    print(f"Current Execution Merkle: {info.get('current_merkle')}")
    print(f"Node Count (Base/Curr):  {info.get('baseline_nodes')} / {info.get('current_nodes')}")
    print(f"Ed25519 Signature:       {info.get('signature')}")
    print("="*70)

    if success and info.get("status") == "PASSED":
        print("✅ MERGE GATE PASSED: AST structure matches Golden Baseline 100 percent. Ready to merge.")
        print("="*70 + "\n")
        sys.exit(0)
    elif success and info.get("status") == "WARNING_PERMISSIVE":
        print("⚠️  MERGE GATE PASSED (PERMISSIVE POLICY): AST mutation detected but allowed by policy.")
        print("="*70 + "\n")
        sys.exit(0)
    else:
        print("❌ MERGE GATE FAILED: AST mutation or structural drift detected!")
        print("   Pull Request merge BLOCKED under strict security policy.")
        print("="*70 + "\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
