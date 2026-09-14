/**
 * Offline Client-Side RFC 8785 JCS & SHA-256 Merkle Chain Verifier.
 * Zero-dependency Node.js / Browser verification script.
 */

const fs = require("fs");
const crypto = require("crypto");

function canonicalizeJCS(val) {
  if (val === null) return "null";
  if (typeof val === "boolean") return val ? "true" : "false";
  if (typeof val === "number") return val.toString();
  if (typeof val === "string") return JSON.stringify(val);
  if (Array.isArray(val)) {
    return "[" + val.map(canonicalizeJCS).join(",") + "]";
  }
  if (typeof val === "object") {
    const keys = Object.keys(val).sort();
    return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalizeJCS(val[k])).join(",") + "}";
  }
  return JSON.stringify(String(val));
}

function computeEventHash(actionId, sequence, eventKind, prevHash) {
  const enc = new TextEncoder();
  const actionBytes = enc.encode(actionId);
  const seqBuf = new ArrayBuffer(8);
  new DataView(seqBuf).setBigUint64(0, BigInt(sequence), false); // Big-endian
  const seqBytes = new Uint8Array(seqBuf);
  const jcsBytes = enc.encode(canonicalizeJCS(eventKind));
  const prevBytes = enc.encode(prevHash);

  const combined = Buffer.concat([actionBytes, seqBytes, jcsBytes, prevBytes]);
  return crypto.createHash("sha256").update(combined).digest("hex");
}

function verifyBundle(filePath) {
  console.log(`Verifying bundle: ${filePath}...`);
  const data = JSON.parse(fs.readFileSync(filePath, "utf8"));
  let prev = "0000000000000000000000000000000000000000000000000000000000000000";

  for (let i = 0; i < data.events.length; i++) {
    const ev = data.events[i];
    if (ev.prev_hash !== prev) {
      console.error(`❌ Chain broken: prev_hash mismatch at sequence ${ev.sequence}`);
      process.exit(1);
    }
    const computed = computeEventHash(ev.action_id, ev.sequence, ev.event_kind, prev);
    if (computed !== ev.event_hash) {
      console.error(`❌ Hash mismatch at sequence ${ev.sequence}: expected ${ev.event_hash}, computed ${computed}`);
      process.exit(1);
    }
    prev = ev.event_hash;
    console.log(`  [OK] Seq ${ev.sequence}: ${ev.event_kind.type} (${ev.event_hash.substring(0, 16)}...)`);
  }

  console.log(`\n✅ MERKLE CHAIN VERIFIED: ${data.events.length}/${data.events.length} events valid.`);
  console.log(`Root Digest: ${prev}`);
}

const bundlePath = process.argv[2] || "dist/dora_tabletop_bundle.json";
if (fs.existsSync(bundlePath)) {
  verifyBundle(bundlePath);
} else {
  console.log(`Bundle not found at ${bundlePath}, skipping.`);
}
