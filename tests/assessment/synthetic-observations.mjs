import { createHash } from "node:crypto";
import { digestWithExclusion } from "../../tools/lib/jcs.mjs";
import { WINDOWS_PROTECTION_PROFILE as PROFILE } from "../../src/assessment/windows-protection-profile.mjs";

export function sealObservation(value) {
  value.integrity.object_digest = digestWithExclusion(value, "integrity.object_digest");
  return value;
}

export function syntheticObservations() {
  const payloads = [
    { mode: "Active", real_time_protection: "Disabled" },
    { domain: "Enabled", private: "Enabled", public: "Disabled" },
    { protection: "On", encryption: "FullyEncrypted" },
    { state: "Unknown" }
  ];
  const marker = "SecApp synthetic windows-protection fixture; not machine evidence";
  return PROFILE.domains.map((domain, index) => sealObservation({
    schema_version: "1.0.0",
    observation_id: `91000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
    run_id: "92000000-0000-4000-8000-000000000001",
    execution_id: `93000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
    observed_at: "2026-01-01T00:00:01Z",
    area: domain.area,
    subject: { kind: "SecurityControl", key: domain.subject },
    privacy_class: "SensitiveSecurityData",
    data_schema: domain.schema_id,
    data: { schema_version: "1.0.0", ...payloads[index] },
    evidence_ids: [],
    provenance: {
      source_kind: "SecAppSystem", source_name: "SecApp.Synthetic.WindowsProtection", source_release: "v0.1.0",
      upstream_revision: createHash("sha1").update(marker).digest("hex"),
      source_content_digest: createHash("sha256").update(marker).digest("hex")
    },
    integrity: {
      digest_kind: "ObjectDigest", algorithm: "SHA-256", canonicalization: "JCS-RFC8785", encoding: "LowerHex",
      excluded_fields: ["integrity.object_digest"], object_digest: ""
    }
  }));
}
