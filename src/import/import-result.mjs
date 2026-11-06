import { createHash } from "node:crypto";

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function contractCounts(subjects) {
  const counts = new Map();
  for (const subject of subjects) counts.set(subject.contractKind, (counts.get(subject.contractKind) ?? 0) + 1);
  return Object.fromEntries([...counts.entries()].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0));
}

export function acceptedResult({ packageKind, privacyMode, subjects, sourceBytes, sourceDigest, finalLineTerminated, zip, opaqueMemberCount = 0 }) {
  const result = {
    import_result_version: 1,
    status: "Accepted",
    package_kind: packageKind,
    validation: {
      container: "Passed",
      strict_json: "Passed",
      reference_schema: "Passed",
      digests: "Passed",
      references: packageKind === "AuditPackageZip" ? "Passed" : "Standalone"
    },
    summary: {
      privacy_mode: privacyMode,
      source_bytes: sourceBytes,
      source_file_digest: sourceDigest,
      imported_object_count: subjects.length,
      contract_counts: contractCounts(subjects),
      opaque_member_count: opaqueMemberCount,
      integrity_claim: "ModificationDetectionOnly",
      provenance_claim: "NotEstablished"
    }
  };
  if (packageKind === "JsonLines") {
    result.summary.jsonl_final_lf_policy = finalLineTerminated ? "Present" : "AbsentAllowed";
  }
  if (zip) {
    result.summary.archive_entry_count = zip.entryCount;
    result.summary.archive_expanded_bytes = zip.expandedBytes;
  }
  if (privacyMode === "Private") {
    result.objects = subjects.map((subject) => ({
      contract_kind: subject.contractKind,
      schema_id: subject.schemaId,
      role: subject.role,
      logical_path: subject.logicalPath,
      record_index: subject.recordIndex,
      byte_size: subject.byteSize,
      file_digest: subject.fileDigest,
      value: structuredClone(subject.value)
    }));
  }
  return result;
}

export function rejectedResult(error, packageKind = null) {
  return {
    import_result_version: 1,
    status: error.status ?? "Rejected",
    package_kind: packageKind,
    error: {
      code: error.code,
      stage: error.stage,
      message: error.message
    },
    summary: {
      integrity_claim: "NotEstablished",
      provenance_claim: "NotEstablished"
    }
  };
}
