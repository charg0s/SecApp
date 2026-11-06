export class AuditPackageImportError extends Error {
  constructor(code, stage, message, status = "Rejected") {
    super(message);
    this.name = "AuditPackageImportError";
    this.code = code;
    this.stage = stage;
    this.status = status;
  }
}

export function reject(code, stage, message, status = "Rejected") {
  throw new AuditPackageImportError(code, stage, message, status);
}

export function unsupported(code, message) {
  reject(code, "Detect", message, "Unsupported");
}

export function isImportError(error) {
  return error instanceof AuditPackageImportError;
}
