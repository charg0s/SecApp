import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateRawSync } from "node:zlib";

const probePath = fileURLToPath(new URL("./zip-package-probe.mjs", import.meta.url));

function fail(message) {
  throw new Error(message);
}

const crcTable = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) value = (value >>> 1) ^ ((value & 1) ? 0xedb88320 : 0);
    table[index] = value >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = (crc >>> 8) ^ crcTable[(crc ^ byte) & 0xff];
  return (crc ^ 0xffffffff) >>> 0;
}

function u16(value) {
  const result = Buffer.alloc(2);
  result.writeUInt16LE(value);
  return result;
}

function u32(value) {
  const result = Buffer.alloc(4);
  result.writeUInt32LE(value >>> 0);
  return result;
}

function buildZip(entries) {
  const localParts = [];
  const centralParts = [];
  let localOffset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, "utf8");
    const data = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data ?? "", "utf8");
    const method = entry.method ?? 0;
    const compressed = method === 8 ? deflateRawSync(data) : data;
    const crc = crc32(data);
    const local = Buffer.concat([
      u32(0x04034b50), u16(20), u16(0x0800), u16(method), u16(0), u16(0),
      u32(crc), u32(compressed.length), u32(data.length), u16(name.length), u16(0), name, compressed,
    ]);
    localParts.push(local);
    const versionMadeBy = entry.versionMadeBy ?? ((3 << 8) | 20);
    const externalAttributes = entry.externalAttributes ?? 0;
    centralParts.push(Buffer.concat([
      u32(0x02014b50), u16(versionMadeBy), u16(20), u16(0x0800), u16(method), u16(0), u16(0),
      u32(crc), u32(compressed.length), u32(data.length), u16(name.length), u16(0), u16(0),
      u16(0), u16(0), u32(externalAttributes), u32(localOffset), name,
    ]));
    localOffset += local.length;
  }
  const central = Buffer.concat(centralParts);
  const eocd = Buffer.concat([
    u32(0x06054b50), u16(0), u16(0), u16(entries.length), u16(entries.length),
    u32(central.length), u32(localOffset), u16(0),
  ]);
  return Buffer.concat([...localParts, central, eocd]);
}

function runProbe(argumentsArray) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, [probePath, ...argumentsArray], {
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.once("error", rejectPromise);
    child.once("close", (code, signal) => resolvePromise({
      code,
      signal,
      stdout: Buffer.concat(stdout).toString("utf8"),
      stderr: Buffer.concat(stderr).toString("utf8"),
    }));
  });
}

async function main() {
  const root = await mkdtemp(join(tmpdir(), "secapp-zip-probe-"));
  const valid = buildZip([{ name: "results.json", data: '[{"synthetic":true}]' }]);
  const corruptCrc = Buffer.from(valid);
  corruptCrc[30 + Buffer.byteLength("results.json", "utf8")] ^= 0x01;
  const cases = [
    { name: "valid", bytes: valid, arguments: [], valid: true },
    { name: "duplicate-path", bytes: buildZip([{ name: "same.json", data: "[]" }, { name: "same.json", data: "[]" }]), arguments: [], error: "Duplicate or case-colliding" },
    { name: "case-collision", bytes: buildZip([{ name: "A.json", data: "[]" }, { name: "a.json", data: "[]" }]), arguments: [], error: "Duplicate or case-colliding" },
    { name: "absolute-path", bytes: buildZip([{ name: "/absolute.json", data: "[]" }]), arguments: [], error: "Absolute ZIP entry path" },
    { name: "drive-path", bytes: buildZip([{ name: "C:/absolute.json", data: "[]" }]), arguments: [], error: "Absolute ZIP entry path" },
    { name: "traversal", bytes: buildZip([{ name: "../escape.json", data: "[]" }]), arguments: [], error: "traversal or ambiguous" },
    { name: "backslash", bytes: buildZip([{ name: "dir\\file.json", data: "[]" }]), arguments: [], error: "Backslash" },
    { name: "symlink", bytes: buildZip([{ name: "link", data: "target", externalAttributes: (0xa1ff << 16) >>> 0 }]), arguments: [], error: "symlink" },
    { name: "entry-count", bytes: buildZip([{ name: "1", data: "" }, { name: "2", data: "" }, { name: "3", data: "" }]), arguments: ["--max-entries", "2"], error: "entry count exceeds" },
    { name: "individual-size", bytes: buildZip([{ name: "large", data: "x".repeat(20) }]), arguments: ["--max-entry-bytes", "10"], error: "individual expanded size" },
    { name: "total-size", bytes: buildZip([{ name: "one", data: "x".repeat(8) }, { name: "two", data: "x".repeat(8) }]), arguments: ["--max-expanded-bytes", "10"], error: "total expanded size" },
    { name: "compression-ratio", bytes: buildZip([{ name: "compressed", data: "x".repeat(4096), method: 8 }]), arguments: ["--max-ratio", "10"], error: "compression ratio" },
    { name: "crc-corrupt", bytes: corruptCrc, arguments: [], error: "CRC mismatch" },
    { name: "truncated", bytes: valid.subarray(0, valid.length - 1), arguments: [], error: "end-of-central-directory" },
  ];
  const results = [];
  try {
    for (const testCase of cases) {
      const input = join(root, `${testCase.name}.zip`);
      await writeFile(input, testCase.bytes, { flag: "wx" });
      const observed = await runProbe(["--input", input, ...testCase.arguments]);
      if (testCase.valid) {
        if (observed.code !== 0 || observed.signal !== null) fail(`${testCase.name}: expected valid ZIP: ${observed.stderr}`);
        const parsed = JSON.parse(observed.stdout);
        if (parsed.status !== "VALID" || parsed.central_directory.entry_count !== 1) fail(`${testCase.name}: valid summary mismatch`);
        results.push({ name: testCase.name, status: "PASS", exit_code: 0, entry_count: 1 });
      } else {
        if (observed.code === 0 || !observed.stderr.includes(testCase.error)) {
          fail(`${testCase.name}: expected rejection containing ${JSON.stringify(testCase.error)}; received ${observed.stderr}`);
        }
        results.push({ name: testCase.name, status: "PASS", exit_code: observed.code, error_class: testCase.error });
      }
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
  process.stdout.write(`${JSON.stringify({
    status: "PASS",
    cases: results.length,
    temporary_archives_removed: true,
    results,
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`test-zip-package-probe: ${error.message}\n`);
  process.exitCode = 1;
});
