import {
  constants,
  createHash,
  createPublicKey,
  createVerify,
} from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { basename } from "node:path";

const MAX_SIGNATURE_BYTES = 1024 * 1024;
const MAX_KEYRING_BYTES = 4 * 1024 * 1024;
const MAX_DATA_BYTES = 1024 * 1024 * 1024;

function fail(message) {
  throw new Error(message);
}

function parseArguments(argv) {
  const result = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith("--") || value === undefined) {
      fail("Usage: --data FILE --signature FILE --keyring FILE --expected-fingerprint HEX --expected-sha256 HEX");
    }
    if (result.has(name)) {
      fail(`Duplicate argument: ${name}`);
    }
    result.set(name, value);
  }

  const required = [
    "--data",
    "--signature",
    "--keyring",
    "--expected-fingerprint",
    "--expected-sha256",
  ];
  for (const name of required) {
    if (!result.has(name)) {
      fail(`Missing argument: ${name}`);
    }
  }
  return result;
}

function readUint32(buffer, offset) {
  if (offset + 4 > buffer.length) {
    fail("Truncated OpenPGP length");
  }
  return buffer.readUInt32BE(offset);
}

function parseNewLength(buffer, offset) {
  if (offset >= buffer.length) {
    fail("Truncated OpenPGP packet length");
  }
  const first = buffer[offset];
  if (first < 192) {
    return { length: first, nextOffset: offset + 1 };
  }
  if (first <= 223) {
    if (offset + 1 >= buffer.length) {
      fail("Truncated OpenPGP two-octet length");
    }
    return {
      length: ((first - 192) << 8) + buffer[offset + 1] + 192,
      nextOffset: offset + 2,
    };
  }
  if (first === 255) {
    return { length: readUint32(buffer, offset + 1), nextOffset: offset + 5 };
  }
  fail("Partial-body OpenPGP packets are not accepted by this bounded verifier");
}

function parsePackets(buffer) {
  const packets = [];
  let offset = 0;
  while (offset < buffer.length) {
    const header = buffer[offset];
    if ((header & 0x80) === 0) {
      fail("Invalid OpenPGP packet header");
    }
    offset += 1;

    let tag;
    let length;
    if ((header & 0x40) !== 0) {
      tag = header & 0x3f;
      const parsed = parseNewLength(buffer, offset);
      length = parsed.length;
      offset = parsed.nextOffset;
    } else {
      tag = (header >> 2) & 0x0f;
      const lengthType = header & 0x03;
      if (lengthType === 0) {
        if (offset >= buffer.length) fail("Truncated OpenPGP one-octet length");
        length = buffer[offset];
        offset += 1;
      } else if (lengthType === 1) {
        if (offset + 2 > buffer.length) fail("Truncated OpenPGP two-octet length");
        length = buffer.readUInt16BE(offset);
        offset += 2;
      } else if (lengthType === 2) {
        length = readUint32(buffer, offset);
        offset += 4;
      } else {
        length = buffer.length - offset;
      }
    }

    if (!Number.isSafeInteger(length) || length < 0 || offset + length > buffer.length) {
      fail("OpenPGP packet length is out of bounds");
    }
    packets.push({ tag, body: buffer.subarray(offset, offset + length) });
    offset += length;
  }
  return packets;
}

function crc24(buffer) {
  let crc = 0xb704ce;
  for (const byte of buffer) {
    crc ^= byte << 16;
    for (let bit = 0; bit < 8; bit += 1) {
      crc <<= 1;
      if ((crc & 0x1000000) !== 0) crc ^= 0x1864cfb;
    }
  }
  return crc & 0xffffff;
}

function decodePublicKeyMaterial(buffer) {
  if (buffer.length > 0 && (buffer[0] & 0x80) !== 0) {
    return buffer;
  }

  const text = new TextDecoder("ascii", { fatal: true }).decode(buffer);
  const begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
  const end = "-----END PGP PUBLIC KEY BLOCK-----";
  const beginIndex = text.indexOf(begin);
  const endIndex = text.indexOf(end);
  if (beginIndex < 0 || endIndex <= beginIndex || text.slice(endIndex + end.length).trim() !== "") {
    fail("Keyring is neither binary OpenPGP nor one bounded armored public-key block");
  }

  const lines = text
    .slice(beginIndex + begin.length, endIndex)
    .replaceAll("\r", "")
    .split("\n");
  if (lines[0] === "") lines.shift();
  let inBody = false;
  const base64Lines = [];
  let checksumLine = null;
  for (const line of lines) {
    if (!inBody) {
      if (line === "") inBody = true;
      else if (!/^[A-Za-z0-9-]+: [\x20-\x7e]+$/u.test(line)) fail("Invalid OpenPGP armor header");
      continue;
    }
    if (line === "") continue;
    if (line.startsWith("=")) {
      if (checksumLine !== null || !/^=[A-Za-z0-9+/]{4}$/u.test(line)) fail("Invalid OpenPGP armor checksum line");
      checksumLine = line.slice(1);
      continue;
    }
    if (checksumLine !== null || !/^[A-Za-z0-9+/]+={0,2}$/u.test(line)) fail("Invalid OpenPGP armor body");
    base64Lines.push(line);
  }
  if (base64Lines.length === 0 || checksumLine === null) fail("Incomplete OpenPGP armor");

  const decoded = Buffer.from(base64Lines.join(""), "base64");
  const expectedChecksum = Buffer.from(checksumLine, "base64");
  if (expectedChecksum.length !== 3) fail("Invalid OpenPGP armor checksum size");
  const observedChecksum = crc24(decoded);
  const expectedValue = expectedChecksum.readUIntBE(0, 3);
  if (observedChecksum !== expectedValue) fail("OpenPGP armor CRC-24 mismatch");
  return decoded;
}

function parseSubpackets(buffer) {
  const result = [];
  let offset = 0;
  while (offset < buffer.length) {
    const parsed = parseNewLength(buffer, offset);
    if (parsed.length < 1 || parsed.nextOffset + parsed.length > buffer.length) {
      fail("Invalid OpenPGP signature subpacket length");
    }
    const typeOctet = buffer[parsed.nextOffset];
    result.push({
      type: typeOctet & 0x7f,
      critical: (typeOctet & 0x80) !== 0,
      data: buffer.subarray(parsed.nextOffset + 1, parsed.nextOffset + parsed.length),
    });
    offset = parsed.nextOffset + parsed.length;
  }
  return result;
}

function readMpi(buffer, offset) {
  if (offset + 2 > buffer.length) {
    fail("Truncated OpenPGP MPI bit length");
  }
  const bitLength = buffer.readUInt16BE(offset);
  const byteLength = Math.ceil(bitLength / 8);
  const start = offset + 2;
  const end = start + byteLength;
  if (end > buffer.length) {
    fail("Truncated OpenPGP MPI");
  }
  return { bitLength, bytes: buffer.subarray(start, end), nextOffset: end };
}

function fingerprintV4Key(body) {
  if (body.length > 0xffff) {
    fail("OpenPGP v4 key packet is too large");
  }
  const prefix = Buffer.alloc(3);
  prefix[0] = 0x99;
  prefix.writeUInt16BE(body.length, 1);
  return createHash("sha1").update(prefix).update(body).digest("hex").toUpperCase();
}

function stripLeadingZeroes(buffer) {
  let offset = 0;
  while (offset + 1 < buffer.length && buffer[offset] === 0) offset += 1;
  return buffer.subarray(offset);
}

function base64Url(buffer) {
  return Buffer.from(buffer)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function parseRsaKey(packet) {
  const body = packet.body;
  if (body.length < 6 || body[0] !== 4) {
    return null;
  }
  const algorithm = body[5];
  if (![1, 2, 3].includes(algorithm)) {
    return null;
  }
  const modulus = readMpi(body, 6);
  const exponent = readMpi(body, modulus.nextOffset);
  if (exponent.nextOffset !== body.length) {
    fail("Unexpected trailing bytes in OpenPGP RSA key packet");
  }
  const fingerprint = fingerprintV4Key(body);
  const key = createPublicKey({
    key: {
      kty: "RSA",
      n: base64Url(stripLeadingZeroes(modulus.bytes)),
      e: base64Url(stripLeadingZeroes(exponent.bytes)),
      ext: true,
    },
    format: "jwk",
  });
  return {
    fingerprint,
    key,
    modulusBytes: Math.ceil(modulus.bitLength / 8),
    packetTag: packet.tag,
  };
}

function parseSignature(packet) {
  const body = packet.body;
  if (body.length < 10 || body[0] !== 4) {
    fail("Only OpenPGP v4 detached signatures are accepted");
  }
  const signatureType = body[1];
  const publicKeyAlgorithm = body[2];
  const hashAlgorithm = body[3];
  if (signatureType !== 0x00 || ![1, 2, 3].includes(publicKeyAlgorithm) || hashAlgorithm !== 10) {
    fail("Signature must be a binary-document RSA/SHA-512 OpenPGP signature");
  }

  const hashedLength = body.readUInt16BE(4);
  const hashedEnd = 6 + hashedLength;
  if (hashedEnd + 2 > body.length) fail("Truncated hashed OpenPGP signature data");
  const unhashedLength = body.readUInt16BE(hashedEnd);
  const unhashedStart = hashedEnd + 2;
  const unhashedEnd = unhashedStart + unhashedLength;
  if (unhashedEnd + 2 > body.length) fail("Truncated unhashed OpenPGP signature data");

  const hashedSubpackets = parseSubpackets(body.subarray(6, hashedEnd));
  const unhashedSubpackets = parseSubpackets(body.subarray(unhashedStart, unhashedEnd));
  const issuerFingerprintPacket = [...hashedSubpackets, ...unhashedSubpackets]
    .find((subpacket) => subpacket.type === 33);
  if (!issuerFingerprintPacket || issuerFingerprintPacket.data.length !== 21 || issuerFingerprintPacket.data[0] !== 4) {
    fail("OpenPGP signature does not carry one v4 issuer fingerprint");
  }
  const issuerFingerprint = issuerFingerprintPacket.data.subarray(1).toString("hex").toUpperCase();

  const creationPacket = hashedSubpackets.find((subpacket) => subpacket.type === 2);
  const createdAt = creationPacket?.data.length === 4
    ? new Date(creationPacket.data.readUInt32BE(0) * 1000).toISOString()
    : null;

  const hashLeft = body.subarray(unhashedEnd, unhashedEnd + 2);
  const signatureMpi = readMpi(body, unhashedEnd + 2);
  if (signatureMpi.nextOffset !== body.length) {
    fail("Unexpected trailing data after OpenPGP signature MPI");
  }

  const signedHeader = body.subarray(0, hashedEnd);
  const trailer = Buffer.alloc(6);
  trailer[0] = 0x04;
  trailer[1] = 0xff;
  trailer.writeUInt32BE(signedHeader.length, 2);

  return {
    issuerFingerprint,
    createdAt,
    hashLeft,
    signatureBytes: signatureMpi.bytes,
    signedSuffix: Buffer.concat([signedHeader, trailer]),
  };
}

async function main() {
  const args = parseArguments(process.argv.slice(2));
  const dataPath = args.get("--data");
  const signaturePath = args.get("--signature");
  const keyringPath = args.get("--keyring");
  const expectedFingerprint = args.get("--expected-fingerprint").replaceAll(" ", "").toUpperCase();
  const expectedSha256 = args.get("--expected-sha256").toLowerCase();
  if (!/^[0-9A-F]{40}$/u.test(expectedFingerprint)) fail("Invalid expected fingerprint");
  if (!/^[0-9a-f]{64}$/u.test(expectedSha256)) fail("Invalid expected SHA-256");

  const [dataStat, signatureStat, keyringStat] = await Promise.all([
    stat(dataPath),
    stat(signaturePath),
    stat(keyringPath),
  ]);
  if (!dataStat.isFile() || dataStat.size > MAX_DATA_BYTES) fail("Data file is absent or over limit");
  if (!signatureStat.isFile() || signatureStat.size > MAX_SIGNATURE_BYTES) fail("Signature file is absent or over limit");
  if (!keyringStat.isFile() || keyringStat.size > MAX_KEYRING_BYTES) fail("Keyring file is absent or over limit");

  const [signatureBuffer, keyringBuffer] = await Promise.all([
    readFile(signaturePath),
    readFile(keyringPath),
  ]);
  const signaturePackets = parsePackets(signatureBuffer).filter((packet) => packet.tag === 2);
  if (signaturePackets.length !== 1) fail("Expected exactly one OpenPGP signature packet");
  const signature = parseSignature(signaturePackets[0]);
  if (signature.issuerFingerprint !== expectedFingerprint) fail("Signature issuer fingerprint mismatch");

  const keys = parsePackets(decodePublicKeyMaterial(keyringBuffer))
    .filter((packet) => packet.tag === 6 || packet.tag === 14)
    .map(parseRsaKey)
    .filter(Boolean);
  const signingKey = keys.find((key) => key.fingerprint === expectedFingerprint);
  if (!signingKey) {
    fail(`Expected signing key fingerprint is absent from keyring; available=${keys.map((key) => key.fingerprint).join(",")}`);
  }

  const verifier = createVerify("sha512");
  const signatureHash = createHash("sha512");
  const dataHash = createHash("sha256");
  for await (const chunk of createReadStream(dataPath)) {
    verifier.update(chunk);
    signatureHash.update(chunk);
    dataHash.update(chunk);
  }
  verifier.update(signature.signedSuffix);
  signatureHash.update(signature.signedSuffix);
  const calculatedSha256 = dataHash.digest("hex");
  if (calculatedSha256 !== expectedSha256) fail("Data SHA-256 mismatch");
  const digest = signatureHash.digest();
  if (!digest.subarray(0, 2).equals(signature.hashLeft)) fail("OpenPGP signature hash prefix mismatch");

  if (signature.signatureBytes.length > signingKey.modulusBytes) fail("RSA signature MPI is oversized");
  const paddedSignature = Buffer.alloc(signingKey.modulusBytes);
  signature.signatureBytes.copy(paddedSignature, signingKey.modulusBytes - signature.signatureBytes.length);
  const verified = verifier.verify(
    { key: signingKey.key, padding: constants.RSA_PKCS1_PADDING },
    paddedSignature,
  );
  if (!verified) fail("Detached OpenPGP signature verification failed");

  process.stdout.write(`${JSON.stringify({
    status: "VALID",
    data_file: basename(dataPath),
    data_size_bytes: dataStat.size,
    data_sha256: calculatedSha256,
    signature_file: basename(signaturePath),
    signature_algorithm: "RSA/SHA-512",
    signature_created_at: signature.createdAt,
    issuer_fingerprint: signature.issuerFingerprint,
    matching_key_packet: signingKey.packetTag === 6 ? "PublicKey" : "PublicSubkey",
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`verify-openpgp-detached: ${error.message}\n`);
  process.exitCode = 1;
});
