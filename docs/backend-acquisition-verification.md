# BACKEND-ACQUISITION-VERIFY1

Date: 2026-11-06. Scope: the D-058-authorized acquisition of the selected official
Windows AMD64 candidate and byte-level verification, without backend execution.
This follows [release triage](backend-release-review.md) and does not select a
production release or enable the historical planner/runtime.

Subsequent [BACKEND-TRUST-LAUNCH-SLICE1](backend-trust-launch-slice-review.md)
adds a GnuPG cross-check and static image/advisory observations. The initial
verification record and its limits below remain historical; full release/runtime
admission is still blocked.

```text
ResearchCandidate = v0.77.3
SourceRevision = 7d287b0b988b35657e1b401f7b2ffebaf60dbcae
CompressedAssetIdentity = MatchedOfficialMetadata
ExtractedImageIdentity = MatchedOfficialDownloadsTable
DetachedSignatureCryptography = MathematicalSignatureVerified
KeyMaterial = PreviouslyAcquiredPublicKey
FreshKeyRetrieval = NotPerformed
KeyLifecycleAndRevocation = NotValidated
Authenticode = NotEvaluatedInThisPass
BackendExecution = NotPerformed
CandidateAdmission = Blocked
ProductionLauncher = NotImplemented
AutomaticBackendExecution = Disabled
```

## 1. Acquisition and byte domains

Re-read the [official downloads page](https://docs.velociraptor.app/downloads/),
[release API](https://api.github.com/repos/Velocidex/velociraptor/releases/tags/v0.77.3)
and [tag ref](https://api.github.com/repos/Velocidex/velociraptor/git/ref/tags/v0.77.3).
The release remains published, not draft/prerelease, with publication timestamp
`2026-10-05T01:00:38Z`; the tag directly identifies the source revision above.
These mutable pages were checked for this acquisition, not continuously monitored.

| File | Measured bytes | Measured SHA-256 | Comparison |
|---|---:|---|---|
| `velociraptor-v0.77.3-windows-amd64.exe.gz` | 28350845 | `0b9cd957e5605da74994a6c29934da9af0e3af9c9b808f2274c826fba32dc3ae` | GitHub asset metadata matched |
| `velociraptor-v0.77.3-windows-amd64.exe.sig` | 438 | `070b244794094689d7554fa77c9f1506da9207410c94cbb5662d65c6ae89e72a` | GitHub asset metadata matched |
| `velociraptor-v0.77.3-windows-amd64.exe` | 73422840 | `3d20a5a2d272e3eb2bccae4a80ebe469fc1a6f63eb4a8f8a586dbae356437d32` | Official downloads table matched |

Only the exact gzip and detached-signature release assets were downloaded from
the [official release](https://github.com/Velocidex/velociraptor/releases/tag/v0.77.3).
HTTPS redirects were restricted to GitHub's release-assets host, with bounded
response size/time, exact metadata checks and create-new files. The dedicated
user-local acquisition directory is outside Git and was checked for unsafe
ancestry. It is **not** a protected installation or runtime execution directory.
These checks do not prove resistance to concurrent same-user path replacement.

The gzip was verified before bounded decompression (256 MiB output ceiling) to a
fixed filename; no archive-supplied path was used. The EXE was treated only as
data. The different published hashes are now explained by different byte domains:
compressed container versus extracted executable, not observed tampering.

## 2. Detached signature and precise limits

The current official downloads page pins primary-key fingerprint
`0572F28B4EF19A043F4CBBE0B22A7FB19CB6CFA1`. An already available external public-key
file from the earlier v0.77.1 verification was used; its SHA-256 is
`71f37f19312f543534f2eaadde63d1afe28ed2140c16fec85885f92597bbbee6`.
It was not imported into a keyring or Windows trust store. No new public-key
download occurred in this pass; separate permission for the exact keyserver
endpoint was requested. This is not a freshness or non-revocation claim.

The existing [bounded Node verifier](../tools/compatibility/verify-openpgp-detached.mjs)
was read before use and left unchanged (SHA-256
`b922a0860488be76178674206496d02253a63146e5ec1e428326d040684a52d6`).
It recomputed the primary-key fingerprint and the EXE SHA-256, then verified
the mathematical correspondence of the detached RSA/PKCS#1 v1.5 SHA-512 signature
to the streamed EXE bytes under that exact pinned RSA key packet. The signature's
signed creation-time field is
`2026-10-04T15:19:14.000Z`; that field is not an independent trusted timestamp.

| Byte-only check | Observed result |
|---|---|
| Exact EXE, signature, official fingerprint and EXE hash | Exit 0: VALID, matching primary public-key packet |
| Wrong expected fingerprint | Exit 1: issuer fingerprint mismatch |
| Wrong expected EXE hash | Exit 1: data SHA-256 mismatch |
| Gzip supplied as signed data, with correct gzip hash | Exit 1: signature hash prefix mismatch |

The signature covers the extracted EXE, not the gzip container. These are four
direct invocations of existing verification code, not the TrustLaunchProbe
synthetic matrix or execution of `test-openpgp-policy.mjs`.
The verifier is a narrow cryptographic checker, **not** a full OpenPGP certificate
policy engine: key lifecycle, revocation, self-signatures, all critical-subpacket
policy and current publisher authorization were not independently validated.
No GnuPG/gpgv cross-check or dependency installation was performed.
The result concerns bytes read in this pass; the verifier's separate stat/read
operations do not establish ongoing path/file immutability.

No Authenticode/Windows trust verdict, online certificate-revocation result,
PE manifest acceptance, reproducible-build/source-to-binary correspondence or
source-to-mapped-process binding follows from these results. No native helper was
compiled or invoked. Valid bytes are not proof of a safe release or safe behavior.

## 3. Remaining work and non-effects

Resolve key lifecycle/trust policy and applicable Windows image checks; complete
the current security-advisory, selected build/startup and diagnostic-effects
review; finalize and independently review the bounded Standard service/account/
launch slice before implementation/native trials. The unconditional event-source
installation/logging startup finding remains unresolved. Version/Help were not
run, output profiles were not established, and no collector was invoked.

No service, UAC, registry, ACL, PATH, trust store, security setting or dependency
was changed. No real audit evidence was collected. Downloads and the extracted
EXE remain outside Git; only this normalized public-data record and navigation
updates enter the worktree. Existing schemas, expected results, runtime pins,
prototype code and package manifests remain unchanged. No stage/commit/push.

Independent review: AcceptedBoundedByteVerificationRecordOnly on 2026-11-06,
with no blocking findings. The read-only reviewer checked this record, its
navigation updates and the verifier's identity/limitations against the author's
reported observations; the reviewer did not independently repeat signature
verification. Runtime acceptance remains Blocked.
