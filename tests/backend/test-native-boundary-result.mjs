// Pure validation of retained synthetic observations. No native compilation/run.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { OBSERVATIONS, validateRecord } from '../../tools/backend/native-boundary/result-contract.mjs';
const record = JSON.parse(await readFile(new URL('./native-boundary/normalized-result.json', import.meta.url), 'utf8'));
const rejects = change => {
  const value = structuredClone(record); change(value);
  assert.throws(() => validateRecord(value), /NATIVE_BOUNDARY_RECORD_INVALID/);
};
test('complete normalized observation set is non-authority', () => {
  assert.equal(validateRecord(record), record);
  assert.equal(Object.keys(OBSERVATIONS).length, 7);
});
test('all six source digests match exact files, not mapped-image attestation', async () => {
  const sources = { harness: 'native-boundary/NativeBoundaryHarness.cs', fixture: 'native-boundary/Fixture.cs',
    support: 'native-synthetic/SyntheticLaunchHarness.cs', manifest: 'native-synthetic/as-invoker.manifest',
    runner: 'native-boundary/run-native-boundary.mjs', validator: 'native-boundary/result-contract.mjs' };
  for (const [key, file] of Object.entries(sources)) {
    const bytes = await readFile(new URL(`../../tools/backend/${file}`, import.meta.url));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), record.source_sha256[key]);
  }
});
for (const id of ['NB-004', 'NB-005']) for (const observation of OBSERVATIONS[id]) {
  test(`observing ${observation} never grants authority`, () => {
    const value = structuredClone(record);
    value.observation.cases.find(r => r.id === id).observation = observation;
    assert.equal(validateRecord(value).observation.production_ready, false);
  });
}
for (const [i, id] of Object.keys(OBSERVATIONS).entries()) {
  test(`${id} cannot be replaced with a generic pass label`, () => rejects(r => { r.observation.cases[i].observation = 'Passed'; }));
}
const negatives = [
  ['missing case', r => r.observation.cases.pop()],
  ['duplicate case', r => { r.observation.cases[1] = r.observation.cases[0]; }],
  ['reordered cases', r => r.observation.cases.reverse()],
  ['extra case', r => r.observation.cases.push(r.observation.cases[0])],
  ['skipped native observation', r => { r.observation.cases[3].status = 'NotRun'; }],
  ['native error', r => { r.observation.cases[0].native_error = 5; }],
  ['failed native observation', r => { r.observation.cases[6].error = 'CLEANUP_FAILED'; }],
  ['raw stdout', r => { r.observation.cases[0].stdout = 'synthetic'; }],
  ['PID evidence', r => { r.observation.cases[0].pid = 123; }],
  ['production readiness', r => { r.observation.production_ready = true; }],
  ['backend execution', r => { r.observation.velociraptor_executed = true; }],
  ['execution authority', r => { r.observation.execution_enabled = true; }],
  ['extra outer authority', r => { r.authorized = true; }],
  ['missing cleanup', r => { r.temporary_files_removed = false; }],
  ['compile failure', r => { r.compile = 'Failed'; }],
  ['wrong stage', r => { r.stage = 'Production'; }],
  ['wrong native stage', r => { r.observation.stage = 'Production'; }],
  ['missing source', r => { delete r.source_sha256.support; }],
  ['invalid digest', r => { r.source_sha256.harness = 'unverified'; }],
  ['unknown source', r => { r.source_sha256.other = r.source_sha256.harness; }],
];
for (const [name, change] of negatives) test(`reject ${name}`, () => rejects(change));
