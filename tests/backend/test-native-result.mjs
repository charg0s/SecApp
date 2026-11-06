// Pure record validation only: never compiles or starts the native experiment.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { cases, validateSuccessfulResult } from '../../tools/backend/native-synthetic/result-contract.mjs';

const record = JSON.parse(await readFile(new URL('./native-synthetic/normalized-result.json', import.meta.url), 'utf8'));
const fresh = () => structuredClone(record.observation);
const rejects = mutate => {
  const value = fresh(); mutate(value);
  assert.throws(() => validateSuccessfulResult(value), /SYNTHETIC_RESULT_REJECTED/);
};

test('normalized observed case set passes the independent result checker', () => {
  assert.equal(record.compile, 'Passed');
  assert.equal(record.temporary_files_removed, true);
  assert.equal(record.scope, 'DevelopmentSyntheticOnly');
  assert.equal(record.privacy_classification, 'PublicSyntheticData');
  assert.equal(validateSuccessfulResult(record.observation), record.observation);
  assert.equal(cases.length, 10);
});

test('record identifies exact checked-in native source and manifest, not a trusted runtime image', async () => {
  for (const [field, name] of [['source_sha256', 'SyntheticLaunchHarness.cs'], ['manifest_sha256', 'as-invoker.manifest']]) {
    const bytes = await readFile(new URL(`../../tools/backend/native-synthetic/${name}`, import.meta.url));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), record[field]);
  }
});

for (const metadata of ['Present', 'Absent', 'Unknown']) {
  test(`linked metadata ${metadata} is not silently treated as production approval`, () => {
    const value = fresh(); value.cases[1].linked_metadata = metadata;
    assert.equal(validateSuccessfulResult(value).production_ready, false);
  });
}

const negatives = [
  ['missing case', value => value.cases.pop()],
  ['duplicate case', value => { value.cases[1] = value.cases[0]; }],
  ['unknown extra case', value => value.cases.push(value.cases[0])],
  ['changed expected outcome', value => { value.cases[2].expected = 'Completed'; }],
  ['incorrect observed outcome', value => { value.cases[2].outcome = 'Completed'; }],
  ['native pass flag cannot override a live Job', value => { value.cases[2].job_empty = false; }],
  ['unreaped root', value => { value.cases[3].root_exited = false; }],
  ['open descendant pipes', value => { value.cases[7].pipes_closed = false; }],
  ['unbounded retained stream', value => { value.cases[4].buffers_bounded = false; }],
  ['unsafe effective privileges', value => { value.cases[1].effective_standard = false; }],
  ['missing synthetic leaf handshake', value => { value.cases[3].tree_observed = false; }],
  ['unexpected tree assertion in control', value => { value.cases[0].tree_observed = true; }],
  ['pre-cancel creates a child', value => { value.cases[8].created = true; }],
  ['injected pre-resume fault resumes a child', value => { value.cases[9].resumed = true; }],
  ['nonzero exit loses its value', value => { value.cases[6].exit_code = 0; }],
  ['unobserved exit misreported as success', value => { value.cases[2].exit_code = 0; }],
  ['false native pass', value => { value.cases[0].passed = false; }],
  ['native error code despite a pass', value => { value.cases[0].native_error = 5; }],
  ['unknown linked metadata', value => { value.cases[0].linked_metadata = 'Trusted'; }],
  ['missing linked metadata observation', value => { value.cases[0].linked_metadata = 'NotObserved'; }],
  ['raw output field', value => { value.cases[0].stdout = 'synthetic'; }],
  ['readiness promotion', value => { value.production_ready = true; }],
  ['backend execution claim', value => { value.velociraptor_executed = true; }],
];
for (const [name, mutate] of negatives) test(`reject ${name}`, () => rejects(mutate));
