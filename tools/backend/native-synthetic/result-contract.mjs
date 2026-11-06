// Development-only normalized observations; never a launch authority.
export const cases = Object.freeze([
  ['SN-001', 'Completed'], ['SN-002', 'Completed'], ['SN-003', 'Timeout'],
  ['SN-004', 'Cancelled'], ['SN-005', 'StdoutLimit'], ['SN-006', 'StderrLimit'],
  ['SN-007', 'NonZeroExit'], ['SN-008', 'DescendantsAfterParentExit'],
  ['SN-009', 'CancelledBeforeCreate'], ['SN-010', 'InjectedBeforeResume'],
].map(Object.freeze));

const fields = ['id', 'expected', 'outcome', 'passed', 'created', 'resumed',
  'effective_standard', 'linked_metadata', 'root_exited', 'job_empty', 'pipes_closed',
  'buffers_bounded', 'tree_observed', 'exit_code', 'error', 'native_error'];
const booleans = ['passed', 'created', 'resumed', 'effective_standard', 'root_exited',
  'job_empty', 'pipes_closed', 'buffers_bounded', 'tree_observed'];

function exact(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key));
}

export function validateSuccessfulResult(value) {
  const reject = (code = 'ENVELOPE') => { throw new Error(`SYNTHETIC_RESULT_REJECTED_${code}`); };
  if (!exact(value, ['stage', 'production_ready', 'velociraptor_executed', 'cases'])
      || value.stage !== 'BACKEND-NATIVE-SYNTHETIC1' || value.production_ready !== false
      || value.velociraptor_executed !== false || !Array.isArray(value.cases)
      || value.cases.length !== cases.length) reject();
  for (const [index, [id, expected]] of cases.entries()) {
    const row = value.cases[index];
    if (!exact(row, fields) || row.id !== id || row.expected !== expected || row.outcome !== expected
        || booleans.some(key => typeof row[key] !== 'boolean') || !row.passed || !row.buffers_bounded
        || !['Absent', 'Present', 'Unknown', 'NotObserved'].includes(row.linked_metadata)
        || (row.exit_code !== null && (!Number.isSafeInteger(row.exit_code) || row.exit_code < 0 || row.exit_code > 0xffffffff))
        || row.native_error !== 0) reject(`CASE_${index + 1}_COMMON`);
    if (id === 'SN-009') {
      if (row.created || row.resumed || row.effective_standard || row.root_exited || row.job_empty
          || row.pipes_closed || row.tree_observed || row.linked_metadata !== 'NotObserved'
          || row.exit_code !== null || row.error !== 'None') reject(`CASE_${index + 1}_PRE_CANCEL`);
    } else {
      if (!row.created || !row.effective_standard || !row.root_exited || !row.job_empty || !row.pipes_closed
          || row.resumed !== (id !== 'SN-010') || row.linked_metadata === 'NotObserved'
          || row.error !== (id === 'SN-010' ? 'INJECTED_PRE_RESUME' : 'None')) reject(`CASE_${index + 1}_LIFECYCLE`);
      if (row.tree_observed !== ['SN-003', 'SN-004', 'SN-008'].includes(id)) reject(`CASE_${index + 1}_TREE`);
      const exit = id === 'SN-007' ? 17 : ['SN-001', 'SN-002', 'SN-008'].includes(id) ? 0 : null;
      if (row.exit_code !== exit) reject(`CASE_${index + 1}_EXIT`);
    }
  }
  return value;
}
