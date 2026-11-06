// Pure validator for normalized observations, not proof of host or launch authority.
export const OBSERVATIONS = Object.freeze({
  'NB-001': ['NameHashAgreeWriterDenied_NotMappedByteProof'],
  'NB-002': ['InertManagedDllMapped'],
  'NB-003': ['PreferSystem32DidNotBlockExplicitLocalMapping'],
  'NB-004': ['MicrosoftOnlyBlockedFixtureAfterStartup', 'MicrosoftOnlyAllowedFixtureMappingAfterStartup'],
  'NB-005': ['SameUserPeerDangerousRightsGranted_NoInjection', 'SameUserPeerRequestedRightsDenied'],
  'NB-006': ['BoundedPipeRoundTripReplayDenied_NotPeerAuthentication'],
  'NB-007': ['AbruptSupervisorExitReapedObservedLeaf_NotLeaseAtomicity'],
});
Object.values(OBSERVATIONS).forEach(Object.freeze);
function reject() { throw new Error('NATIVE_BOUNDARY_RECORD_INVALID'); }
function keys(o, expected) {
  if (!o || typeof o !== 'object' || Array.isArray(o) || Object.getPrototypeOf(o) !== Object.prototype
      || Object.keys(o).sort().join('|') !== [...expected].sort().join('|')) reject();
}
export function validateObservation(o) {
  keys(o, ['stage', 'production_ready', 'velociraptor_executed', 'cases']);
  if (o.stage !== 'NATIVE-BOUNDARY-EXPERIMENT1' || o.production_ready !== false || o.velociraptor_executed !== false
      || !Array.isArray(o.cases) || o.cases.length !== 7) reject();
  o.cases.forEach((row, i) => {
    keys(row, ['id', 'status', 'observation', 'error', 'native_error']);
    if (row.id !== Object.keys(OBSERVATIONS)[i] || row.status !== 'Observed'
        || !OBSERVATIONS[row.id].includes(row.observation) || row.error !== 'None' || row.native_error !== 0) reject();
  });
  return o;
}
export function validateRecord(o) {
  keys(o, ['stage', 'compile', 'source_sha256', 'temporary_files_removed', 'observation']);
  if (o.stage !== 'NATIVE-BOUNDARY-EXPERIMENT1' || o.compile !== 'Passed' || o.temporary_files_removed !== true) reject();
  keys(o.source_sha256, ['harness', 'fixture', 'support', 'manifest', 'runner', 'validator']);
  if (!Object.values(o.source_sha256).every(v => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v))) reject();
  validateObservation(o.observation);
  return o;
}
