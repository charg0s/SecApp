# Pure deployment-model gate

Run `npm run test:deployment-model` (also included in `npm test`). Only Node,
the existing pinned dev validator and synthetic in-memory inputs are used.
There are no native, installer, UAC, filesystem-mutation or backend test actions.

DP-001 through DP-040 are the explicit required set. The suite rejects missing,
duplicate or unexecuted IDs, independently of a case count. Each ordinary
operation and prefix validates against both development contracts; admission
negatives are structurally schema-valid before testing the semantic denial.
Unsafe shapes/output-authority changes have targeted schema negatives.

Coverage includes exact maintenance scope and confirmation binding, generation
overflow, epoch/reinstall floor preservation, declared nonce replay, expiration,
every forward-transition mismatch, cancellation/failure at each boundary,
ambiguous publication, committed cleanup failure, terminal replay, unknown
input and disabled output effects. Direct-API negatives cover proxies/getters,
sparse/cyclic/exotic data, numeric bounds and canonical timestamps.

The import check is only a source dependency guard, not proof of sandboxing.
Digests and synthetic confirmations provide no authentication. Projected
verification/commit events do not perform actual verification/publication;
the same scenario can be evaluated repeatedly without persistent state.

See [the contract and limitations](../../docs/deployment-plan-contract.md).
PI-001 through PI-022 and all native launch gates are unchanged by these tests.
