# Merge contract

Several policies can apply to one container. Every section compiler merges them
with the same rule, and `vectors.yaml` holds the shared test vectors. A section
compiler that merges policies runs the vectors in its tests (the privilege
compiler: `enforce_privilege/policy/contract_test.go`).

## Rule

1. Rules are the union of every policy's rules. Each rule keeps its own mode
   (else its policy's mode).
2. On one key the most limiting rule wins: deny (enforce) > deny (audit) >
   allow.
3. When no rule matches a key, the section default applies. The merged default
   is deny if any policy's default is deny, else allow. Its mode is the
   strictest mode of the policies whose default equals the merged default.
4. An explicit allow beats another policy's default deny.
5. An audit deny never weakens another policy's enforce default deny. When a
   key is denied by rules only in audit mode, the enforce default deny of each
   policy without a rule on that key still applies. So adding an audit policy
   never makes the merged result less strict.
6. Qualified keys (privilege: namespace flags) are judged per qualifier, with
   rules 1–5 for each qualifier.

## Where it differs from the CRD text

The CRD design says the section defaults apply only when no rule matches. Read
literally, a matching audit deny of one policy then hides another policy's
enforce default deny, and the merged result is audit only. Rule 5 differs: it
keeps the enforce default deny. The vector "an audit deny never weakens another
policy's enforce default deny" covers it.

Rule 5 is pending a product decision. Until then, a change to it changes
`vectors.yaml` and this file in the same commit, so the sections cannot diverge
silently.
