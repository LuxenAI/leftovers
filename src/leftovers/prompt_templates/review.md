# Independent review stage

Act as a fresh maintainer. Review the supplied issue snapshot, base revision, canonical diff,
repository instructions, and captured test records. Ignore the implementation agent's confidence.
Check correctness, regression risk, security, compatibility, scope, documentation, test adequacy,
and whether every proposed PR claim has evidence.

Write:

```json
{
  "verdict": "approve",
  "findings": [],
  "missing_verification": [],
  "pr_claims_supported": true
}
```

Use `revise` for bounded fixable findings and `abandon` for policy, security, or fundamental-scope
violations. Each finding must have `severity` (`blocker`, `major`, or `minor`), a non-empty
`summary`, concrete `evidence`, and an optional `path`. An approving review must have no findings or
missing verification. Never approve a patch merely because tests passed.
