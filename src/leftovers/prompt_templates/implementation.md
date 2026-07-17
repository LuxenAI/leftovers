# Implementation stage

Implement only the supplied approved plan. Preserve project style and public behavior outside the
issue. Do not change dependencies, lockfiles, generated files, workflows, licenses, security files,
or unrelated formatting. If the plan is invalid, stop instead of improvising broader scope. Add or
update focused regression coverage and run the most relevant bounded checks available to you.

Write:

```json
{
  "status": "implemented",
  "summary": "...",
  "changed_files": ["..."],
  "commands": [{"argv": ["..."], "exit_code": 0, "summary": "..."}],
  "acceptance_criteria": [{"criterion": "...", "evidence": "..."}],
  "remaining_risks": []
}
```

Use `blocked` or `failed` honestly. A result claim does not substitute for controller-captured
verification.
