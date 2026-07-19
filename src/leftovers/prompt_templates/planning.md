# Planning stage

Do not edit the repository. Read the applicable instruction files, issue context, relevant source,
and tests. Attempt a bounded reproduction when the sandbox permits it. Produce a plan with this
shape:

```json
{
  "status": "planned",
  "acceptance_criteria": ["..."],
  "reproduction": {"argv": ["..."], "observed": "..."},
  "root_cause": [{"path": "...", "evidence": "..."}],
  "steps": ["..."],
  "tests": [["program", "arg"]],
  "risks": ["..."],
  "estimated_remaining_tokens": 0,
  "stop_conditions": ["..."]
}
```

Use `status: "blocked"` with a factual `reason` when the issue is not reproducible, requires a
maintainer decision, conflicts with repository policy, or cannot fit the supplied limits.
`estimated_remaining_tokens` must conservatively cover all expected implementation and independent
review input/output after this planning call; it is an admission estimate, not a provider-enforced
ceiling.
