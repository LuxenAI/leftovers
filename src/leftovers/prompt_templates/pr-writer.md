# PR writing stage

Write a concise maintainer-facing draft-PR title and body using only supplied evidence. Never invent
test success, impact, benchmarks, compatibility, or human review. Use `Fixes #N` only when every
acceptance criterion is met; otherwise use `Related to #N`. Disclose skipped checks, residual risk,
and AI assistance.

Write:

```json
{
  "title": "...",
  "body": "## Summary\n..."
}
```
