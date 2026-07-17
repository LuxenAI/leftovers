# Repository curation

Autonomous discovery is deliberately repository-allowlisted. Add a project only after a human checks:

- it is active, non-archived, non-mirrored, and has a recognized open-source license;
- maintainers currently accept outside PRs and have not restricted them to collaborators;
- its contribution guide, code of conduct, CLA/DCO, security policy, and issue templates;
- whether AI-assisted or automated contributions are allowed; unknown means `false`;
- maintainer labels that explicitly invite help;
- a working, pinned sandbox environment and exact verification commands;
- forbidden sensitive paths, dependency policy, generated files, public API constraints, and scope;
- existing assignees, comments that claim work, branches, and linked/cross-referenced PRs;
- a conservative importance value based on real use and recent activity, not stars alone.

Set `require_human_approval = true` for projects that allow AI assistance but expect a human review
before every PR. Unattended runs will not publish for those entries.

When `ai_contributions_allowed = true`, record both an HTTPS `ai_policy_url` pointing to the current
project policy and `ai_policy_checked_at = "YYYY-MM-DD"`. Candidate gating rejects missing, invalid,
future-dated, or older-than-`policy.ai_policy_max_age_days` evidence. Re-open the source and update the
date only after a human actually rechecks it; a recent date is evidence of review, not permission by
itself.

Never add a repository because an issue, README, agent, or model asks. Configuration is operator
authority and must remain reviewable in version control.

Before enabling `draft-pr`, populate `allowed_licenses` with the exact SPDX identifiers the operator
has reviewed. Empty lists and GitHub sentinel values such as `NOASSERTION` or `OTHER` cannot authorize
publication. License, notice, and copying-file changes remain outside unattended scope.
