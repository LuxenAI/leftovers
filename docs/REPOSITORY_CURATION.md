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

## Read-only repository-supply nominations

`leftovers repo-scout` is a read-only discovery aid, not an execution selector. It searches public
repositories, then separately verifies their open-issue and open-PR counts so GitHub's combined REST
issue count is not mistaken for issue pressure. Its conservative defaults nominate only repositories
with 100–3,000 stars, 30–200 open issues, at most 12 open PRs, an issue-to-PR ratio of at least 8,
recent pushes, a recognized SPDX license, three recent unassigned `help wanted` or `good first issue`
issues, and recent human maintenance activity. The initial search is ordered by recent repository
updates and caps raw `help wanted` counts so tutorial farms do not crowd out maintained projects.
Tutorial/spam-shaped repositories and archived,
disabled, fork, mirror, template, locked, or unlicensed repositories are excluded.

The macOS preview job uses a smaller read-only scan and stores the resulting ranked list at
`.leftovers/install/reports/repository-candidates.json`. Every entry carries
`execution_authorized: false`: a high issue-to-PR ratio is a signal to investigate, never permission
to run an agent or contact maintainers.

For each nominee, re-open current upstream sources and explicitly record all of the following in the
installed `config.toml` (or the normal repository configuration) before any future strict
execution-boundary run. Curation is necessary evidence, but cannot authorize execution by itself:

1. exact `owner/name`, reviewed SPDX allowlist, default branch, and contribution/CLA/DCO/security
   rules;
2. a current HTTPS policy that permits the intended AI-assisted contribution and the date of the
   human check; unknown remains `ai_contributions_allowed = false`;
3. maintainer-approved labels, sensitive/forbidden paths, a small change budget, no-network setup,
   and exact offline test command arrays; and
4. any active assignee, claimant comment, linked PR, or repository-specific reason to decline the
   issue.

Keep `require_human_approval = true` for a newly curated repository. Do not copy nominations into
the allowlist in bulk, and do not relax these requirements to consume remaining quota.

Before enabling `draft-pr`, populate `allowed_licenses` with the exact SPDX identifiers the operator
has reviewed. Empty lists and GitHub sentinel values such as `NOASSERTION` or `OTHER` cannot authorize
publication. License, notice, and copying-file changes remain outside unattended scope.
