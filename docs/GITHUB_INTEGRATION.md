# GitHub integration snapshot

Verified against official GitHub material on **2026-07-17**.

## Discovery

Leftovers pins `X-GitHub-Api-Version: 2026-03-10`. GitHub's unversioned default remains
`2022-11-28`, but explicit versioning prevents silent behavior drift. Upgrade only with regression
tests. See [GitHub REST API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions?apiVersion=2026-03-10).

The read plane uses repository-scoped lexical issue search with `is:issue`, `is:open`,
`no:assignee`, maintainer labels, and `-linked:pr`. Search is only a prefilter. The client hydrates
each candidate's linked PRs through `closedByPullRequestsReferences` plus cross-referenced timeline
events, then repeats the check before publication. See the [Search API](https://docs.github.com/en/rest/search/search?apiVersion=2026-03-10#search-issues-and-pull-requests),
[Issue GraphQL fields](https://docs.github.com/en/graphql/reference/issues#issue), and
[CrossReferencedEvent](https://docs.github.com/en/graphql/reference/issues#crossreferencedevent).

GitHub search is capped at 1,000 results per query and has its own rate bucket. Leftovers therefore
searches only curated repositories and bounds every run. Honor `Retry-After` and rate-reset headers;
do not use multiple credentials to evade limits. See [REST rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2026-03-10)
and [REST best practices](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api).

## Authentication topology

For repositories that install an app, a GitHub App with minimum permissions and short-lived,
repository-narrowed installation tokens is preferred. Installation tokens expire after one hour.
See [choosing GitHub App permissions](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app)
and [creating an installation token](https://docs.github.com/en/rest/apps/apps?apiVersion=2026-03-10#create-an-installation-access-token-for-an-app).

For arbitrary public repositories, GitHub App and fine-grained PAT topology is currently limited:
user-to-server access covers accounts where the app is installed, and GitHub documents arbitrary
public-repository write access as a fine-grained PAT gap. The fork endpoint also constrains app
installation topology. See [user-to-server token boundaries](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-with-a-github-app-on-behalf-of-a-user),
[fine-grained PAT limitations](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#fine-grained-personal-access-tokens-limitations),
and [create a fork](https://docs.github.com/en/rest/repos/forks?apiVersion=2026-03-10#create-a-fork).

The practical cross-project publisher is therefore a clearly identified dedicated contributor
account with no private-repository access and a rotated classic `public_repo` PAT or user OAuth
credential. This broad credential must stay entirely in the deterministic publisher. It must never
enter prompts, worker environment, repository config, logs, or Git remotes.

The read-plane variable named by `github.token_env` is removed before invoking `gh`; it is never
silently reused as the publisher identity. Authenticate `gh` separately as the dedicated contributor
and record both its login in `publication.expected_login` and immutable numeric account ID in
`publication.expected_user_id`. Draft-pr config validation requires both fields. Before any write,
the publisher resolves `gh api user` and rejects a mismatch in either value. It obtains its token only
for the bounded Git push subprocess and removes the temporary askpass helper afterward.

## Publication policy

Before work and again before publication, check that the repository is active, permits forks and PRs,
accepts the contributor type, and has not capped outside contributors. GitHub introduced repository
PR access controls in February 2026 and an outside-user open-PR cap in June 2026; draft PRs do not
count toward that cap. See [PR creation policy](https://docs.github.com/en/graphql/reference/pulls#pullrequestcreationpolicy),
[PR access settings](https://github.blog/changelog/2026-02-13-new-repository-settings-for-configuring-pull-request-access/),
and [outside-user PR limits](https://github.blog/changelog/2026-06-17-limit-open-pull-requests-for-users-without-write-access/).

The v0.1 publisher creates/reuses a personal fork and uses one deterministic
`<branch_prefix>/issue-N` branch. A same-commit branch or already-open PR is reconciled as the result
of a partial prior attempt only when its head SHA, base branch, draft state, title, and body all match
the approved publication; mismatched, malformed, or multiple remote PR state is rejected as ambiguous.
Otherwise it pushes the branch, creates a draft PR, and reads it back to verify the same head SHA,
base, draft state, canonical URL, and exact controller-rendered title/body before reporting success.
It also checks the live per-repository open-PR count. Keep
`maintainer_can_modify` behavior compatible with personal-fork permissions and never delete the
branch while the PR is open. See [fork permissions](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/about-permissions-and-visibility-of-forks)
and [create a pull request](https://docs.github.com/en/rest/pulls/pulls?apiVersion=2026-03-10#create-a-pull-request).

Local publication slots are transactionally reserved in `<state_dir>/publications.sqlite3` after
fresh issue, repository-policy, and base-SHA checks. `max_prs_per_window` and
`repository_cooldown_days` apply even when a later remote step fails; there is no automatic release
or resume flow in v0.1. Any publisher exception is reported conservatively as `publish_partial`.
Inspect the journal and contributor account for the fork, deterministic branch, and draft PR before
retrying. Never delete a branch that backs an open PR and never bypass the ledger merely to retry.

## Anti-spam rules

GitHub prohibits excessive automated bulk activity, inauthentic interaction, and repeated disruptive
content. Leftovers enforces allowlists, maintainer-signal labels, disclosed AI assistance, one bounded
issue per run, draft-only publication, and conservative cooldown expectations. Read the current
[GitHub Acceptable Use Policies](https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies)
and [Terms of Service](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service)
before operating a public bot account.
