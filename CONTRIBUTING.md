# Contributing to Leftovers

Changes should reduce maintainer burden, improve correctness, or tighten an enforceable safety
boundary. Features that merely increase autonomous PR volume are out of scope.

Before submitting a change:

1. Preserve the worker/publisher credential split and dry-run defaults.
2. Add focused tests for behavior and failure paths.
3. Run `make test`, `make package-smoke`, and `make training-run` (or report the
   lower-assurance local test and process rehearsal commands if no runtime is available).
4. Update the relevant protocol, security, config, and operations documentation.
5. Describe any live GitHub interaction precisely; tests must never perform remote writes.

Security issues should use private vulnerability reporting once the repository is published, not a
public issue.
