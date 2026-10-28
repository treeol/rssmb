# RSSMB Working Method

These are the rules for how changes are made in this project. They apply to
every contribution, without exception.

1. Every change references a roadmap ID (`R-nn`) in the branch name, the commit
   message, and the PR. ([`ROADMAP.md`](ROADMAP.md))
2. Conformance campaigns: an analysis doc lives at
   `tests/conformance/<suite>-analysis.md` **before** implementation; root
   causes are grouped and ordered by subtests unblocked; the human reviews
   the doc before any server change.
3. Golden behaviour = captured Samba 4.19.5 bytes (or a real client), never a
   reading of the spec. Hand-written expectations may exist in addition, never
   instead.
4. One commit per root-cause group, suite count in the commit message. Full
   uncapped smbtorture baseline before merge; any regression in any suite
   blocks. Truncated suites report INCOMPLETE, never a partial count.
5. Mashūra review on every implementation, capped at 2 rounds; only BLOCKING
   findings (changes a number, loses data, leaks test data) are folded in; the
   rest go to the PR's open points.
6. Never fake an unimplemented feature to pass a subtest; a correct
   "not supported" status is a pass.
7. README feature claims must match `results.md`. Experimental label until
   integration tests run in CI.
8. Merging and tag pushes are the human's; Wakil pushes branches and
   opens PRs.
9. Releases: one campaign per release; bump + CHANGELOG date + README numbers
   in one commit; CI green; human confirms before tag.
10. Workarounds in tests for server bugs are not allowed; the bug gets a
    roadmap entry and the test stays in its natural form.
11. A roadmap entry claiming a bug must carry evidence: a committed repro
    script (tests/live/ or tests/conformance/) or a captured log, plus the
    exact build it was observed on. "Observed once in a sandbox" with no
    committed repro is not evidence — close it as cannot-reproduce if it
    cannot be reconstructed. The same rule applies to agent reports: every
    result row in a report must come from a command actually run in that
    session; anything reasoned, remembered, or otherwise not directly
    observed must be marked [inferred].
