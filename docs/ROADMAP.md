# RSSMB Roadmap

- **Date:** 2026-10-25
- **Current version:** 0.1.8
- **Current baseline:** smbtorture 4.19.5, uncapped run of 2026-10-24
  ([`tests/conformance/results.md`](../tests/conformance/results.md)),
  captured against rssmb 0.1.6 (481de59) with the 0.1.7 credit-accounting fix
  reflected in smb2.session. Counts are pass/fail unless stated otherwise:
  smb2.lock 22 pass + 3 cluster-only skips (suite exit 0, golden parity),
  smb2.connect PASS, smb2.durable-v2-open 14/1, smb2.lease 31/8
  (timing-flaky, 28–31 observed across runs), smb2.session 49/17,
  smb2.read 1/4, smb2.dir 2/7, smb2.getinfo 0/8, smb2.rename 3/9,
  smb2.sharemode 1/2, rpc.srvsvc 2/15.

This is the single tracked list of everything open. Every campaign prompt
references an item ID from this file, and every merged PR that closes or
advances an item updates its row here in the same PR.

## P0 — conformance debt blocking broad client compatibility

| ID | Item | Why it matters (one line, client-visible effect) | Evidence | Status | PR/branch |
|---|---|---|---|---|---|
| R-01 | Windows-redirector interop run (Explorer, robocopy, Office save; needs port 445 reachable) | The primary real-world client is the Windows redirector; nothing currently proves it works end-to-end. | none yet | blocked on infra (Valon's task) | — |
| R-02 | smb2.rename + smb2.sharemode campaign | Renames and share-mode conflicts are everyday Explorer/Office operations; failures surface as "file in use" and lost saves. | results.md: smb2.rename 3/9, smb2.sharemode 1/2 | open | — |
| R-03 | smb2.getinfo + smb2.setinfo campaign | Clients read file sizes/timestamps/attributes on nearly every operation; wrong answers corrupt Explorer views and backup tools. | results.md: smb2.getinfo 0/8, smb2.setinfo 0/1 | open | — |
| R-04 | smb2.dir campaign | Directory listing correctness gates every GUI file browser and `ls`-alike. | results.md: smb2.dir 2/7 (1kfiles_rename, fixed, large-files, many, modify, one, sorted) | open | — |
| R-05 | smb2.credits grant counts | Wrong credit grants stall or kill multi-credit large-MTU transfers (1 MiB reads/writes). | results.md: smb2.credits 0/3 (session_setup_credits_granted, single_req_credits_granted, skipped_mid) | open | — |
| R-06 | Lock-audit debt: uninspected guard sites + dual-lock ServerState pairs | Uninspected std-guard sites and dual-lock field pairs are unaudited hazards — deadlock risk under load cannot be ruled out until each is checked (the audit found no confirmed guard-across-await instance to date). | [`docs/lock-audit.md`](lock-audit.md) §1 "Uninspected" (ioctl.rs:95-96,185-186; quic.rs:650; connection.rs:650,1880) + §2 dual-lock table (4 pairs) | done | `fix/lock-audit` |

## P1 — features and hardening for the 1.0 quality bar

| ID | Item | Why it matters (one line, client-visible effect) | Evidence | Status | PR/branch |
|---|---|---|---|---|---|
| R-07 | Perf part 2: concurrent dispatch | Higher throughput for multi-client workloads without per-request serialization. | branch `perf/concurrent-dispatch`; profile on `perf/read-path-profile`; part 1 measured in CHANGELOG 0.1.3 (391 → ~550 MiB/s sealed iodepth 16) | open | perf/concurrent-dispatch |
| R-08 | FSCTL_SRV_COPYCHUNK | Server-side copy lets clients offload large copies instead of moving the data over the wire twice. | results.md: smb2.ioctl — all copy_chunk_* subtests failing (~20) | open | — |
| R-09 | rpc.srvsvc remaining | Complete share enumeration is what network-browse dialogs (Windows Explorer, macOS Finder) display. | results.md: rpc.srvsvc 2/15 | open | — |
| R-10 | Multichannel binding hardening (per-channel signing keys) | Binding is not hardened against a malicious second channel (per-channel signing key derivation); mitigated by shipping multichannel default-off. | CHANGELOG 0.1.7: `multichannel` default flipped to `false` until binding hardening lands | open | — |
| R-11 | smb2.read campaign | Correct READ semantics (positions, EOF, directory access checks) gate every file-transfer tool. | results.md: smb2.read 1/4 (access, dir, eof, position) | open | — |
| R-12 | smb2.notify basedir fidelity + CI budget | Correct change-notify keeps GUI folders live-updating instead of appearing frozen. | results.md: smb2.notify INCOMPLETE — stalls at basedir (attribute-filter fidelity debt) | open | — |
| R-13 | Threat-model / SECURITY.md refresh | Security disclosures and reviewers need a current threat map — the threat model covers neither QUIC, publish_on_close, nor the lease/durable/lock surface, and the external review is still pending. | [`docs/threat-model.md`](threat-model.md) (no QUIC / publish_on_close / lease sections; §External Security Review "pending") | open | — |
| R-14 | 1.0 release checklist (semver policy, config stability, upgrade notes) | Operators need config-format stability and documented upgrade paths before depending on rssmb in production. | none yet | open | — |

## P2 — operations and assurance

| ID | Item | Why it matters (one line, client-visible effect) | Evidence | Status | PR/branch |
|---|---|---|---|---|---|
| R-15 | Load/soak test in nightly (chaos-tests.sh → CI, 50 clients × 1 h, fd/RSS flat) | Catches fd and memory leaks that only appear under sustained multi-client load. | [`chaos-tests.sh`](../tests/conformance/chaos-tests.sh) exists, not run in CI | open | — |
| R-16 | Metrics completeness + Grafana dashboard in packaging/ | Operators need ready-made dashboards to see saturation, credits, and session health. | README documents Prometheus `/metrics`; no dashboard in packaging/ | open | — |
| R-17 | SIGHUP reload with live sessions | Define and verify reload semantics for live sessions (access revocation, share changes) so config changes don't silently strand connected clients. | README advertises SIGHUP live-reload of users/shares; behavior for already-connected sessions is undocumented | open | — |
| R-18 | Graceful shutdown with pending publish_on_close temps | On SIGTERM, clients must not lose data still parked under `.rssmb-tmp.*` temps. | CHANGELOG 0.1.5/0.1.7 publish_on_close; graceful drain documented in README | open | — |
| R-19 | check-config completeness | Operators need `rssmb check-config` to reject every invalid combination before startup, not just common ones. | `rssmb check-config` exists (README); coverage not audited | open | — |
| R-20 | New fuzz targets (create contexts, lock batches, srvsvc) | The durable/lease/lock/srvsvc surface has no dedicated fuzz targets; a panic from a malformed batch is a client-visible outage. | README lists 9 fuzz targets; none dedicated to create contexts, lock batches, or srvsvc | open | — |
| R-21 | Helm chart + Compose with secrets | Kubernetes users currently hand-roll manifests and risk mounting credentials as ConfigMaps. | docker/compose.yml exists; no Helm chart | open | — |
| R-22 | aarch64 image smoke test in release workflow | The arm64 image ships untested; a bad arm64 build would break Raspberry Pi / ARM NAS deployments. | [`release.yml`](../.github/workflows/release.yml) — binaries smoke-tested, multi-arch image built and pushed with no smoke test | open | — |

## P3 — long-term features

| ID | Item | Why it matters (one line, client-visible effect) | Evidence | Status | PR/branch |
|---|---|---|---|---|---|
| R-23 | Alternate data streams | Windows clients attach Zone.Identifier and other metadata via ADS; without it those attributes are lost or error, depending on client. | none yet | open | — |
| R-24 | Kerberos | AD-joined clients cannot log in without falling back to NTLM. | none yet (NTLMv2 only, README) | open | — |
| R-25 | Persistent handles (TLER resilient) | Files survive server restarts so clients resume instead of erroring; the supported recovery model is part of this item. | none yet (durable handles v1/v2 done; persistent not) | open | — |
| R-26 | AppInstanceId | App-instance-scoped opens let Office-style clients coordinate exclusive access. | results.md: smb2.durable-v2-open 14 pass / 1 fail (`app-instance`) | open (subtest excluded from parity gates — see Accepted-never) | — |
| R-27 | SMB over QUIC real-client test + cert rotation | QUIC is implemented but unproven against a real client, and TLS certs expire in production. | SMB over QUIC shipped (CHANGELOG 0.1.0, README); no real-client test | open | — |
| R-28 | CREATE ACL/quota — document as not-applicable on POSIX | CREATE ACL/quota queries have no direct POSIX equivalent; document the supported mapping (POSIX-mode-synthesized SDs) and honest not-supported answers instead of protocol failures. | results.md: smb2.create failures include aclfile, acldir, quota-fake-file | open | — |
| R-29 | macOS Finder interop | Finder exercises unusual compounds and metadata; second real-client ecosystem. | none yet | open | — |

## Accepted-never

| Item | Reason | Pointer |
|---|---|---|
| Durable app-instance (`smb2.durable-v2-open` subtest `app-instance`) | Samba 4.19.5 has no server-side AppInstanceId, so there is no golden behavior to conform to. Test-gating only — the R-26 feature item remains open. | tests/conformance/results.md — durable-v2-open 14 pass / 1 fail |
| Lease `statopen3` / `unlink` | Samba knownfails these subtests itself — matching them would mean matching a known-broken reference. | tests/conformance/results.md — smb2.lease failing list; lease-analysis.md |
| Lease `rename_wait` / `multibreak` flaky band | Timing-flaky band (28–31 pass observed across runs); not deterministic enough to gate on. | tests/conformance/results.md — smb2.lease "timing-flaky (28-31 observed across runs)"; lease-analysis.md |

## How this file is maintained

Item IDs are stable (`R-01`, `R-02`, …) and never renumbered; closed items
stay in their table with `Status = done` and the PR that closed them. Every
PR that implements, advances, or closes an item updates that item's row in
the same PR, and references the item ID in its commit messages (`[R-07]`).
New items are appended with a fresh ID only when they have evidence (a suite
count, a file:line, a captured log, or a user-reported scenario). Baseline
numbers come only from uncapped smbtorture runs recorded in
`tests/conformance/results.md`.

The rules governing how all of this work is done live in
[`WORKING-METHOD.md`](WORKING-METHOD.md).
